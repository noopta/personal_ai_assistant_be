#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import {
    CallToolRequestSchema,
    ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { google } from 'googleapis';
import { z } from "zod";
import { zodToJsonSchema } from "zod-to-json-schema";
import { OAuth2Client } from 'google-auth-library';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import http from 'http';
import crypto from 'crypto';
import {createEmailMessage} from "./utl.js";
import { createLabel, updateLabel, deleteLabel, listLabels, findLabelByName, getOrCreateLabel, GmailLabel } from "./label-manager.js";
import winston from 'winston';
import { LRUCache as LRU } from 'lru-cache';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Configuration
const CONFIG_DIR = path.join(__dirname, '..', 'refresh-tokens');
const OAUTH_PATH = process.env.GMAIL_OAUTH_PATH || path.join(CONFIG_DIR, 'gcp-oauth.keys.json');
const MAX_CACHED_CLIENTS = 1000;
const CLIENT_TTL = 4 * 60 * 60 * 1000;
const CLEANUP_INTERVAL = 30 * 60 * 1000;

// =================
// COMPLEXITY ANALYSIS FRAMEWORK
// =================

// Define which Gmail tools would be simple, complex, or variable when using HTTP transport
const TOOL_COMPLEXITY: {
  simple: string[];
  complex: string[];
  variable: string[];
} = {
  simple: [
    'authenticate_user', 'read_email', 'get_cache_stats',
    'create_label', 'update_label', 'delete_label',
    'get_or_create_label', 'modify_email', 'delete_email'
  ],
  complex: [
    // Most Gmail operations are relatively quick
  ],
  variable: [
    'send_email', 'draft_email', 'search_emails',
    'list_email_labels', 'batch_modify_emails', 'batch_delete_emails'
  ]
};

class GmailComplexityAnalyzer {
  analyzeSendEmail(args: any): 'simple' | 'complex' {
    const bodyLength = (args?.body || '').length + (args?.htmlBody || '').length;
    const recipients = (args?.to || []).length + (args?.cc || []).length + (args?.bcc || []).length;
    
    if (bodyLength > 50000) return 'complex';
    if (recipients > 20) return 'complex';
    if (args?.htmlBody && bodyLength > 20000) return 'complex';
    
    return 'simple';
  }
  
  analyzeSearchEmails(args: any): 'simple' | 'complex' {
    const maxResults = args?.maxResults || 10;
    const query = args?.query || '';
    
    if (maxResults > 100) return 'complex';
    if (query.length > 200) return 'complex';
    if (query.includes('has:attachment') && maxResults > 50) return 'complex';
    
    return 'simple';
  }
  
  analyzeBatchModifyEmails(args: any): 'simple' | 'complex' {
    const messageIds = Array.isArray(args?.messageIds) ? args.messageIds : [];
    
    if (messageIds.length > 100) return 'complex';
    if (messageIds.length > 50) return 'complex';
    
    return 'simple';
  }
  
  analyzeBatchDeleteEmails(args: any): 'simple' | 'complex' {
    const messageIds = Array.isArray(args?.messageIds) ? args.messageIds : [];
    
    if (messageIds.length > 50) return 'complex';
    if (messageIds.length > 25) return 'complex';
    
    return 'simple';
  }
}

function shouldUseSSE(toolName: string, args: any, req?: express.Request): boolean {
  const analyzer = new GmailComplexityAnalyzer();
  
  // 1. Client preference overrides (highest priority)
  if (req?.headers.accept?.includes('text/event-stream')) {
    return true;  // Client explicitly wants SSE
  }
  
  if (req?.headers['x-prefer-streaming'] === 'true') {
    return true;  // Custom header for streaming preference
  }
  
  if (req?.headers['x-prefer-streaming'] === 'false') {
    return false; // Client explicitly rejects SSE
  }
  
  // 2. Check hardcoded classifications
  if (TOOL_COMPLEXITY.simple.includes(toolName)) {
    return false; // Always HTTP for simple operations
  }
  
  if (TOOL_COMPLEXITY.complex.includes(toolName)) {
    return true;  // Always SSE for complex operations
  }
  
  // 3. Analyze variable operations
  if (TOOL_COMPLEXITY.variable.includes(toolName)) {
    let complexity: 'simple' | 'complex';
    
    switch (toolName) {
      case 'send_email':
      case 'draft_email':
        complexity = analyzer.analyzeSendEmail(args);
        break;
      case 'search_emails':
        complexity = analyzer.analyzeSearchEmails(args);
        break;
      case 'batch_modify_emails':
        complexity = analyzer.analyzeBatchModifyEmails(args);
        break;
      case 'batch_delete_emails':
        complexity = analyzer.analyzeBatchDeleteEmails(args);
        break;
      default:
        complexity = 'simple';
    }
    
    return complexity === 'complex';
  }
  
  // 4. Default to HTTP for unknown tools
  return false;
}

// =================
// GLOBAL VARIABLES
// =================

// Create server instance (global for export)
const server = new Server(
  {
    name: "gmail-multi-user",
    version: "2.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

let httpServer: any = null;

// Type definitions
interface GmailMessagePart {
    partId?: string;
    mimeType?: string;
    filename?: string;
    headers?: Array<{
        name: string;
        value: string;
    }>;
    body?: {
        attachmentId?: string;
        size?: number;
        data?: string;
    };
    parts?: GmailMessagePart[];
}

interface EmailAttachment {
    id: string;
    filename: string;
    mimeType: string;
    size: number;
}

interface EmailContent {
    text: string;
    html: string;
}

interface UserCredentials {
    access_token?: string;
    refresh_token?: string;
    scope?: string;
    token_type?: string;
    expiry_date?: number;
}

interface CachedClient {
    oauth2Client: OAuth2Client;
    gmailApi: any;
    lastUsed: number;
    gmailHashID: string;
}

interface UserContext {
    gmailHashID: string;
    client: CachedClient;
}

// Global OAuth keys (loaded once)
let globalOAuthKeys: any = null;

// User client cache with LRU eviction
const clientCache = new LRU<string, CachedClient>({
    max: MAX_CACHED_CLIENTS,
    ttl: CLIENT_TTL,
    dispose: (client: CachedClient, key: string) => {
        logger.info(`Disposing cached client for user: ${key}`);
    }
});

// Logger setup
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
      winston.format.timestamp(),
      winston.format.errors({ stack: true }),
      winston.format.json()
    ),
    transports: [
      new winston.transports.File({ 
        filename: path.join(CONFIG_DIR, 'mcp.log'),
        maxsize: 5242880,
        maxFiles: 5,
      }),
      new winston.transports.Console({
        format: winston.format.combine(
          winston.format.colorize(),
          winston.format.simple()
        )
      })
    ]
  });

logger.on('error', (error: Error) => {
  console.error('Logger error:', error);
});

/**
 * User Management Class
 */
class UserManager {
    private static instance: UserManager;
    private authServers: Map<string, http.Server> = new Map();
    private sharedOAuthServer: http.Server | null = null;
    private pendingAuthentications: Map<string, { resolve: Function; reject: Function }> = new Map();

    static getInstance(): UserManager {
        if (!UserManager.instance) {
            UserManager.instance = new UserManager();
        }
        return UserManager.instance;
    }

    /**
     * Get credentials file path for a specific user
     */
    getCredentialsPath(gmailHashID: string): string {
        return path.join(CONFIG_DIR, `.${gmailHashID}-gcp-saved-tokens.json`);
    }

    /**
     * Find token file with case-insensitive prefix matching
     */
    findCaseInsensitiveTokenFile(gmailHashID: string): string | null {
        try {
            const files = fs.readdirSync(CONFIG_DIR);
            const targetLower = gmailHashID.toLowerCase();
            
            console.log(`🔍 [TOKEN CHECK] Looking for prefix matches for: ${targetLower}`);
            console.log(`🔍 [TOKEN CHECK] Available files: ${files.filter(f => f.includes('gcp-saved-tokens')).join(', ')}`);
            
            // Try different prefix lengths to handle character additions/modifications
            // Use 3 characters minimum for better matching
            const prefixLengths = [targetLower.length, Math.max(6, targetLower.length - 4), 3];
            
            for (const prefixLength of prefixLengths) {
                const searchPrefix = targetLower.substring(0, prefixLength);
                console.log(`🔍 [TOKEN CHECK] Trying prefix length ${prefixLength}: "${searchPrefix}"`);
                
                for (const file of files) {
                    if (file.includes('gcp-saved-tokens')) {
                        const fileLower = file.toLowerCase();
                        // Extract the gmailHashID part from filename (remove . prefix and -gcp-saved-tokens suffix)
                        const fileIdMatch = fileLower.match(/^\.(.+)-gcp-saved-tokens/);
                        if (fileIdMatch) {
                            const fileId = fileIdMatch[1];
                            
                            // Check if the file ID starts with our search prefix OR vice versa
                            if (fileId.startsWith(searchPrefix) || searchPrefix.startsWith(fileId.substring(0, Math.min(fileId.length, searchPrefix.length)))) {
                                const fullPath = path.join(CONFIG_DIR, file);
                                console.log(`🔍 [TOKEN CHECK] Prefix match found: ${file} (fileId: ${fileId}, searchPrefix: ${searchPrefix})`);
                                return fullPath;
                            }
                        }
                    }
                }
            }
            console.log(`🔍 [TOKEN CHECK] No prefix match found for: ${targetLower}`);
            return null;
        } catch (error) {
            console.log(`❌ [TOKEN CHECK] Error during prefix lookup: ${error}`);
            return null;
        }
    }

    /**
     * Load user-specific credentials
     */
    loadUserCredentials(gmailHashID: string): UserCredentials | null {
        const credPath = this.getCredentialsPath(gmailHashID);
        const credPathWithSave = credPath + '.save';
        
        // Console logging for token detection
        console.log(`🔑 [TOKEN CHECK] gmailHashID: ${gmailHashID}`);
        console.log(`🔑 [TOKEN CHECK] credPath: ${credPath}`);
        console.log(`🔑 [TOKEN CHECK] exists: ${fs.existsSync(credPath)}`);
        console.log(`🔑 [TOKEN CHECK] credPathWithSave: ${credPathWithSave}`);
        console.log(`🔑 [TOKEN CHECK] existsWithSave: ${fs.existsSync(credPathWithSave)}`);
        
        let finalCredPath = credPath;
        if (!fs.existsSync(credPath)) {
            if (fs.existsSync(credPathWithSave)) {
                finalCredPath = credPathWithSave;
                console.log(`🔄 [TOKEN CHECK] Using .save file for gmailHashID: ${gmailHashID}`);
            } else {
                // Try case-insensitive lookup
                const caseInsensitiveMatch = this.findCaseInsensitiveTokenFile(gmailHashID);
                if (caseInsensitiveMatch) {
                    finalCredPath = caseInsensitiveMatch;
                    console.log(`🔄 [TOKEN CHECK] Using case-insensitive match: ${caseInsensitiveMatch} for gmailHashID: ${gmailHashID}`);
                } else {
                    logger.info(`No credentials found for user: ${gmailHashID}`);
                    console.log(`❌ [TOKEN CHECK] No refresh token file found for gmailHashID: ${gmailHashID}`);
                    return null;
                }
            }
        }

        try {
            const credentials = JSON.parse(fs.readFileSync(finalCredPath, 'utf8'));
            console.log(`✅ [TOKEN CHECK] Successfully loaded refresh token for gmailHashID: ${gmailHashID}`);
            logger.info(`Loaded credentials for user: ${gmailHashID}`);
            return credentials;
        } catch (error) {
            logger.warn(`Failed to load credentials for user ${gmailHashID}:`, error);
            return null;
        }
    }

    /**
     * Save user-specific credentials
     */
    saveUserCredentials(gmailHashID: string, credentials: any): void {
        // Filter out null values to match UserCredentials interface
        const cleanCredentials: UserCredentials = {} as UserCredentials;
        Object.entries(credentials).forEach(([key, value]) => {
            if (value !== null && value !== undefined) {
                (cleanCredentials as any)[key] = value;
            }
        });
        
        const credPath = this.getCredentialsPath(gmailHashID);
        
        if (!fs.existsSync(CONFIG_DIR)) {
            fs.mkdirSync(CONFIG_DIR, { recursive: true });
        }

        try {
            fs.writeFileSync(credPath, JSON.stringify(cleanCredentials, null, 2));
            logger.info(`Saved credentials for user: ${gmailHashID}`);
        } catch (error) {
            logger.error(`Failed to save credentials for user ${gmailHashID}:`, error);
            throw error;
        }
    }

    /**
     * Create OAuth2Client for a specific user
     */
    createOAuth2Client(gmailHashID: string, port?: number): OAuth2Client {
        if (!globalOAuthKeys) {
            throw new Error('Global OAuth keys not loaded');
        }

        const callback = port ? `https://luciuslab.xyz:${port}/oauth2callback` : `https://luciuslab.xyz:4007/oauth2callback`;

        console.log(`🔗 Creating OAuth2Client with callback: ${callback}`);
        logger.info(`Creating OAuth2Client with callback: ${callback}`);

        const oauth2Client = new OAuth2Client(
            globalOAuthKeys.client_id,
            globalOAuthKeys.client_secret,
            callback
        );

        // Load existing credentials if available
        const credentials = this.loadUserCredentials(gmailHashID);
        if (credentials) {
            oauth2Client.setCredentials(credentials);
        }

        return oauth2Client;
    }

    /**
     * Get or create cached client for user
     */
    async getOrCreateClient(gmailHashID: string): Promise<CachedClient> {
        // Check cache first
        let cachedClient = clientCache.get(gmailHashID);
        
        if (cachedClient) {
            // Update last used timestamp
            cachedClient.lastUsed = Date.now();
            logger.info(`Using cached client for user: ${gmailHashID}`);
            return cachedClient;
        }

        // Create new client
        logger.info(`Creating new client for user: ${gmailHashID}`);
        
        const oauth2Client = this.createOAuth2Client(gmailHashID);
        const gmailApi = google.gmail({ version: 'v1', auth: oauth2Client });
//ok so we need to allow https instead of http so we should double check the nginx configuraiton 
// after that we need to test on VAPI to make sure the agent is connected 
        cachedClient = {
            oauth2Client,
            gmailApi,
            lastUsed: Date.now(),
            gmailHashID
        };

        // Cache the client
        clientCache.set(gmailHashID, cachedClient);
        
        return cachedClient;
    }

    /**
     * Start shared OAuth callback server
     */
    private async startSharedOAuthServer(): Promise<void> {
        if (this.sharedOAuthServer) {
            return; // Already running
        }

        const port = 3111;
        
        return new Promise((resolve, reject) => {
            const server = http.createServer();
            
            server.listen(port, () => {
                logger.info(`Shared OAuth callback server started on port ${port}`);
                resolve();
            });

            server.on('error', (error) => {
                logger.error(`Failed to start shared OAuth callback server:`, error);
                reject(error);
            });

            // Set up callback handler for all users
            server.on('request', async (req, res) => {
                console.log(`📥 OAuth callback request: ${req.method} ${req.url}`);
                
                if (!req.url?.includes(`/oauth2callback`)) {
                    res.writeHead(404, { 'Content-Type': 'text/html' });
                    res.end('<h1>404 - Not Found</h1>');
                    return;
                }

                const url = new URL(req.url, `https://luciuslab.xyz:4007`);
                const code = url.searchParams.get('code');
                const error = url.searchParams.get('error');
                const state = url.searchParams.get('state');

                if (error) {
                    res.writeHead(400, { 'Content-Type': 'text/html' });
                    res.end(`<h1>❌ Authentication Error</h1><p>Error: ${error}</p>`);
                    return;
                }

                if (!code || !state) {
                    res.writeHead(400, { 'Content-Type': 'text/html' });
                    res.end('<h1>❌ Authentication Failed</h1><p>Missing required parameters</p>');
                    return;
                }

                try {
                    const stateData = JSON.parse(state);
                    const gmailHashID = stateData.userID;

                    if (!gmailHashID) {
                        res.writeHead(400, { 'Content-Type': 'text/html' });
                        res.end('<h1>❌ Authentication Failed</h1><p>Invalid state parameter</p>');
                        return;
                    }

                    // Get OAuth client and exchange code for tokens
                    const oauth2Client = this.createOAuth2Client(gmailHashID, 4007);
                    const { tokens } = await oauth2Client.getToken(code);
                    
                    // Save the credentials
                    this.saveUserCredentials(gmailHashID, tokens);
                    
                    res.writeHead(200, { 'Content-Type': 'text/html' });
                    res.end(`
                        <!DOCTYPE html>
                        <html>
                        <head>
                            <meta charset="UTF-8">
                            <meta name="viewport" content="width=device-width, initial-scale=1.0">
                            <title>Gmail Authentication Complete</title>
                            <style>
                                body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
                                .success { color: green; }
                            </style>
                        </head>
                        <body>
                            <h1 class="success">✅ Authentication Successful!</h1>
                            <p>Your Gmail account has been successfully connected.</p>
                            <p>You can now close this window.</p>
                        </body>
                        </html>
                    `);
                    
                    // Resolve any pending authentication for this user
                    const pending = this.pendingAuthentications.get(gmailHashID);
                    if (pending) {
                        pending.resolve({ success: true, gmailHashID });
                        this.pendingAuthentications.delete(gmailHashID);
                    }
                    
                } catch (exchangeError) {
                    logger.error(`OAuth token exchange failed:`, exchangeError);
                    res.writeHead(400, { 'Content-Type': 'text/html' });
                    res.end(`<h1>❌ Authentication Failed</h1><p>Error: ${exchangeError instanceof Error ? exchangeError.message : 'Unknown error'}</p>`);
                }
            });

            this.sharedOAuthServer = server;
        });
    }

    /**
     * Find an available port starting from a base port
     */
    private async findAvailablePort(startPort: number = 4010, endPort: number = 4100): Promise<number> {
        const net = await import('net');
        
        return new Promise((resolve, reject) => {
            let port = startPort;
            
            const tryPort = () => {
                if (port > endPort) {
                    reject(new Error(`No available ports found between ${startPort} and ${endPort}`));
                    return;
                }
                
                const server = net.createServer();
                server.listen(port, () => {
                    server.close(() => {
                        resolve(port);
                    });
                });
                
                server.on('error', () => {
                    port++;
                    tryPort();
                });
            };
            
            tryPort();
        });
    }

    /**
     * Generate auth URL and start callback server (for external browser opening)
     */
    async generateAuthURL(gmailHashID: string): Promise<{ authUrl: string; callbackPort: number }> {
        // Start shared OAuth server if not already running
        if (!this.sharedOAuthServer) {
            try {
                await this.startSharedOAuthServer();
            } catch (error) {
                logger.warn(`Shared OAuth server may already be running:`, error);
                // Continue anyway - nginx will route to the existing server
            }
        }
        
        const port = 3111;
        const oauth2Client = this.createOAuth2Client(gmailHashID, 4007); // OAuth client uses 4007 for redirect URI
        
        const authUrl = oauth2Client.generateAuthUrl({
            access_type: 'offline',
            scope: ['https://www.googleapis.com/auth/gmail.modify'],
            state: JSON.stringify({ userID: gmailHashID })
        });

        console.log(`🚀 Auth URL generated for user ${gmailHashID}: ${authUrl}`);
        logger.info(`Auth URL generated for user ${gmailHashID}: ${authUrl}`);

        return { authUrl, callbackPort: port };
    }

    /**

                try {
                    logger.info(`Exchanging code for tokens for user: ${gmailHashID}`);
                    const { tokens } = await oauth2Client.getToken(code);
                    
                    // Save user-specific credentials
                    this.saveUserCredentials(gmailHashID, tokens);
                    
                    // Clear cached client to force refresh
                    clientCache.delete(gmailHashID);

                    res.writeHead(200, { 'Content-Type': 'text/html' });
                    res.end(`
                        <!DOCTYPE html>
                        <html lang="en">
                        <head>
                            <meta charset="UTF-8">
                            <meta name="viewport" content="width=device-width, initial-scale=1.0">
                            <title>Gmail Authentication Complete</title>
                            <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
                            <style>
                                :root {
                                    --primary-gradient: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                                    --success-color: #10b981;
                                    --text-primary: #1f2937;
                                    --text-secondary: #6b7280;
                                    --bg-primary: #ffffff;
                                    --bg-secondary: #f8fafc;
                                    --border-color: #e5e7eb;
                                    --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
                                    --shadow-lg: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
                                    --gmail-red: #ea4335;
                                }

                                * {
                                    margin: 0;
                                    padding: 0;
                                    box-sizing: border-box;
                                }

                                body {
                                    font-family: 'Inter', -apple-system, BlinkMacSystemFont, system-ui, sans-serif;
                                    background: var(--primary-gradient);
                                    min-height: 100vh;
                                    display: flex;
                                    align-items: center;
                                    justify-content: center;
                                    padding: 20px;
                                    position: relative;
                                    overflow-x: hidden;
                                }

                                .background-pattern {
                                    position: absolute;
                                    top: 0;
                                    left: 0;
                                    right: 0;
                                    bottom: 0;
                                    opacity: 0.1;
                                    background-image: radial-gradient(circle at 25% 25%, white 2px, transparent 0),
                                                      radial-gradient(circle at 75% 75%, white 2px, transparent 0);
                                    background-size: 50px 50px;
                                    animation: float 20s ease-in-out infinite;
                                }

                                @keyframes float {
                                    0%, 100% { transform: translate(0, 0) rotate(0deg); }
                                    33% { transform: translate(10px, -10px) rotate(1deg); }
                                    66% { transform: translate(-5px, 5px) rotate(-1deg); }
                                }

                                .container {
                                    background: var(--bg-primary);
                                    backdrop-filter: blur(20px);
                                    border-radius: 24px;
                                    padding: 48px 40px;
                                    text-align: center;
                                    box-shadow: var(--shadow-lg);
                                    border: 1px solid rgba(255, 255, 255, 0.2);
                                    max-width: 480px;
                                    width: 100%;
                                    position: relative;
                                    z-index: 1;
                                    animation: slideUp 0.6s ease-out;
                                }

                                @keyframes slideUp {
                                    from {
                                        opacity: 0;
                                        transform: translateY(30px);
                                    }
                                    to {
                                        opacity: 1;
                                        transform: translateY(0);
                                    }
                                }

                                .success-icon {
                                    width: 80px;
                                    height: 80px;
                                    margin: 0 auto 24px;
                                    background: linear-gradient(135deg, var(--success-color) 0%, #059669 100%);
                                    border-radius: 50%;
                                    display: flex;
                                    align-items: center;
                                    justify-content: center;
                                    animation: pulse 2s ease-in-out infinite;
                                }

                                @keyframes pulse {
                                    0%, 100% { transform: scale(1); }
                                    50% { transform: scale(1.05); }
                                }

                                .checkmark {
                                    width: 32px;
                                    height: 32px;
                                    stroke: white;
                                    stroke-width: 3;
                                    fill: none;
                                    animation: drawCheck 0.8s ease-in-out 0.3s both;
                                }

                                @keyframes drawCheck {
                                    to {
                                        stroke-dashoffset: 0;
                                    }
                                }

                                .checkmark path {
                                    stroke-dasharray: 100;
                                    stroke-dashoffset: 100;
                                }

                                h1 {
                                    color: var(--text-primary);
                                    font-size: 28px;
                                    font-weight: 600;
                                    margin-bottom: 16px;
                                    line-height: 1.3;
                                }

                                .subtitle {
                                    color: var(--text-secondary);
                                    font-size: 16px;
                                    font-weight: 400;
                                    margin-bottom: 32px;
                                    line-height: 1.5;
                                }

                                .gmail-logo {
                                    display: inline-flex;
                                    align-items: center;
                                    gap: 8px;
                                    margin-bottom: 24px;
                                    padding: 12px 20px;
                                    background: var(--bg-secondary);
                                    border-radius: 12px;
                                    border: 1px solid var(--border-color);
                                }

                                .gmail-icon {
                                    width: 24px;
                                    height: 24px;
                                }

                                .service-name {
                                    color: var(--text-primary);
                                    font-weight: 500;
                                    font-size: 16px;
                                }

                                .user-info {
                                    background: var(--bg-secondary);
                                    border: 1px solid var(--border-color);
                                    border-radius: 16px;
                                    padding: 20px;
                                    margin: 24px 0;
                                    text-align: left;
                                }

                                .user-label {
                                    color: var(--text-secondary);
                                    font-size: 14px;
                                    font-weight: 500;
                                    margin-bottom: 8px;
                                    text-transform: uppercase;
                                    letter-spacing: 0.5px;
                                }

                                .user-id {
                                    color: var(--text-primary);
                                    font-family: 'SF Mono', Monaco, 'Cascadia Code', 'Roboto Mono', Consolas, 'Courier New', monospace;
                                    font-size: 14px;
                                    word-break: break-all;
                                    padding: 12px;
                                    background: var(--bg-primary);
                                    border-radius: 8px;
                                    border: 1px solid var(--border-color);
                                }

                                .actions {
                                    margin-top: 32px;
                                    display: flex;
                                    flex-direction: column;
                                    gap: 12px;
                                }

                                .btn {
                                    padding: 14px 24px;
                                    border-radius: 12px;
                                    font-weight: 500;
                                    font-size: 16px;
                                    cursor: pointer;
                                    transition: all 0.2s ease;
                                    border: none;
                                    position: relative;
                                    overflow: hidden;
                                }

                                .btn-primary {
                                    background: var(--primary-gradient);
                                    color: white;
                                    box-shadow: var(--shadow-sm);
                                }

                                .btn-primary:hover {
                                    transform: translateY(-2px);
                                    box-shadow: 0 10px 25px -5px rgba(102, 126, 234, 0.4);
                                }

                                .btn-primary:active {
                                    transform: translateY(0);
                                }

                                .status-badge {
                                    display: inline-flex;
                                    align-items: center;
                                    gap: 8px;
                                    background: rgba(16, 185, 129, 0.1);
                                    color: var(--success-color);
                                    padding: 8px 16px;
                                    border-radius: 20px;
                                    font-size: 14px;
                                    font-weight: 500;
                                    margin-bottom: 24px;
                                }

                                .status-dot {
                                    width: 8px;
                                    height: 8px;
                                    background: var(--success-color);
                                    border-radius: 50%;
                                    animation: blink 2s ease-in-out infinite;
                                }

                                @keyframes blink {
                                    0%, 100% { opacity: 1; }
                                    50% { opacity: 0.5; }
                                }

                                .footer-text {
                                    color: var(--text-secondary);
                                    font-size: 14px;
                                    margin-top: 24px;
                                    line-height: 1.5;
                                }

                                @media (max-width: 480px) {
                                    .container {
                                        padding: 32px 24px;
                                        border-radius: 16px;
                                    }
                                    
                                    h1 {
                                        font-size: 24px;
                                    }
                                    
                                    .success-icon {
                                        width: 64px;
                                        height: 64px;
                                    }
                                }
                            </style>
                        </head>
                        <body>
                            <div class="background-pattern"></div>
                            
                            <div class="container">
                                <div class="success-icon">
                                    <svg class="checkmark" viewBox="0 0 100 100">
                                        <path d="M20,50 L40,70 L80,30" stroke-linecap="round" stroke-linejoin="round"/>
                                    </svg>
                                </div>

                                <div class="status-badge">
                                    <div class="status-dot"></div>
                                    Authentication Complete
                                </div>

                                <h1>Gmail Connected Successfully</h1>
                                <p class="subtitle">Your Gmail account has been securely authenticated and connected to the MCP server.</p>

                                <div class="gmail-logo">
                                    <svg class="gmail-icon" viewBox="0 0 24 24" fill="none">
                                        <path d="M24 5.457v13.909c0 .904-.732 1.636-1.636 1.636h-3.819V11.73L12 16.64l-6.545-4.91v9.273H1.636A1.636 1.636 0 0 1 0 19.366V5.457c0-2.023 2.309-3.178 3.927-1.964L5.455 4.64 12 9.548l6.545-4.91 1.528-1.145C21.69 2.28 24 3.434 24 5.457z" fill="#EA4335"/>
                                    </svg>
                                    <span class="service-name">Gmail MCP Server</span>
                                </div>

                                <div class="user-info">
                                    <div class="user-label">Authenticated Session ID</div>
                                    <div class="user-id">${gmailHashID}</div>
                                </div>

                                <div class="actions">
                                    <button class="btn btn-primary" onclick="window.close()">
                                        Continue & Close Window
                                    </button>
                                </div>

                                <p class="footer-text">
                                    This window will automatically close in <span id="countdown">5</span> seconds.<br>
                                    Your Gmail integration is now ready for use.
                                </p>
                            </div>

                            <script>
                                let seconds = 5;
                                const countdownElement = document.getElementById('countdown');
                                
                                const timer = setInterval(() => {
                                    seconds--;
                                    countdownElement.textContent = seconds;
                                    
                                    if (seconds <= 0) {
                                        clearInterval(timer);
                                        window.close();
                                    }
                                }, 1000);
                                
                                // Add click animation
                                document.querySelector('.btn-primary').addEventListener('click', function() {
                                    this.style.transform = 'scale(0.98)';
                                    setTimeout(() => {
                                        this.style.transform = '';
                                    }, 150);
                                });
                            </script>
                        </body>
                        </html>
                    `);
                    
                    this.cleanupAuthServer(gmailHashID);
                        
                } catch (error) {
                    logger.error(`Token exchange failed for user ${gmailHashID}:`, error);
                    res.writeHead(500, { 'Content-Type': 'text/html' });
                    res.end(`<h1>❌ Authentication Failed</h1><p>Error: ${error}</p>`);
                    this.cleanupAuthServer(gmailHashID);
                }
            });

            // Timeout after 10 minutes
            setTimeout(() => {
                this.cleanupAuthServer(gmailHashID);
            }, 10 * 60 * 1000);

            // Return the auth URL immediately
            resolve({ authUrl, callbackPort: port });
        });
    }

    /**
     * Authenticate a specific user (original method with auto-open)
     */
    async authenticateUser(gmailHashID: string): Promise<string> {
        const oauth2Client = this.createOAuth2Client(gmailHashID);
        const port = 4010;
        
        return new Promise<string>((resolve, reject) => {
            const server = http.createServer();
            
            // Store server reference for cleanup
            this.authServers.set(gmailHashID, server);
            
            server.listen(port, () => {
                logger.info(`Auth server started for user ${gmailHashID} on port ${port}`);
            });

            server.on('error', (error) => {
                logger.error(`Failed to start auth server for user ${gmailHashID}:`, error);
                this.authServers.delete(gmailHashID);
                reject(new Error(`Failed to start auth server: ${error.message}`));
            });

            const authUrl = oauth2Client.generateAuthUrl({
                access_type: 'offline',
                scope: ['https://www.googleapis.com/auth/gmail.modify'],
                state: JSON.stringify({ userID: gmailHashID })
            });

            console.log(`🔗 Please visit this URL to authenticate user ${gmailHashID}: ${authUrl}`);
            console.log(`📋 Callback URL configured as: https://luciuslab.xyz:4007/oauth2callback`);
            console.log(`🔧 Make sure this URL is added to your Google Cloud OAuth client redirect URIs`);
            
            // Return the auth URL immediately to the frontend
            resolve(authUrl);

            server.on('request', async (req, res) => {
                console.log(`📥 OAuth authenticateUser request: ${req.method} ${req.url}`);
                
                if (!req.url?.includes(`/oauth2callback`)) {
                    res.writeHead(404, { 'Content-Type': 'text/html' });
                    res.end('<h1>404 - Not Found</h1>');
                    return;
                }


                
                const url = new URL(req.url, `https://luciuslab.xyz:4007`);
                const code = url.searchParams.get('code');
                const error = url.searchParams.get('error');
                const state = url.searchParams.get('state');

                if (error) {
                    res.writeHead(400, { 'Content-Type': 'text/html' });
                    res.end(`<h1>❌ Authentication Error</h1><p>Error: ${error}</p>`);
                    this.cleanupAuthServer(gmailHashID);
                    reject(new Error(`OAuth error: ${error}`));
                    return;
                }

                if (!code) {
                    res.writeHead(400, { 'Content-Type': 'text/html' });
                    res.end('<h1>❌ No Authorization Code</h1>');
                    this.cleanupAuthServer(gmailHashID);
                    reject(new Error('No authorization code provided'));
                    return;
                }

                // Validate state parameter
                if (state) {
                    try {
                        const stateData = JSON.parse(state);
                        if (stateData.userID !== gmailHashID) {
                            logger.warn(`State parameter mismatch. Expected: ${gmailHashID}, Got: ${stateData.userID}`);
                            res.writeHead(400, { 'Content-Type': 'text/html' });
                            res.end('<h1>❌ Invalid State Parameter</h1>');
                            this.cleanupAuthServer(gmailHashID);
                            reject(new Error('Invalid state parameter'));
                            return;
                        }
                    } catch (error) {
                        logger.warn(`Failed to parse state parameter: ${state}`);
                        res.writeHead(400, { 'Content-Type': 'text/html' });
                        res.end('<h1>❌ Invalid State Parameter</h1>');
                        this.cleanupAuthServer(gmailHashID);
                        reject(new Error('Invalid state parameter'));
                        return;
                    }
                }

                try {
                    logger.info(`Exchanging code for tokens for user: ${gmailHashID}`);
                    const { tokens } = await oauth2Client.getToken(code);
                    
                    // Save user-specific credentials
                    this.saveUserCredentials(gmailHashID, tokens);
                    
                    // Clear cached client to force refresh
                    clientCache.delete(gmailHashID);

                    res.writeHead(200, { 'Content-Type': 'text/html' });
                    res.end(`
                        <!DOCTYPE html>
                        <html lang="en">
                        <head>
                            <meta charset="UTF-8">
                            <meta name="viewport" content="width=device-width, initial-scale=1.0">
                            <title>Gmail Authentication Complete</title>
                            <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
                            <style>
                                :root {
                                    --primary-gradient: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                                    --success-color: #10b981;
                                    --text-primary: #1f2937;
                                    --text-secondary: #6b7280;
                                    --bg-primary: #ffffff;
                                    --bg-secondary: #f8fafc;
                                    --border-color: #e5e7eb;
                                    --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
                                    --shadow-lg: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
                                    --gmail-red: #ea4335;
                                }

                                * {
                                    margin: 0;
                                    padding: 0;
                                    box-sizing: border-box;
                                }

                                body {
                                    font-family: 'Inter', -apple-system, BlinkMacSystemFont, system-ui, sans-serif;
                                    background: var(--primary-gradient);
                                    min-height: 100vh;
                                    display: flex;
                                    align-items: center;
                                    justify-content: center;
                                    padding: 20px;
                                    position: relative;
                                    overflow-x: hidden;
                                }

                                .background-pattern {
                                    position: absolute;
                                    top: 0;
                                    left: 0;
                                    right: 0;
                                    bottom: 0;
                                    opacity: 0.1;
                                    background-image: radial-gradient(circle at 25% 25%, white 2px, transparent 0),
                                                      radial-gradient(circle at 75% 75%, white 2px, transparent 0);
                                    background-size: 50px 50px;
                                    animation: float 20s ease-in-out infinite;
                                }

                                @keyframes float {
                                    0%, 100% { transform: translate(0, 0) rotate(0deg); }
                                    33% { transform: translate(10px, -10px) rotate(1deg); }
                                    66% { transform: translate(-5px, 5px) rotate(-1deg); }
                                }

                                .container {
                                    background: var(--bg-primary);
                                    backdrop-filter: blur(20px);
                                    border-radius: 24px;
                                    padding: 48px 40px;
                                    text-align: center;
                                    box-shadow: var(--shadow-lg);
                                    border: 1px solid rgba(255, 255, 255, 0.2);
                                    max-width: 480px;
                                    width: 100%;
                                    position: relative;
                                    z-index: 1;
                                    animation: slideUp 0.6s ease-out;
                                }

                                @keyframes slideUp {
                                    from {
                                        opacity: 0;
                                        transform: translateY(30px);
                                    }
                                    to {
                                        opacity: 1;
                                        transform: translateY(0);
                                    }
                                }

                                .success-icon {
                                    width: 80px;
                                    height: 80px;
                                    margin: 0 auto 24px;
                                    background: linear-gradient(135deg, var(--success-color) 0%, #059669 100%);
                                    border-radius: 50%;
                                    display: flex;
                                    align-items: center;
                                    justify-content: center;
                                    animation: pulse 2s ease-in-out infinite;
                                }

                                @keyframes pulse {
                                    0%, 100% { transform: scale(1); }
                                    50% { transform: scale(1.05); }
                                }

                                .checkmark {
                                    width: 32px;
                                    height: 32px;
                                    stroke: white;
                                    stroke-width: 3;
                                    fill: none;
                                    animation: drawCheck 0.8s ease-in-out 0.3s both;
                                }

                                @keyframes drawCheck {
                                    to {
                                        stroke-dashoffset: 0;
                                    }
                                }

                                .checkmark path {
                                    stroke-dasharray: 100;
                                    stroke-dashoffset: 100;
                                }

                                h1 {
                                    color: var(--text-primary);
                                    font-size: 28px;
                                    font-weight: 600;
                                    margin-bottom: 16px;
                                    line-height: 1.3;
                                }

                                .subtitle {
                                    color: var(--text-secondary);
                                    font-size: 16px;
                                    font-weight: 400;
                                    margin-bottom: 32px;
                                    line-height: 1.5;
                                }

                                .gmail-logo {
                                    display: inline-flex;
                                    align-items: center;
                                    gap: 8px;
                                    margin-bottom: 24px;
                                    padding: 12px 20px;
                                    background: var(--bg-secondary);
                                    border-radius: 12px;
                                    border: 1px solid var(--border-color);
                                }

                                .gmail-icon {
                                    width: 24px;
                                    height: 24px;
                                }

                                .service-name {
                                    color: var(--text-primary);
                                    font-weight: 500;
                                    font-size: 16px;
                                }

                                .user-info {
                                    background: var(--bg-secondary);
                                    border: 1px solid var(--border-color);
                                    border-radius: 16px;
                                    padding: 20px;
                                    margin: 24px 0;
                                    text-align: left;
                                }

                                .user-label {
                                    color: var(--text-secondary);
                                    font-size: 14px;
                                    font-weight: 500;
                                    margin-bottom: 8px;
                                    text-transform: uppercase;
                                    letter-spacing: 0.5px;
                                }

                                .user-id {
                                    color: var(--text-primary);
                                    font-family: 'SF Mono', Monaco, 'Cascadia Code', 'Roboto Mono', Consolas, 'Courier New', monospace;
                                    font-size: 14px;
                                    word-break: break-all;
                                    padding: 12px;
                                    background: var(--bg-primary);
                                    border-radius: 8px;
                                    border: 1px solid var(--border-color);
                                }

                                .actions {
                                    margin-top: 32px;
                                    display: flex;
                                    flex-direction: column;
                                    gap: 12px;
                                }

                                .btn {
                                    padding: 14px 24px;
                                    border-radius: 12px;
                                    font-weight: 500;
                                    font-size: 16px;
                                    cursor: pointer;
                                    transition: all 0.2s ease;
                                    border: none;
                                    position: relative;
                                    overflow: hidden;
                                }

                                .btn-primary {
                                    background: var(--primary-gradient);
                                    color: white;
                                    box-shadow: var(--shadow-sm);
                                }

                                .btn-primary:hover {
                                    transform: translateY(-2px);
                                    box-shadow: 0 10px 25px -5px rgba(102, 126, 234, 0.4);
                                }

                                .btn-primary:active {
                                    transform: translateY(0);
                                }

                                .status-badge {
                                    display: inline-flex;
                                    align-items: center;
                                    gap: 8px;
                                    background: rgba(16, 185, 129, 0.1);
                                    color: var(--success-color);
                                    padding: 8px 16px;
                                    border-radius: 20px;
                                    font-size: 14px;
                                    font-weight: 500;
                                    margin-bottom: 24px;
                                }

                                .status-dot {
                                    width: 8px;
                                    height: 8px;
                                    background: var(--success-color);
                                    border-radius: 50%;
                                    animation: blink 2s ease-in-out infinite;
                                }

                                @keyframes blink {
                                    0%, 100% { opacity: 1; }
                                    50% { opacity: 0.5; }
                                }

                                .footer-text {
                                    color: var(--text-secondary);
                                    font-size: 14px;
                                    margin-top: 24px;
                                    line-height: 1.5;
                                }

                                @media (max-width: 480px) {
                                    .container {
                                        padding: 32px 24px;
                                        border-radius: 16px;
                                    }
                                    
                                    h1 {
                                        font-size: 24px;
                                    }
                                    
                                    .success-icon {
                                        width: 64px;
                                        height: 64px;
                                    }
                                }
                            </style>
                        </head>
                        <body>
                            <div class="background-pattern"></div>
                            
                            <div class="container">
                                <div class="success-icon">
                                    <svg class="checkmark" viewBox="0 0 100 100">
                                        <path d="M20,50 L40,70 L80,30" stroke-linecap="round" stroke-linejoin="round"/>
                                    </svg>
                                </div>

                                <div class="status-badge">
                                    <div class="status-dot"></div>
                                    Authentication Complete
                                </div>

                                <h1>Gmail Connected Successfully</h1>
                                <p class="subtitle">Your Gmail account has been securely authenticated and connected to the MCP server.</p>

                                <div class="gmail-logo">
                                    <svg class="gmail-icon" viewBox="0 0 24 24" fill="none">
                                        <path d="M24 5.457v13.909c0 .904-.732 1.636-1.636 1.636h-3.819V11.73L12 16.64l-6.545-4.91v9.273H1.636A1.636 1.636 0 0 1 0 19.366V5.457c0-2.023 2.309-3.178 3.927-1.964L5.455 4.64 12 9.548l6.545-4.91 1.528-1.145C21.69 2.28 24 3.434 24 5.457z" fill="#EA4335"/>
                                    </svg>
                                    <span class="service-name">Gmail MCP Server</span>
                                </div>

                                <div class="user-info">
                                    <div class="user-label">Authenticated Session ID</div>
                                    <div class="user-id">${gmailHashID}</div>
                                </div>

                                <div class="actions">
                                    <button class="btn btn-primary" onclick="window.close()">
                                        Continue & Close Window
                                    </button>
                                </div>

                                <p class="footer-text">
                                    This window will automatically close in <span id="countdown">5</span> seconds.<br>
                                    Your Gmail integration is now ready for use.
                                </p>
                            </div>

                            <script>
                                let seconds = 5;
                                const countdownElement = document.getElementById('countdown');
                                
                                const timer = setInterval(() => {
                                    seconds--;
                                    countdownElement.textContent = seconds;
                                    
                                    if (seconds <= 0) {
                                        clearInterval(timer);
                                        window.close();
                                    }
                                }, 1000);
                                
                                // Add click animation
                                document.querySelector('.btn-primary').addEventListener('click', function() {
                                    this.style.transform = 'scale(0.98)';
                                    setTimeout(() => {
                                        this.style.transform = '';
                                    }, 150);
                                });
                            </script>
                        </body>
                        </html>
                    `);
                    
                    this.cleanupAuthServer(gmailHashID);
                        
                } catch (error) {
                    logger.error(`Token exchange failed for user ${gmailHashID}:`, error);
                    res.writeHead(500, { 'Content-Type': 'text/html' });
                    res.end(`<h1>❌ Authentication Failed</h1><p>Error: ${error}</p>`);
                    this.cleanupAuthServer(gmailHashID);
                    reject(error);
                }
            });

            // Timeout after 5 minutes
            setTimeout(() => {
                this.cleanupAuthServer(gmailHashID);
                reject(new Error('Authentication timeout'));
            }, 5 * 60 * 1000);
        });
    }

    /**
     * Cleanup authentication server for user
     */
    private cleanupAuthServer(gmailHashID: string): void {
        const server = this.authServers.get(gmailHashID);
        if (server) {
            server.close();
            this.authServers.delete(gmailHashID);
            logger.info(`Cleaned up auth server for user: ${gmailHashID}`);
        }
    }

    /**
     * Check if user is authenticated
     */
    isUserAuthenticated(gmailHashID: string): boolean {
        const credentials = this.loadUserCredentials(gmailHashID);
        return !!(credentials && (credentials.access_token || credentials.refresh_token));
    }

    /**
     * Remove user credentials and cached client
     */
    removeUser(gmailHashID: string): void {
        // Remove credentials file
        const credPath = this.getCredentialsPath(gmailHashID);
        if (fs.existsSync(credPath)) {
            fs.unlinkSync(credPath);
        }
        
        // Remove from cache
        clientCache.delete(gmailHashID);
        
        // Cleanup auth server if running
        this.cleanupAuthServer(gmailHashID);
        
        logger.info(`Removed user: ${gmailHashID}`);
    }

    /**
     * Get cache statistics
     */
    getCacheStats() {
        return {
            size: clientCache.size,
            maxSize: clientCache.max,
            calculatedSize: clientCache.calculatedSize
        };
    }
}

/**
 * Load global OAuth configuration
 */
async function loadGlobalOAuthKeys() {
    try {
        // Create config directory if it doesn't exist
        if (!fs.existsSync(CONFIG_DIR)) {
            fs.mkdirSync(CONFIG_DIR, { recursive: true });
        }

        // Check for OAuth keys in current directory first
        // **THIS IS WHERE WE ARE CHECKING FOR THE PATH TO COPY OVER**
        console.log(process.cwd());
        const localOAuthPath = path.join(process.cwd(), 'gcp-oauth.keys.json');

        if (fs.existsSync(localOAuthPath)) {
          console.log("definetly exists")
            fs.copyFileSync(localOAuthPath, OAUTH_PATH);
            logger.info('OAuth keys found in current directory, copied to global config.');
        }

        if (!fs.existsSync(OAUTH_PATH)) {
          console.log("definetly does not exist")
            throw new Error('OAuth keys file not found. Please place gcp-oauth.keys.json in current directory or ' + CONFIG_DIR);
        }

        const keysContent = JSON.parse(fs.readFileSync(OAUTH_PATH, 'utf8'));
        globalOAuthKeys = keysContent.installed || keysContent.web;

        if (!globalOAuthKeys) {
            throw new Error('Invalid OAuth keys file format. File should contain either "installed" or "web" credentials.');
        }

        logger.info('Global OAuth keys loaded successfully');
    } catch (error) {
        logger.error("Failed to load global OAuth keys", { error });
        throw error;
    }
}

/**
 * Extract user context from request arguments
 */
function extractUserContext(args: any): string {
    // Look for gmailHashID in arguments
    const gmailHashID = args.gmailHashID || args.gmailHashId || args.gmail_hash_id;
    
    if (!gmailHashID) {
        throw new Error('gmailHashID is required for all operations');
    }
    
    return gmailHashID;
}

/**
 * Get authenticated client for user
 */
async function getAuthenticatedClient(gmailHashID: string): Promise<CachedClient> {
    const userManager = UserManager.getInstance();
    
    if (!userManager.isUserAuthenticated(gmailHashID)) {
        throw new Error(`User ${gmailHashID} is not authenticated. Please authenticate first.`);
    }
    
    const client = await userManager.getOrCreateClient(gmailHashID);
    
    // Verify credentials are still valid by testing API access
    try {
        await client.gmailApi.users.getProfile({ userId: 'me' });
        return client;
    } catch (error) {
        logger.warn(`Credentials expired for user ${gmailHashID}, removing from cache`);
        clientCache.delete(gmailHashID);
        throw new Error(`Authentication expired for user ${gmailHashID}. Please re-authenticate.`);
    }
}

/**
 * Recursively extract email body content from MIME message parts
 */
function extractEmailContent(messagePart: GmailMessagePart): EmailContent {
    let textContent = '';
    let htmlContent = '';

    if (messagePart.body && messagePart.body.data) {
        const content = Buffer.from(messagePart.body.data, 'base64').toString('utf8');

        if (messagePart.mimeType === 'text/plain') {
            textContent = content;
        } else if (messagePart.mimeType === 'text/html') {
            htmlContent = content;
        }
    }

    if (messagePart.parts && messagePart.parts.length > 0) {
        for (const part of messagePart.parts) {
            const { text, html } = extractEmailContent(part);
            if (text) textContent += text;
            if (html) htmlContent += html;
        }
    }

    return { text: textContent, html: htmlContent };
}

// Enhanced schemas to include gmailHashID
const BaseUserSchema = z.object({
    gmailHashID: z.string().describe("Gmail user hash ID for authentication")
});

const SendEmailSchema = BaseUserSchema.extend({
    to: z.array(z.string()).describe("List of recipient email addresses"),
    subject: z.string().describe("Email subject"),
    body: z.string().describe("Email body content"),
    htmlBody: z.string().optional().describe("HTML version of the email body"),
    mimeType: z.enum(['text/plain', 'text/html', 'multipart/alternative']).optional().default('text/plain'),
    cc: z.array(z.string()).optional().describe("List of CC recipients"),
    bcc: z.array(z.string()).optional().describe("List of BCC recipients"),
    threadId: z.string().optional().describe("Thread ID to reply to"),
    inReplyTo: z.string().optional().describe("Message ID being replied to"),
});

const ReadEmailSchema = BaseUserSchema.extend({
    messageId: z.string().describe("ID of the email message to retrieve"),
});

const SearchEmailsSchema = BaseUserSchema.extend({
    query: z.string().describe("Gmail search query"),
    maxResults: z.number().optional().describe("Maximum number of results to return"),
});

const ModifyEmailSchema = BaseUserSchema.extend({
    messageId: z.string().describe("ID of the email message to modify"),
    labelIds: z.array(z.string()).optional().describe("List of label IDs to apply"),
    addLabelIds: z.array(z.string()).optional().describe("List of label IDs to add"),
    removeLabelIds: z.array(z.string()).optional().describe("List of label IDs to remove"),
});

const DeleteEmailSchema = BaseUserSchema.extend({
    messageId: z.string().describe("ID of the email message to delete"),
});

const ListEmailLabelsSchema = BaseUserSchema;

const CreateLabelSchema = BaseUserSchema.extend({
    name: z.string().describe("Name for the new label"),
    messageListVisibility: z.enum(['show', 'hide']).optional(),
    labelListVisibility: z.enum(['labelShow', 'labelShowIfUnread', 'labelHide']).optional(),
});

const UpdateLabelSchema = BaseUserSchema.extend({
    id: z.string().describe("ID of the label to update"),
    name: z.string().optional().describe("New name for the label"),
    messageListVisibility: z.enum(['show', 'hide']).optional(),
    labelListVisibility: z.enum(['labelShow', 'labelShowIfUnread', 'labelHide']).optional(),
});

const DeleteLabelSchema = BaseUserSchema.extend({
    id: z.string().describe("ID of the label to delete"),
});

const GetOrCreateLabelSchema = BaseUserSchema.extend({
    name: z.string().describe("Name of the label to get or create"),
    messageListVisibility: z.enum(['show', 'hide']).optional(),
    labelListVisibility: z.enum(['labelShow', 'labelShowIfUnread', 'labelHide']).optional(),
});

const BatchModifyEmailsSchema = BaseUserSchema.extend({
    messageIds: z.array(z.string()).describe("List of message IDs to modify"),
    addLabelIds: z.array(z.string()).optional(),
    removeLabelIds: z.array(z.string()).optional(),
    batchSize: z.number().optional().default(50),
});

const BatchDeleteEmailsSchema = BaseUserSchema.extend({
    messageIds: z.array(z.string()).describe("List of message IDs to delete"),
    batchSize: z.number().optional().default(50),
});

// Add authentication schema
const AuthenticateUserSchema = z.object({
    gmailHashID: z.string().describe("Gmail user hash ID to authenticate")
});

// Add cache stats schema
const GetCacheStatsSchema = z.object({});

// Add this function before the main() function
async function processBatches<T>(
    items: T[],
    batchSize: number,
    processor: (batch: T[]) => Promise<any[]>
): Promise<{ successes: any[], failures: { item: T, error: Error }[] }> {
    const successes: any[] = [];
    const failures: { item: T, error: Error }[] = [];

    for (let i = 0; i < items.length; i += batchSize) {
        const batch = items.slice(i, i + batchSize);
        try {
            const batchResults = await processor(batch);
            successes.push(...batchResults);
        } catch (error) {
            // If batch fails, process items individually
            for (const item of batch) {
                try {
                    const result = await processor([item]);
                    successes.push(...result);
                } catch (itemError) {
                    failures.push({ item, error: itemError as Error });
                }
            }
        }
    }

    return { successes, failures };
}

// =================
// MCP HANDLER SETUP (Shared by both transports)
// =================

function setupMCPHandlers() {
  logger.info('Setting up MCP request handlers');
  
  // List Tools Handler
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    logger.info('ListTools request received');
    const tools = [
      {
        name: "authenticate_user",
        description: "Authenticate a specific user for Gmail access",
        inputSchema: zodToJsonSchema(AuthenticateUserSchema),
      },
      {
        name: "send_email",
        description: "Sends a new email",
        inputSchema: zodToJsonSchema(SendEmailSchema),
      },
      {
        name: "draft_email",
        description: "Draft a new email",
        inputSchema: zodToJsonSchema(SendEmailSchema),
      },
      {
        name: "read_email",
        description: "Retrieves the content of a specific email",
        inputSchema: zodToJsonSchema(ReadEmailSchema),
      },
      {
        name: "search_emails",
        description: "Searches for emails using Gmail search syntax",
        inputSchema: zodToJsonSchema(SearchEmailsSchema),
      },
      {
        name: "modify_email",
        description: "Modifies email labels (move to different folders)",
        inputSchema: zodToJsonSchema(ModifyEmailSchema),
      },
      {
        name: "delete_email",
        description: "Permanently deletes an email",
        inputSchema: zodToJsonSchema(DeleteEmailSchema),
      },
      {
        name: "list_email_labels",
        description: "Retrieves all available Gmail labels",
        inputSchema: zodToJsonSchema(ListEmailLabelsSchema),
      },
      {
        name: "batch_modify_emails",
        description: "Modifies labels for multiple emails in batches",
        inputSchema: zodToJsonSchema(BatchModifyEmailsSchema),
      },
      {
        name: "batch_delete_emails",
        description: "Permanently deletes multiple emails in batches",
        inputSchema: zodToJsonSchema(BatchDeleteEmailsSchema),
      },
      {
        name: "create_label",
        description: "Creates a new Gmail label",
        inputSchema: zodToJsonSchema(CreateLabelSchema),
      },
      {
        name: "update_label",
        description: "Updates an existing Gmail label",
        inputSchema: zodToJsonSchema(UpdateLabelSchema),
      },
      {
        name: "delete_label",
        description: "Deletes a Gmail label",
        inputSchema: zodToJsonSchema(DeleteLabelSchema),
      },
      {
        name: "get_or_create_label",
        description: "Gets an existing label by name or creates it if it doesn't exist",
        inputSchema: zodToJsonSchema(GetOrCreateLabelSchema),
      },
      {
        name: "get_cache_stats",
        description: "Get cache statistics for monitoring",
        inputSchema: zodToJsonSchema(GetCacheStatsSchema),
      },
    ];
    
    logger.info('ListTools response sent', { toolCount: tools.length });
    return { tools };
  });

  // Call Tool Handler
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    const userManager = UserManager.getInstance();
    
    logger.info("Received tool call", { 
      name, 
      gmailHashID: args?.gmailHashID,
      complexity: TOOL_COMPLEXITY.simple.includes(name) ? 'simple' : 
                 TOOL_COMPLEXITY.complex.includes(name) ? 'complex' : 'variable'
    });

    try {
      // Handle authentication separately
      if (name === "authenticate_user") {
        const validatedArgs = AuthenticateUserSchema.parse(args);
        const { authUrl } = await userManager.generateAuthURL(validatedArgs.gmailHashID);
        
        const result = {
          content: [{
            type: "text",
            text: JSON.stringify({
              message: "Please visit this URL to authenticate your Gmail account",
              auth_url: authUrl,
              status: "authentication_required"
            }),
          }],
        };
        console.log(`✅ [SSE TOOL RESPONSE] ${name} - Success - User: ${validatedArgs.gmailHashID}`);
        return result;
      }

      // Handle cache stats
      if (name === "get_cache_stats") {
        const stats = userManager.getCacheStats();
        const result = {
          content: [{
            type: "text",
            text: `Cache Statistics:\nSize: ${stats.size}/${stats.maxSize}\nCalculated Size: ${stats.calculatedSize}`,
          }],
        };
        console.log(`✅ [SSE TOOL RESPONSE] ${name} - Success - Stats Retrieved`);
        return result;
      }

      // Extract user context and get authenticated client
      const gmailHashID = extractUserContext(args);
      const client = await getAuthenticatedClient(gmailHashID);
      const gmail = client.gmailApi;

      // Handle email operations with user-specific client
      switch (name) {
        case "send_email":
        case "draft_email": {
          const validatedArgs = SendEmailSchema.parse(args);
          const message = createEmailMessage(validatedArgs);

          const encodedMessage = Buffer.from(message).toString('base64')
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/, '');

          const messageRequest: any = {
            raw: encodedMessage,
          };

          if (validatedArgs.threadId) {
            messageRequest.threadId = validatedArgs.threadId;
          }

          if (name === "send_email") {
            const response = await gmail.users.messages.send({
              userId: 'me',
              requestBody: messageRequest,
            });
            const result = {
              content: [{
                type: "text",
                text: `Email sent successfully with ID: ${response.data.id}`,
              }],
            };
            console.log(`✅ [SSE TOOL RESPONSE] ${name} - Success - Email sent: ${response.data.id} - User: ${gmailHashID}`);
            return result;
          } else {
            const response = await gmail.users.drafts.create({
              userId: 'me',
              requestBody: {
                message: messageRequest,
              },
            });
            const result = {
              content: [{
                type: "text",
                text: `Email draft created successfully with ID: ${response.data.id}`,
              }],
            };
            console.log(`✅ [SSE TOOL RESPONSE] ${name} - Success - Draft created: ${response.data.id} - User: ${gmailHashID}`);
            return result;
          }
        }

        case "read_email": {
          const validatedArgs = ReadEmailSchema.parse(args);
          const response = await gmail.users.messages.get({
            userId: 'me',
            id: validatedArgs.messageId,
            format: 'full',
          });

          const headers = response.data.payload?.headers || [];
          const subject = headers.find((h: { name?: string; value?: string }) => h.name?.toLowerCase() === 'subject')?.value || '';
          const from = headers.find((h: { name?: string; value?: string }) => h.name?.toLowerCase() === 'from')?.value || '';
          const to = headers.find((h: { name?: string; value?: string }) => h.name?.toLowerCase() === 'to')?.value || '';
          const date = headers.find((h: { name?: string; value?: string }) => h.name?.toLowerCase() === 'date')?.value || '';
          const threadId = response.data.threadId || '';

          const { text, html } = extractEmailContent(response.data.payload as GmailMessagePart || {});
          let body = text || html || '';
          const contentTypeNote = !text && html ?
            '[Note: This email is HTML-formatted. Plain text version not available.]\n\n' : '';

          return {
            content: [{
              type: "text",
              text: `Thread ID: ${threadId}\nSubject: ${subject}\nFrom: ${from}\nTo: ${to}\nDate: ${date}\n\n${contentTypeNote}${body}`,
            }],
          };
        }

        case "search_emails": {
          const validatedArgs = SearchEmailsSchema.parse(args);
          const response = await gmail.users.messages.list({
            userId: 'me',
            q: validatedArgs.query,
            maxResults: validatedArgs.maxResults || 10,
          });

          const messages = response.data.messages || [];
          const results = await Promise.all(
            messages.map(async (msg: { id?: string }) => {
              const detail = await gmail.users.messages.get({
                userId: 'me',
                id: msg.id!,
                format: 'metadata',
                metadataHeaders: ['Subject', 'From', 'Date'],
              });
              const headers = detail.data.payload?.headers || [];
              return {
                id: msg.id,
                subject: headers.find((h: { name?: string; value?: string }) => h.name === 'Subject')?.value || '',
                from: headers.find((h: { name?: string; value?: string }) => h.name === 'From')?.value || '',
                date: headers.find((h: { name?: string; value?: string }) => h.name === 'Date')?.value || '',
              };
            })
          );

          return {
            content: [{
              type: "text",
              text: results.map(r =>
                `ID: ${r.id}\nSubject: ${r.subject}\nFrom: ${r.from}\nDate: ${r.date}\n`
              ).join('\n'),
            }],
          };
        }

        case "modify_email": {
          const validatedArgs = ModifyEmailSchema.parse(args);
          
          const requestBody: any = {};
          
          if (validatedArgs.labelIds) {
            requestBody.addLabelIds = validatedArgs.labelIds;
          }
          
          if (validatedArgs.addLabelIds) {
            requestBody.addLabelIds = validatedArgs.addLabelIds;
          }
          
          if (validatedArgs.removeLabelIds) {
            requestBody.removeLabelIds = validatedArgs.removeLabelIds;
          }
          
          await gmail.users.messages.modify({
            userId: 'me',
            id: validatedArgs.messageId,
            requestBody: requestBody,
          });

          return {
            content: [{
              type: "text",
              text: `Email ${validatedArgs.messageId} labels updated successfully`,
            }],
          };
        }

        case "delete_email": {
          const validatedArgs = DeleteEmailSchema.parse(args);
          await gmail.users.messages.delete({
            userId: 'me',
            id: validatedArgs.messageId,
          });

          return {
            content: [{
              type: "text",
              text: `Email ${validatedArgs.messageId} deleted successfully`,
            }],
          };
        }

        case "list_email_labels": {
          const labelResults = await listLabels(gmail);
          const systemLabels = labelResults.system;
          const userLabels = labelResults.user;

          return {
            content: [{
              type: "text",
              text: `Found ${labelResults.count.total} labels (${labelResults.count.system} system, ${labelResults.count.user} user):\n\n` +
                "System Labels:\n" +
                systemLabels.map((l: GmailLabel) => `ID: ${l.id}\nName: ${l.name}\n`).join('\n') +
                "\nUser Labels:\n" +
                userLabels.map((l: GmailLabel) => `ID: ${l.id}\nName: ${l.name}\n`).join('\n')
            }],
          };
        }
        
        case "batch_modify_emails": {
          const validatedArgs = BatchModifyEmailsSchema.parse(args);
          const messageIds = validatedArgs.messageIds;
          const batchSize = validatedArgs.batchSize || 50;
          
          const requestBody: any = {};
          
          if (validatedArgs.addLabelIds) {
            requestBody.addLabelIds = validatedArgs.addLabelIds;
          }
          
          if (validatedArgs.removeLabelIds) {
            requestBody.removeLabelIds = validatedArgs.removeLabelIds;
          }

          // Process messages in batches
          const { successes, failures } = await processBatches(
            messageIds,
            batchSize,
            async (batch) => {
              const results = await Promise.all(
                batch.map(async (messageId) => {
                  const result = await gmail.users.messages.modify({
                    userId: 'me',
                    id: messageId,
                    requestBody: requestBody,
                  });
                  return { messageId, success: true };
                })
              );
              return results;
            }
          );

          const successCount = successes.length;
          const failureCount = failures.length;
          
          let resultText = `Batch label modification complete.\n`;
          resultText += `Successfully processed: ${successCount} messages\n`;
          
          if (failureCount > 0) {
            resultText += `Failed to process: ${failureCount} messages\n\n`;
            resultText += `Failed message IDs:\n`;
            resultText += failures.map(f => `- ${(f.item as string).substring(0, 16)}... (${f.error.message})`).join('\n');
          }

          return {
            content: [{
              type: "text",
              text: resultText,
            }],
          };
        }

        case "batch_delete_emails": {
          const validatedArgs = BatchDeleteEmailsSchema.parse(args);
          const messageIds = validatedArgs.messageIds;
          const batchSize = validatedArgs.batchSize || 50;

          // Process messages in batches
          const { successes, failures } = await processBatches(
            messageIds,
            batchSize,
            async (batch) => {
              const results = await Promise.all(
                batch.map(async (messageId) => {
                  await gmail.users.messages.delete({
                    userId: 'me',
                    id: messageId,
                  });
                  return { messageId, success: true };
                })
              );
              return results;
            }
          );

          const successCount = successes.length;
          const failureCount = failures.length;
          
          let resultText = `Batch delete operation complete.\n`;
          resultText += `Successfully deleted: ${successCount} messages\n`;
          
          if (failureCount > 0) {
            resultText += `Failed to delete: ${failureCount} messages\n\n`;
            resultText += `Failed message IDs:\n`;
            resultText += failures.map(f => `- ${(f.item as string).substring(0, 16)}... (${f.error.message})`).join('\n');
          }

          return {
            content: [{
              type: "text",
              text: resultText,
            }],
          };
        }

        case "create_label": {
          const validatedArgs = CreateLabelSchema.parse(args);
          const result = await createLabel(gmail, validatedArgs.name, {
            messageListVisibility: validatedArgs.messageListVisibility,
            labelListVisibility: validatedArgs.labelListVisibility,
          });

          return {
            content: [{
              type: "text",
              text: `Label created successfully:\nID: ${result.id}\nName: ${result.name}\nType: ${result.type}`,
            }],
          };
        }

        case "update_label": {
          const validatedArgs = UpdateLabelSchema.parse(args);
          
          const updates: any = {};
          if (validatedArgs.name) updates.name = validatedArgs.name;
          if (validatedArgs.messageListVisibility) updates.messageListVisibility = validatedArgs.messageListVisibility;
          if (validatedArgs.labelListVisibility) updates.labelListVisibility = validatedArgs.labelListVisibility;
          
          const result = await updateLabel(gmail, validatedArgs.id, updates);

          return {
            content: [{
              type: "text",
              text: `Label updated successfully:\nID: ${result.id}\nName: ${result.name}\nType: ${result.type}`,
            }],
          };
        }

        case "delete_label": {
          const validatedArgs = DeleteLabelSchema.parse(args);
          const result = await deleteLabel(gmail, validatedArgs.id);

          return {
            content: [{
              type: "text",
              text: result.message,
            }],
          };
        }

        case "get_or_create_label": {
          const validatedArgs = GetOrCreateLabelSchema.parse(args);
          const result = await getOrCreateLabel(gmail, validatedArgs.name, {
            messageListVisibility: validatedArgs.messageListVisibility,
            labelListVisibility: validatedArgs.labelListVisibility,
          });

          const action = result.type === 'user' && result.name === validatedArgs.name ? 'found existing' : 'created new';
          
          return {
            content: [{
              type: "text",
              text: `Successfully ${action} label:\nID: ${result.id}\nName: ${result.name}\nType: ${result.type}`,
            }],
          };
        }

        default:
          throw new Error(`Unknown tool: ${name}`);
      }
      
      // This code won't be reached due to returns in switch cases,
      // but if we add a variable to capture results, we could log here
    } catch (error: any) {
      console.log(`❌ [SSE TOOL RESPONSE] ${name} - Error: ${error.message} - User: ${args?.gmailHashID}`);
      logger.error(`Tool call failed: ${name}`, { error: error.message, gmailHashID: args?.gmailHashID });
      return {
        content: [{
          type: "text",
          text: `Error: ${error.message}`,
        }],
      };
    }
  });
}

/**
 * Handle tool calls - extracted for reuse in HTTP transport
 */
async function handleToolCall(name: string, args: any, gmail: any, gmailHashID: string): Promise<any> {
  switch (name) {
    case "send_email":
    case "draft_email": {
      const validatedArgs = SendEmailSchema.parse(args);
      const message = createEmailMessage(validatedArgs);

      const encodedMessage = Buffer.from(message).toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');

      const messageRequest: any = {
        raw: encodedMessage,
      };

      if (validatedArgs.threadId) {
        messageRequest.threadId = validatedArgs.threadId;
      }

      if (name === "send_email") {
        const response = await gmail.users.messages.send({
          userId: 'me',
          requestBody: messageRequest,
        });
        return {
          content: [{
            type: "text",
            text: `Email sent successfully with ID: ${response.data.id}`,
          }],
        };
      } else {
        const response = await gmail.users.drafts.create({
          userId: 'me',
          requestBody: {
            message: messageRequest,
          },
        });
        return {
          content: [{
            type: "text",
            text: `Email draft created successfully with ID: ${response.data.id}`,
          }],
        };
      }
    }

    case "read_email": {
      const validatedArgs = ReadEmailSchema.parse(args);
      const response = await gmail.users.messages.get({
        userId: 'me',
        id: validatedArgs.messageId,
        format: 'full',
      });

      const headers = response.data.payload?.headers || [];
      const subject = headers.find((h: { name?: string; value?: string }) => h.name?.toLowerCase() === 'subject')?.value || '';
      const from = headers.find((h: { name?: string; value?: string }) => h.name?.toLowerCase() === 'from')?.value || '';
      const to = headers.find((h: { name?: string; value?: string }) => h.name?.toLowerCase() === 'to')?.value || '';
      const date = headers.find((h: { name?: string; value?: string }) => h.name?.toLowerCase() === 'date')?.value || '';
      const threadId = response.data.threadId || '';

      const { text, html } = extractEmailContent(response.data.payload as GmailMessagePart || {});
      let body = text || html || '';
      const contentTypeNote = !text && html ?
        '[Note: This email is HTML-formatted. Plain text version not available.]\n\n' : '';

      return {
        content: [{
          type: "text",
          text: `Thread ID: ${threadId}\nSubject: ${subject}\nFrom: ${from}\nTo: ${to}\nDate: ${date}\n\n${contentTypeNote}${body}`,
        }],
      };
    }

    case "search_emails": {
      const validatedArgs = SearchEmailsSchema.parse(args);
      const response = await gmail.users.messages.list({
        userId: 'me',
        q: validatedArgs.query,
        maxResults: validatedArgs.maxResults || 10,
      });

      const messages = response.data.messages || [];
      const results = await Promise.all(
        messages.map(async (msg: { id?: string }) => {
          const detail = await gmail.users.messages.get({
            userId: 'me',
            id: msg.id!,
            format: 'metadata',
            metadataHeaders: ['Subject', 'From', 'Date'],
          });
          const headers = detail.data.payload?.headers || [];
          return {
            id: msg.id,
            subject: headers.find((h: { name?: string; value?: string }) => h.name === 'Subject')?.value || '',
            from: headers.find((h: { name?: string; value?: string }) => h.name === 'From')?.value || '',
            date: headers.find((h: { name?: string; value?: string }) => h.name === 'Date')?.value || '',
          };
        })
      );

      return {
        content: [{
          type: "text",
          text: results.map(r =>
            `ID: ${r.id}\nSubject: ${r.subject}\nFrom: ${r.from}\nDate: ${r.date}\n`
          ).join('\n'),
        }],
      };
    }

    case "modify_email": {
      const validatedArgs = ModifyEmailSchema.parse(args);
      
      const requestBody: any = {};
      
      if (validatedArgs.labelIds) {
        requestBody.addLabelIds = validatedArgs.labelIds;
      }
      
      if (validatedArgs.addLabelIds) {
        requestBody.addLabelIds = validatedArgs.addLabelIds;
      }
      
      if (validatedArgs.removeLabelIds) {
        requestBody.removeLabelIds = validatedArgs.removeLabelIds;
      }
      
      await gmail.users.messages.modify({
        userId: 'me',
        id: validatedArgs.messageId,
        requestBody: requestBody,
      });

      return {
        content: [{
          type: "text",
          text: `Email ${validatedArgs.messageId} labels updated successfully`,
        }],
      };
    }

    case "delete_email": {
      const validatedArgs = DeleteEmailSchema.parse(args);
      await gmail.users.messages.delete({
        userId: 'me',
        id: validatedArgs.messageId,
      });

      return {
        content: [{
          type: "text",
          text: `Email ${validatedArgs.messageId} deleted successfully`,
        }],
      };
    }

    case "list_email_labels": {
      const labelResults = await listLabels(gmail);
      const systemLabels = labelResults.system;
      const userLabels = labelResults.user;

      return {
        content: [{
          type: "text",
          text: `Found ${labelResults.count.total} labels (${labelResults.count.system} system, ${labelResults.count.user} user):\n\n` +
            "System Labels:\n" +
            systemLabels.map((l: GmailLabel) => `ID: ${l.id}\nName: ${l.name}\n`).join('\n') +
            "\nUser Labels:\n" +
            userLabels.map((l: GmailLabel) => `ID: ${l.id}\nName: ${l.name}\n`).join('\n')
        }],
      };
    }

    case "batch_modify_emails": {
      const validatedArgs = BatchModifyEmailsSchema.parse(args);
      const messageIds = validatedArgs.messageIds;
      const batchSize = validatedArgs.batchSize || 50;
      
      const requestBody: any = {};
      
      if (validatedArgs.addLabelIds) {
        requestBody.addLabelIds = validatedArgs.addLabelIds;
      }
      
      if (validatedArgs.removeLabelIds) {
        requestBody.removeLabelIds = validatedArgs.removeLabelIds;
      }

      // Process messages in batches
      const { successes, failures } = await processBatches(
        messageIds,
        batchSize,
        async (batch) => {
          const results = await Promise.all(
            batch.map(async (messageId) => {
              const result = await gmail.users.messages.modify({
                userId: 'me',
                id: messageId,
                requestBody: requestBody,
              });
              return { messageId, success: true };
            })
          );
          return results;
        }
      );

      const successCount = successes.length;
      const failureCount = failures.length;
      
      let resultText = `Batch label modification complete.\n`;
      resultText += `Successfully processed: ${successCount} messages\n`;
      
      if (failureCount > 0) {
        resultText += `Failed to process: ${failureCount} messages\n\n`;
        resultText += `Failed message IDs:\n`;
        resultText += failures.map(f => `- ${(f.item as string).substring(0, 16)}... (${f.error.message})`).join('\n');
      }

      return {
        content: [{
          type: "text",
          text: resultText,
        }],
      };
    }

    case "batch_delete_emails": {
      const validatedArgs = BatchDeleteEmailsSchema.parse(args);
      const messageIds = validatedArgs.messageIds;
      const batchSize = validatedArgs.batchSize || 50;

      // Process messages in batches
      const { successes, failures } = await processBatches(
        messageIds,
        batchSize,
        async (batch) => {
          const results = await Promise.all(
            batch.map(async (messageId) => {
              await gmail.users.messages.delete({
                userId: 'me',
                id: messageId,
              });
              return { messageId, success: true };
            })
          );
          return results;
        }
      );

      const successCount = successes.length;
      const failureCount = failures.length;
      
      let resultText = `Batch delete operation complete.\n`;
      resultText += `Successfully deleted: ${successCount} messages\n`;
      
      if (failureCount > 0) {
        resultText += `Failed to delete: ${failureCount} messages\n\n`;
        resultText += `Failed message IDs:\n`;
        resultText += failures.map(f => `- ${(f.item as string).substring(0, 16)}... (${f.error.message})`).join('\n');
      }

      return {
        content: [{
          type: "text",
          text: resultText,
        }],
      };
    }

    case "create_label": {
      const validatedArgs = CreateLabelSchema.parse(args);
      const result = await createLabel(gmail, validatedArgs.name, {
        messageListVisibility: validatedArgs.messageListVisibility,
        labelListVisibility: validatedArgs.labelListVisibility,
      });

      return {
        content: [{
          type: "text",
          text: `Label created successfully:\nID: ${result.id}\nName: ${result.name}\nType: ${result.type}`,
        }],
      };
    }

    case "update_label": {
      const validatedArgs = UpdateLabelSchema.parse(args);
      
      const updates: any = {};
      if (validatedArgs.name) updates.name = validatedArgs.name;
      if (validatedArgs.messageListVisibility) updates.messageListVisibility = validatedArgs.messageListVisibility;
      if (validatedArgs.labelListVisibility) updates.labelListVisibility = validatedArgs.labelListVisibility;
      
      const result = await updateLabel(gmail, validatedArgs.id, updates);

      return {
        content: [{
          type: "text",
          text: `Label updated successfully:\nID: ${result.id}\nName: ${result.name}\nType: ${result.type}`,
        }],
      };
    }

    case "delete_label": {
      const validatedArgs = DeleteLabelSchema.parse(args);
      const result = await deleteLabel(gmail, validatedArgs.id);

      return {
        content: [{
          type: "text",
          text: result.message,
        }],
      };
    }

    case "get_or_create_label": {
      const validatedArgs = GetOrCreateLabelSchema.parse(args);
      const result = await getOrCreateLabel(gmail, validatedArgs.name, {
        messageListVisibility: validatedArgs.messageListVisibility,
        labelListVisibility: validatedArgs.labelListVisibility,
      });

      const action = result.type === 'user' && result.name === validatedArgs.name ? 'found existing' : 'created new';
      
      return {
        content: [{
          type: "text",
          text: `Successfully ${action} label:\nID: ${result.id}\nName: ${result.name}\nType: ${result.type}`,
        }],
      };
    }

    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}

// =================
// STDIO TRANSPORT SETUP (Original functionality)
// =================

async function setupStdioTransport() {
  logger.info('Connecting to STDIO transport');
  const transport = new StdioServerTransport();
  await server.connect(transport);
  logger.info('STDIO MCP Server connected and ready to handle requests');
}

// =================
// HTTP TRANSPORT SETUP (New functionality)
// =================

async function setupHTTPTransport(port: number = 4008) {
  logger.info(`Setting up HTTP transport on port ${port}`);
  
  const app = express();
  
  // Add request logging middleware
  app.use((req, res, next) => {
    const startTime = Date.now();
    const clientIP = req.ip || req.socket.remoteAddress;
    
    logger.debug(`📨 Incoming request`, {
      method: req.method,
      url: req.originalUrl,
      clientIP,
      userAgent: req.headers['user-agent'],
      contentType: req.headers['content-type'],
    });
    
    next();
  });
  
  app.use(express.json());
  app.use(cookieParser());
  
  // Configure CORS to support credentials for HTTP-only cookies
  app.use(cors({
    credentials: true,
    origin: [
      'http://localhost:3000',      // React dev
      'http://localhost:5173',      // Vite dev
      'https://luciuslab.xyz'       // Production
    ],
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
  }));
  
  // Cookie helper functions for HTTP-only cookie management
  function setUserSessionCookies(res: express.Response, userIdHash: string, gmailHashId: string): express.Response {
    const cookieOptions = {
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
      httpOnly: true,
      secure: false, // true in production
      sameSite: 'lax' as const,
      path: '/'
    };
    
    res.cookie('userIDHash', userIdHash, cookieOptions);
    res.cookie('gmailHashID', gmailHashId, cookieOptions);
    
    return res;
  }
  
  function getUserFromCookies(req: express.Request): { userIdHash?: string; gmailHashId?: string } {
    return {
      userIdHash: req.cookies?.userIDHash,
      gmailHashId: req.cookies?.gmailHashID
    };
  }
  
  function clearUserSessionCookies(res: express.Response): express.Response {
    res.clearCookie('userIDHash', { path: '/' });
    res.clearCookie('gmailHashID', { path: '/' });
    return res;
  }
  
  function getUserAuth(req: express.Request): { userIdHash?: string; gmailHashId?: string } {
    // Try cookies first (new way)
    const cookieAuth = getUserFromCookies(req);
    
    // Fallback to request body (old way) for backward compatibility
    if (!cookieAuth.userIdHash) {
      return {
        userIdHash: req.body?.userIDHash,
        gmailHashId: req.body?.gmailHashID
      };
    }
    
    return cookieAuth;
  }
  
  // Add authentication initiation endpoint
  app.post('/initiate-auth', async (req, res) => {
    console.log(`📥 POST /initiate-auth request from ${req.ip || req.socket.remoteAddress}`);
    
    // Try cookies first, then fallback to request body
    const auth = getUserAuth(req);
    let gmailHashID = auth.gmailHashId;
    let userIDHash = auth.userIdHash;
    
    // If no existing auth, generate new UUIDs
    if (!gmailHashID) {
      gmailHashID = crypto.randomUUID();
      userIDHash = crypto.randomUUID();
      console.log(`Generated new gmailHashID: ${gmailHashID}`);
      console.log(`Generated new userIDHash: ${userIDHash}`);
    } else {
      console.log(`Using existing gmailHashID: ${gmailHashID}`);
    }
    
    const userManager = UserManager.getInstance();
    
    try {
      
      // Check if already authenticated
      if (userManager.isUserAuthenticated(gmailHashID)) {
        setUserSessionCookies(res, userIDHash!, gmailHashID);
        return res.json({
          status: 'already_authenticated',
          message: 'User already has valid tokens'
        });
      }
      
      // Generate authentication URL and start callback server
      const { authUrl, callbackPort } = await userManager.generateAuthURL(gmailHashID);
      
      setUserSessionCookies(res, userIDHash!, gmailHashID);
      return res.json({
        status: 'auth_required',
        message: 'Please open the provided URL in your browser to authenticate',
        authUrl: authUrl,
        callbackPort: callbackPort,
        instructions: 'Open the authUrl in your browser to complete Gmail authentication'
      });
      
    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      
      // Set cookies even on error so user can retry
      setUserSessionCookies(res, userIDHash!, gmailHashID);
      return res.status(500).json({
        status: 'error',
        message: errorMessage
      });
    }
  });


  // Gmail status check endpoint
  app.post('/checkGmailStatus', async (req, res) => {
    console.log(`📥 POST /checkGmailStatus request from ${req.ip || req.socket.remoteAddress}`);
    
    // Read from cookies instead of request body
    const auth = getUserFromCookies(req);
    const gmailHashID = auth.gmailHashId;
    
    if (!gmailHashID) {
      return res.status(401).json({
        status: false,
        error: 'No session found. Please authenticate first.'
      });
    }
    
    const userManager = UserManager.getInstance();
    console.log(`Gmail status check requested for user: ${gmailHashID}`);
    
    logger.info(`📊 Gmail status check requested`, {
      gmailHashID,
      clientIP: req.ip || req.socket.remoteAddress
    });

    try {
      
      // ok so expected flow is that 
      // we can authenticate the user for gmail, access the credentials during 
      // text mode and then switch to voice and voice can detect the same credentials to use for requests
      const isAuthenticated = userManager.isUserAuthenticated(gmailHashID);
      
      if (!isAuthenticated) {
        return res.json({
          status: false,
          error: 'No authentication tokens foundd'
        });
      }
      
      // Try to verify credentials are still valid
      try {
        const client = await userManager.getOrCreateClient(gmailHashID);
        await client.gmailApi.users.getProfile({ userId: 'me' });
        
        return res.json({
          status: true,
          authenticated: true
        });
      } catch (error) {
        return res.json({
          status: false,
          error: 'Authentication expired'
        });
      }
      
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      
      return res.status(500).json({
        status: false,
        error: errorMessage
      });
    }
  });

  // Store active transports for session management
  const transports: Record<string, StreamableHTTPServerTransport> = {};
  
  // Main MCP endpoint - handles both GET and POST
  // Handle OAuth callback before MCP endpoint
  app.get('/oauth2callback', async (req, res) => {
    console.log(`📥 OAuth callback request: ${req.method} ${req.url}`);
    
    const code = req.query.code as string;
    const error = req.query.error as string;
    const state = req.query.state as string;

    if (error) {
      res.status(400).send(`<h1>❌ Authentication Error</h1><p>Error: ${error}</p>`);
      return;
    }

    if (!code || !state) {
      res.status(400).send('<h1>❌ Authentication Failed</h1><p>Missing required parameters</p>');
      return;
    }

    try {
      const stateData = JSON.parse(state);
      const gmailHashID = stateData.userID;

      if (!gmailHashID) {
        res.status(400).send('<h1>❌ Authentication Failed</h1><p>Invalid state parameter</p>');
        return;
      }

      // Get OAuth client and exchange code for tokens
      const userManager = UserManager.getInstance();
      const oauth2Client = userManager.createOAuth2Client(gmailHashID, 4007);
      const { tokens } = await oauth2Client.getToken(code);
      
      // Save the credentials
      userManager.saveUserCredentials(gmailHashID, tokens);
      
      res.status(200).send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Gmail Authentication Complete</title>
            <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
            <style>
                :root {
                    --primary-gradient: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    --gmail-primary: #EA4335;
                    --gmail-secondary: #FBBC04;
                    --success-color: #10b981;
                    --text-primary: #1f2937;
                    --text-secondary: #6b7280;
                    --bg-primary: #ffffff;
                    --bg-secondary: #f8fafc;
                    --border-color: #e5e7eb;
                    --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
                    --shadow-lg: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
                }

                * {
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                }

                body {
                    font-family: 'Inter', -apple-system, BlinkMacSystemFont, system-ui, sans-serif;
                    background: var(--primary-gradient);
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    padding: 20px;
                    position: relative;
                    overflow-x: hidden;
                }

                .background-pattern {
                    position: absolute;
                    top: 0;
                    left: 0;
                    right: 0;
                    bottom: 0;
                    opacity: 0.1;
                    background-image: radial-gradient(circle at 25% 25%, white 2px, transparent 0),
                                      radial-gradient(circle at 75% 75%, white 2px, transparent 0);
                    background-size: 50px 50px;
                    animation: float 20s ease-in-out infinite;
                }

                @keyframes float {
                    0%, 100% { transform: translate(0, 0) rotate(0deg); }
                    33% { transform: translate(10px, -10px) rotate(1deg); }
                    66% { transform: translate(-5px, 5px) rotate(-1deg); }
                }

                .container {
                    background: var(--bg-primary);
                    backdrop-filter: blur(20px);
                    border-radius: 24px;
                    padding: 48px 40px;
                    text-align: center;
                    box-shadow: var(--shadow-lg);
                    border: 1px solid rgba(255, 255, 255, 0.2);
                    max-width: 480px;
                    width: 100%;
                    position: relative;
                    z-index: 1;
                    animation: slideUp 0.6s ease-out;
                }

                @keyframes slideUp {
                    from {
                        opacity: 0;
                        transform: translateY(30px);
                    }
                    to {
                        opacity: 1;
                        transform: translateY(0);
                    }
                }

                .success-icon {
                    width: 80px;
                    height: 80px;
                    margin: 0 auto 24px;
                    background: linear-gradient(135deg, var(--success-color) 0%, #059669 100%);
                    border-radius: 50%;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    animation: pulse 2s ease-in-out infinite;
                }

                @keyframes pulse {
                    0%, 100% { transform: scale(1); }
                    50% { transform: scale(1.05); }
                }

                .checkmark {
                    width: 32px;
                    height: 32px;
                    stroke: white;
                    stroke-width: 3;
                    fill: none;
                    animation: drawCheck 0.8s ease-in-out 0.3s both;
                }

                @keyframes drawCheck {
                    to {
                        stroke-dashoffset: 0;
                    }
                }

                .checkmark path {
                    stroke-dasharray: 100;
                    stroke-dashoffset: 100;
                }

                h1 {
                    color: var(--text-primary);
                    font-size: 28px;
                    font-weight: 600;
                    margin-bottom: 16px;
                    line-height: 1.3;
                }

                .subtitle {
                    color: var(--text-secondary);
                    font-size: 16px;
                    font-weight: 400;
                    margin-bottom: 32px;
                    line-height: 1.5;
                }

                .gmail-logo {
                    display: inline-flex;
                    align-items: center;
                    gap: 8px;
                    margin-bottom: 24px;
                    padding: 12px 20px;
                    background: var(--bg-secondary);
                    border-radius: 12px;
                    border: 1px solid var(--border-color);
                }

                .gmail-icon {
                    width: 24px;
                    height: 24px;
                }

                .service-name {
                    color: var(--text-primary);
                    font-weight: 500;
                    font-size: 16px;
                }

                .status-badge {
                    display: inline-flex;
                    align-items: center;
                    gap: 8px;
                    background: rgba(16, 185, 129, 0.1);
                    color: var(--success-color);
                    padding: 8px 16px;
                    border-radius: 20px;
                    font-size: 14px;
                    font-weight: 500;
                    margin-bottom: 24px;
                }

                .status-dot {
                    width: 8px;
                    height: 8px;
                    background: var(--success-color);
                    border-radius: 50%;
                    animation: blink 2s ease-in-out infinite;
                }

                @keyframes blink {
                    0%, 100% { opacity: 1; }
                    50% { opacity: 0.5; }
                }

                .user-info {
                    background: var(--bg-secondary);
                    border: 1px solid var(--border-color);
                    border-radius: 16px;
                    padding: 20px;
                    margin: 24px 0;
                    text-align: left;
                }

                .user-label {
                    color: var(--text-secondary);
                    font-size: 14px;
                    font-weight: 500;
                    margin-bottom: 8px;
                    text-transform: uppercase;
                    letter-spacing: 0.5px;
                }

                .user-id {
                    color: var(--text-primary);
                    font-family: 'SF Mono', Monaco, 'Cascadia Code', 'Roboto Mono', Consolas, 'Courier New', monospace;
                    font-size: 14px;
                    word-break: break-all;
                    padding: 12px;
                    background: var(--bg-primary);
                    border-radius: 8px;
                    border: 1px solid var(--border-color);
                }

                .actions {
                    margin-top: 32px;
                    display: flex;
                    flex-direction: column;
                    gap: 12px;
                }

                .btn {
                    padding: 14px 24px;
                    border-radius: 12px;
                    font-weight: 500;
                    font-size: 16px;
                    cursor: pointer;
                    transition: all 0.2s ease;
                    border: none;
                    position: relative;
                    overflow: hidden;
                }

                .btn-primary {
                    background: var(--primary-gradient);
                    color: white;
                    box-shadow: var(--shadow-sm);
                }

                .btn-primary:hover {
                    transform: translateY(-2px);
                    box-shadow: 0 10px 25px -5px rgba(102, 126, 234, 0.4);
                }

                .btn-primary:active {
                    transform: translateY(0);
                }

                .footer-text {
                    color: var(--text-secondary);
                    font-size: 14px;
                    margin-top: 24px;
                    line-height: 1.5;
                }

                @media (max-width: 480px) {
                    .container {
                        padding: 32px 24px;
                        border-radius: 16px;
                    }
                    
                    h1 {
                        font-size: 24px;
                    }
                    
                    .success-icon {
                        width: 64px;
                        height: 64px;
                    }
                }
            </style>
            <script>
                let seconds = 5;
                const countdownElement = document.getElementById('countdown');
                
                const timer = setInterval(() => {
                    seconds--;
                    if (countdownElement) {
                        countdownElement.textContent = seconds;
                    }
                    
                    if (seconds <= 0) {
                        clearInterval(timer);
                        window.close();
                    }
                }, 1000);
                
                // Add click animation
                window.addEventListener('DOMContentLoaded', () => {
                    const button = document.querySelector('.btn-primary');
                    if (button) {
                        button.addEventListener('click', function() {
                            this.style.transform = 'scale(0.98)';
                            setTimeout(() => {
                                this.style.transform = '';
                            }, 150);
                        });
                    }
                });
            </script>
        </head>
        <body>
            <div class="background-pattern"></div>
            
            <div class="container">
                <div class="success-icon">
                    <svg class="checkmark" viewBox="0 0 100 100">
                        <path d="M20,50 L40,70 L80,30" stroke-linecap="round" stroke-linejoin="round"/>
                    </svg>
                </div>

                <div class="status-badge">
                    <div class="status-dot"></div>
                    Authentication Complete
                </div>

                <h1>Gmail Connected Successfully</h1>
                <p class="subtitle">Your Gmail account has been securely authenticated and connected to the MCP server.</p>

                <div class="gmail-logo">
                    <svg class="gmail-icon" viewBox="0 0 24 24" fill="none">
                        <path d="M24 5.457v13.909c0 .904-.732 1.636-1.636 1.636h-3.819V11.73L12 16.64l-6.545-4.91v9.273H1.636A1.636 1.636 0 0 1 0 19.366V5.457c0-.904.732-1.636 1.636-1.636h.008L12 13.727 22.356 3.821h.008c.904 0 1.636.732 1.636 1.636z" fill="#EA4335"/>
                    </svg>
                    <span class="service-name">Gmail MCP</span>
                </div>
                
                <div class="user-info">
                    <div class="user-label">Authenticated Session ID</div>
                    <div class="user-id">${gmailHashID}</div>
                </div>
                
                <div class="actions">
                    <button class="btn btn-primary" onclick="window.close()">
                        Continue & Close Window
                    </button>
                </div>
                
                <p class="footer-text">
                    This window will automatically close in <span id="countdown">5</span> seconds.<br>
                    Your Gmail integration is now ready for use.
                </p>
            </div>
        </body>
        </html>
      `);
      
    } catch (exchangeError) {
      logger.error(`OAuth token exchange failed:`, exchangeError);
      res.status(400).send(`<h1>❌ Authentication Failed</h1><p>Error: ${exchangeError instanceof Error ? exchangeError.message : 'Unknown error'}</p>`);
    }
  });

  app.all('/mcp', async (req, res) => {
    const requestStart = Date.now();
    const clientIP = req.ip || req.socket.remoteAddress;
    
    const jsonRpcRequest = req.method === 'POST' ? req.body : null;
    const toolName = jsonRpcRequest?.params?.name;
    const args = jsonRpcRequest?.params?.arguments || {};
    const gmailHashID = args?.gmailHashID;
    
    console.log(`📥 ${req.method} /mcp request from ${clientIP} - Tool: ${toolName || 'N/A'} - User: ${gmailHashID || 'N/A'}`);
    logger.info(`🌐 Incoming HTTP request`, {
      method: req.method,
      url: req.originalUrl,
      clientIP,
      toolName,
      gmailHashID,
      hasArgs: !!args,
      contentType: req.headers['content-type'],
      accept: req.headers.accept,
      sessionId: req.headers['mcp-session-id'],
    });
    
    try {
      // Generate or extract session ID
      let sessionId = req.headers['mcp-session-id'] as string;
      if (!sessionId && req.method === 'POST') {
        sessionId = crypto.randomUUID();
        logger.debug(`Generated new session ID: ${sessionId}`);
      }

      // Apply complexity analysis to determine response type
      const useSSE = shouldUseSSE(toolName, args, req);
      
      if (useSSE) {
        logger.info(`🌊 Using SSE for ${toolName}`, { 
          sessionId, 
          toolName, 
          gmailHashID,
          clientIP,
        });
        
        // Get or create transport for this session
        let transport = sessionId ? transports[sessionId] : null;
        if (!transport) {
          logger.debug(`🔧 Creating new SSE transport`, { sessionId, toolName, gmailHashID });
          transport = new StreamableHTTPServerTransport({
            sessionIdGenerator: () => sessionId || crypto.randomUUID()
          });
          
          if (sessionId) {
            transports[sessionId] = transport;
            
            // Cleanup on close
            transport.onclose = () => {
              delete transports[sessionId];
              logger.info(`🗑️ Cleaned up SSE session`, { sessionId });
            };
          }

          // Connect MCP server to this transport
          await server.connect(transport);
        }

        // Let the transport handle the request/response
        await transport.handleRequest(req, res, jsonRpcRequest);
        
        const duration = Date.now() - requestStart;
        logger.info(`✅ SSE request completed`, {
          toolName,
          gmailHashID,
          sessionId,
          duration: `${duration}ms`,
          clientIP
        });
        
      } else {
        logger.info(`📄 Using HTTP for ${toolName}`, { 
          toolName, 
          gmailHashID,
          clientIP,
        });
        
        // Handle as regular HTTP request
        if (jsonRpcRequest) {
          let result;
          
          if (jsonRpcRequest.method === 'initialize') {
            result = {
              protocolVersion: '2025-03-26',
              capabilities: {
                tools: {},
                notifications: {}
              },
              serverInfo: {
                name: 'gmail-multi-user',
                version: '2.0.0'
              }
            };
          } else if (jsonRpcRequest.method === 'tools/list') {
            const tools = [
              {
                name: "authenticate_user",
                description: "Authenticate a specific user for Gmail access",
                inputSchema: zodToJsonSchema(AuthenticateUserSchema),
              },
              {
                name: "send_email",
                description: "Sends a new email",
                inputSchema: zodToJsonSchema(SendEmailSchema),
              },
              {
                name: "draft_email",
                description: "Draft a new email",
                inputSchema: zodToJsonSchema(SendEmailSchema),
              },
              {
                name: "read_email",
                description: "Retrieves the content of a specific email",
                inputSchema: zodToJsonSchema(ReadEmailSchema),
              },
              {
                name: "search_emails",
                description: "Searches for emails using Gmail search syntax",
                inputSchema: zodToJsonSchema(SearchEmailsSchema),
              },
              {
                name: "modify_email",
                description: "Modifies email labels (move to different folders)",
                inputSchema: zodToJsonSchema(ModifyEmailSchema),
              },
              {
                name: "delete_email",
                description: "Permanently deletes an email",
                inputSchema: zodToJsonSchema(DeleteEmailSchema),
              },
              {
                name: "list_email_labels",
                description: "Retrieves all available Gmail labels",
                inputSchema: zodToJsonSchema(ListEmailLabelsSchema),
              },
              {
                name: "batch_modify_emails",
                description: "Modifies labels for multiple emails in batches",
                inputSchema: zodToJsonSchema(BatchModifyEmailsSchema),
              },
              {
                name: "batch_delete_emails",
                description: "Permanently deletes multiple emails in batches",
                inputSchema: zodToJsonSchema(BatchDeleteEmailsSchema),
              },
              {
                name: "create_label",
                description: "Creates a new Gmail label",
                inputSchema: zodToJsonSchema(CreateLabelSchema),
              },
              {
                name: "update_label",
                description: "Updates an existing Gmail label",
                inputSchema: zodToJsonSchema(UpdateLabelSchema),
              },
              {
                name: "delete_label",
                description: "Deletes a Gmail label",
                inputSchema: zodToJsonSchema(DeleteLabelSchema),
              },
              {
                name: "get_or_create_label",
                description: "Gets an existing label by name or creates it if it doesn't exist",
                inputSchema: zodToJsonSchema(GetOrCreateLabelSchema),
              },
              {
                name: "get_cache_stats",
                description: "Get cache statistics for monitoring",
                inputSchema: zodToJsonSchema(GetCacheStatsSchema),
              },
            ];
            result = { tools };
          } else if (jsonRpcRequest.method === 'tools/call') {
            // Call the tool handler directly
            const { name, arguments: args } = jsonRpcRequest.params;
            const userManager = UserManager.getInstance();
            
            try {
              // Handle authentication separately
              if (name === "authenticate_user") {
                const validatedArgs = AuthenticateUserSchema.parse(args);
                const { authUrl } = await userManager.generateAuthURL(validatedArgs.gmailHashID);
                
                result = {
                  content: [{
                    type: "text",
                    text: JSON.stringify({
                      message: "Please visit this URL to authenticate your Gmail account",
                      auth_url: authUrl,
                      status: "authentication_required"
                    }),
                  }],
                };
              } else if (name === "get_cache_stats") {
                const stats = userManager.getCacheStats();
                result = {
                  content: [{
                    type: "text",
                    text: `Cache Statistics:\nSize: ${stats.size}/${stats.maxSize}\nCalculated Size: ${stats.calculatedSize}`,
                  }],
                };
              } else {
                // Extract user context and get authenticated client
                const gmailHashID = extractUserContext(args);
                const client = await getAuthenticatedClient(gmailHashID);
                const gmail = client.gmailApi;
                
                // Call the appropriate tool handler
                result = await handleToolCall(name, args, gmail, gmailHashID);
              }
            } catch (error: any) {
              logger.error(`Tool call failed: ${name}`, { error: error.message, gmailHashID: args?.gmailHashID });
              result = {
                content: [{
                  type: "text",
                  text: `Error: ${error.message}`,
                }],
              };
            }
          } else {
            throw new Error(`Unknown method: ${jsonRpcRequest.method}`);
          }
          
          const duration = Date.now() - requestStart;
          logger.info(`✅ HTTP request completed`, {
            method: jsonRpcRequest.method,
            toolName,
            gmailHashID,
            duration: `${duration}ms`,
            clientIP,
          });
          
          // Return JSON-RPC response
          res.json({
            jsonrpc: '2.0',
            id: jsonRpcRequest.id,
            result: result
          });
        } else {
          // GET request - return server info
          res.json({
            server: 'gmail-multi-user-mcp',
            version: '2.0.0',
            transport: 'streamable-http',
            capabilities: ['tools'],
            endpoints: {
              mcp: '/mcp',
              health: '/health',
              checkGmailStatus: '/checkGmailStatus',
              initiateAuth: '/initiate-auth'
            }
          });
        }
      }

    } catch (error) {
      const duration = Date.now() - requestStart;
      logger.error('❌ HTTP MCP request error', { 
        error: error instanceof Error ? error.message : String(error), 
        toolName,
        gmailHashID,
        method: req.method,
        clientIP,
        duration: `${duration}ms`,
      });
      
      if (!res.headersSent) {
        res.status(500).json({
          jsonrpc: '2.0',
          id: jsonRpcRequest?.id,
          error: {
            code: -32000,
            message: error instanceof Error ? error.message : 'Internal server error',
            data: { toolName }
          }
        });
      }
    }
  });
  
  // Logout endpoint
  app.post('/logout', async (req, res) => {
    console.log(`📥 POST /logout request from ${req.ip || req.socket.remoteAddress}`);
    
    try {
      clearUserSessionCookies(res);
      return res.json({
        success: true,
        message: 'Logged out successfully'
      });
    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      return res.status(500).json({
        success: false,
        error: errorMessage
      });
    }
  });
  
  // Health check endpoint
  app.get('/health', async (req, res) => {
    console.log(`📥 GET /health request from ${req.ip || req.socket.remoteAddress}`);
    
    // Handle OAuth callback in health endpoint
    if (req.query.code && req.query.state) {
      console.log('🔍 OAuth callback detected in health endpoint');
      
      const code = req.query.code as string;
      const error = req.query.error as string;
      const state = req.query.state as string;

      if (error) {
        res.status(400).send(`<h1>❌ Authentication Error</h1><p>Error: ${error}</p>`);
        return;
      }

      try {
        const stateData = JSON.parse(state);
        const gmailHashID = stateData.userID;

        if (!gmailHashID) {
          res.status(400).send('<h1>❌ Authentication Failed</h1><p>Invalid state parameter</p>');
          return;
        }

        // Get OAuth client and exchange code for tokens
        const userManager = UserManager.getInstance();
        const oauth2Client = userManager.createOAuth2Client(gmailHashID, 4007);
        const { tokens } = await oauth2Client.getToken(code);
        
        // Save the credentials
        userManager.saveUserCredentials(gmailHashID, tokens);
        
        res.status(200).send(`
          <!DOCTYPE html>
          <html>
          <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Gmail Authentication Complete</title>
            <style>
              body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
              .success { color: green; }
            </style>
          </head>
          <body>
            <h1 class="success">✅ Authentication Successful!</h1>
            <p>Your Gmail account has been successfully connected.</p>
            <p>You can now close this window.</p>
          </body>
          </html>
        `);
        return;
        
      } catch (exchangeError) {
        logger.error(`OAuth token exchange failed:`, exchangeError);
        res.status(400).send(`<h1>❌ Authentication Failed</h1><p>Error: ${exchangeError instanceof Error ? exchangeError.message : 'Unknown error'}</p>`);
        return;
      }
    }
    
    const uptime = process.uptime();
    const memoryUsage = process.memoryUsage();
    const userManager = UserManager.getInstance();
    const cacheStats = userManager.getCacheStats();
    
    res.json({ 
      status: 'healthy', 
      server: 'gmail-multi-user-mcp',
      transport: 'streamable-http',
      version: '2.0.0',
      activeSessions: Object.keys(transports).length,
      uptime: `${Math.floor(uptime)}s`,
      memory: {
        used: Math.round(memoryUsage.heapUsed / 1024 / 1024) + 'MB',
        total: Math.round(memoryUsage.heapTotal / 1024 / 1024) + 'MB'
      },
      cache: cacheStats
    });
  });


  // Start HTTP server
  httpServer = app.listen(port, () => {
    logger.info(`🚀 HTTP MCP Server running on http://localhost:${port}`);
    logger.info(`📋 MCP Endpoint: http://localhost:${port}/mcp`);
    logger.info(`❤️ Health Check: http://localhost:${port}/health`);
    console.log(`🚀 HTTP MCP Server running on http://localhost:${port}`);
  });
}

// =================
// CLEANUP LOGIC
// =================

async function cleanup() {
  try {
    logger.info('Graceful shutdown initiated');
    
    // Stop HTTP server
    if (httpServer) {
      logger.info('Stopping HTTP server');
      await new Promise<void>((resolve, reject) => {
        httpServer.close((err: any) => {
          if (err) {
            logger.error('Error stopping HTTP server', { error: err.message });
            reject(err);
          } else {
            logger.info('HTTP server stopped successfully');
            resolve();
          }
        });
      });
    }
    
    process.exit(0);
  } catch (error: unknown) {
    logger.error('Cleanup error', { error });
    process.exit(1);
  }
}

/**
 * Main function
 */
async function main(transport: 'stdio' | 'http' | 'both' = 'stdio') {
  logger.info("Starting Multi-User Gmail MCP Server");
  logger.info(`Transport mode: ${transport}`);
  logger.info(`Current working directory: ${process.cwd()}`);
  logger.info(`Config directory: ${CONFIG_DIR}`);

  
  try {  
    await loadGlobalOAuthKeys();
  } catch (error) {
    logger.error("Failed to load global OAuth keys", { error });
    throw error;
  }

  const userManager = UserManager.getInstance();

  // Handle authentication mode
  if (process.argv[2] === 'auth') {
    const gmailHashID = process.argv[3];
    if (!gmailHashID) {
      console.error('Error: gmailHashID is required for authentication');
      console.log('Usage: npm run auth <gmailHashID>');
      process.exit(1);
    }

    logger.info(`Authentication mode detected for user: ${gmailHashID}`);
    try {
      await userManager.authenticateUser(gmailHashID);
      logger.info(`Authentication completed successfully for user: ${gmailHashID}`);
      console.log(`Authentication completed successfully for user: ${gmailHashID}`);
      process.exit(0);
    } catch (error) {
      logger.error(`Authentication failed for user ${gmailHashID}:`, error);
      console.error(`Authentication failed for user ${gmailHashID}:`, error);
      process.exit(1);
    }
  }

  // Set up MCP Handlers (shared by both transports)
  setupMCPHandlers();

  // Connect transport(s) based on parameter
  if (transport === 'stdio' || transport === 'both') {
    await setupStdioTransport();
  }
  
  if (transport === 'http' || transport === 'both') {
    const port = process.env.PORT ? parseInt(process.env.PORT, 10) : 4008;
    await setupHTTPTransport(port);
  }

  // Set up Graceful Shutdown
  logger.info('Setting up graceful shutdown handlers');
  process.on("SIGINT", cleanup);
  process.on("SIGTERM", cleanup);

  // Start periodic cleanup
  setInterval(() => {
    const stats = userManager.getCacheStats();
    logger.info("Cache stats", stats);
  }, CLEANUP_INTERVAL);

  // Add heartbeat
  setInterval(() => {
    logger.info("Server heartbeat - still running", { 
      cacheSize: clientCache.size,
      maxCache: clientCache.max
    });
  }, 30000);
}

// Parse command line arguments for transport type
const isDirectRun = import.meta.url.startsWith('file://') && process.argv[1] === fileURLToPath(import.meta.url);
if (isDirectRun) {
  // Parse transport argument
  const args = process.argv.slice(2);
  const transportArg = args.find(arg => arg.startsWith('--transport='));
  const transport = transportArg ? transportArg.split('=')[1] as 'stdio' | 'http' | 'both' : 'stdio';
  
  logger.info(`Starting with transport: ${transport}`);
  
  main(transport).catch((error) => {
    logger.error('Server error:', error);
    console.error('Server error:', error);
    process.exit(1);
  });
}

export { main, server };