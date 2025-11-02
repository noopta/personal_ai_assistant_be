import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { OAuth2Client } from "google-auth-library";
import { fileURLToPath } from "url";
import fs from 'fs/promises';
import crypto from 'crypto';
import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

// Import modular components
import { initializeOAuth2Client } from './auth/client.js';
import { AuthServer } from './auth/server.js';
import { TokenManager } from './auth/tokenManager.js';
import { CallbackDispatcher } from './auth/callbackDispatcher.js';
import { getToolDefinitions } from './handlers/listTools.js';
import { handleCallTool } from './handlers/callTool.js';
import { FileLogger } from "./auth/logger.js";
import { getSecureTokenPathWithCacheAndFuzzyMatching } from "./auth/utils.js";

// =================
// COMPLEXITY ANALYSIS CONFIGURATION
// =================

// Define which tools are simple, complex, or variable
const TOOL_COMPLEXITY = {
  // Simple operations - always HTTP (< 2 seconds)
  simple: [
    'auth_status',           // Token validation check
    'get_calendar_info',     // Calendar metadata
    'get_single_event',      // Single event lookup
    'get_calendar_list',     // List user's calendars
    'get_event_attendees'    // Single event attendees
  ],

  // Complex operations - always SSE (> 10 seconds)
  complex: [
    'sync_all_calendars',    // Multiple API calls, 30+ seconds
    'backup_calendar_data',  // Large data export, 15+ seconds  
    'import_calendar_file',  // File processing, variable time
    'generate_calendar_report', // Complex analysis, 20+ seconds
    'bulk_calendar_migration'   // Mass data movement
  ],
  
  // Variable operations - depends on parameters
  variable: [
    'list_events',           // Depends on date range & count
    'create_events',         // Depends on batch size
    'search_events',         // Depends on query complexity
    'update_events',         // Depends on number of updates
    'delete_events'          // Depends on batch size
  ]
};

class CalendarComplexityAnalyzer {
  
  analyzeListEvents(args: any): 'simple' | 'complex' {
    const maxResults = args?.maxResults || 10;
    const timeMin = args?.timeMin ? new Date(args.timeMin) : new Date();
    const timeMax = args?.timeMax ? new Date(args.timeMax) : new Date();
    const dayRange = Math.abs(timeMax.getTime() - timeMin.getTime()) / (1000 * 60 * 60 * 24);
    
    // Complexity thresholds based on realistic calendar usage
    if (maxResults > 100) return 'complex';           // 100+ events needs progress
    if (dayRange > 365) return 'complex';             // Full year query is slow
    if (args?.searchQuery?.length > 50) return 'complex';  // Complex search patterns
    if (args?.calendarIds?.length > 5) return 'complex';   // Multiple calendars
    
    return 'simple';
  }
  
  analyzeCreateEvents(args: any): 'simple' | 'complex' {
    const events = Array.isArray(args?.events) ? args.events : [args];
    const eventCount = events.length;
    
    // Batch size thresholds
    if (eventCount > 10) return 'complex';            // 10+ events needs progress
    if (events.some((e: any) => e.recurrence)) return 'complex';  // Recurring events are complex
    if (events.some((e: any) => e.attendees?.length > 10)) return 'complex';  // Many attendees
    if (events.some((e: any) => e.attachments?.length > 0)) return 'complex'; // File attachments
    
    return 'simple';
  }
  
  analyzeSearchEvents(args: any): 'simple' | 'complex' {
    const query = args?.query || '';
    const filters = args?.filters || {};
    const maxResults = args?.maxResults || 25;
    
    // Query complexity analysis
    if (query.includes('*') || query.includes('?')) return 'complex';  // Wildcard search
    if (query.length > 100) return 'complex';                         // Very long queries
    if (maxResults > 100) return 'complex';                           // Many results
    
    // Filter complexity
    const filterCount = Object.keys(filters).length;
    if (filterCount > 5) return 'complex';                            // Too many filters
    
    // Advanced filter types
    if (filters.dateRangeIntersection || filters.attendeeIntersection) return 'complex';
    if (filters.customFields || filters.metadata) return 'complex';
    
    return 'simple';
  }
  
  analyzeUpdateEvents(args: any): 'simple' | 'complex' {
    const eventIds = Array.isArray(args?.eventIds) ? args.eventIds : [args?.eventId].filter(Boolean);
    const updates = args?.updates || {};
    
    // Batch update size
    if (eventIds.length > 10) return 'complex';                       // Batch updates
    
    // Complex update operations
    if (updates.recurrence || updates.attendees?.length > 5) return 'complex';
    if (updates.moveToCalendar || updates.duplicateToCalendar) return 'complex';
    if (updates.attachments || updates.conferenceData) return 'complex';
    
    // Many field updates
    const updateFieldCount = Object.keys(updates).length;
    if (updateFieldCount > 5) return 'complex';
    
    return 'simple';
  }
  
  analyzeDeleteEvents(args: any): 'simple' | 'complex' {
    const eventIds = Array.isArray(args?.eventIds) ? args.eventIds : [args?.eventId].filter(Boolean);
    
    // Batch deletion threshold
    if (eventIds.length > 15) return 'complex';                       // Many deletions need progress
    if (args?.deleteRecurring === true) return 'complex';             // Recurring series deletion
    if (args?.notifyAttendees === true && eventIds.length > 5) return 'complex'; // Email notifications
    
    return 'simple';
  }
}

function shouldUseSSE(toolName: string, args: any, req?: express.Request): boolean {
  const analyzer = new CalendarComplexityAnalyzer();
  
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
      case 'list_events':
        complexity = analyzer.analyzeListEvents(args);
        break;
      case 'create_events':
        complexity = analyzer.analyzeCreateEvents(args);
        break;
      case 'search_events':
        complexity = analyzer.analyzeSearchEvents(args);
        break;
      case 'update_events':
        complexity = analyzer.analyzeUpdateEvents(args);
        break;
      case 'delete_events':
        complexity = analyzer.analyzeDeleteEvents(args);
        break;
      default:
        complexity = 'simple'; // Fallback for unknown variable tools
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
    name: "google-calendar",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

let oauth2Client: OAuth2Client;
let tokenManager: TokenManager;
let authServer: AuthServer;
let callbackDispatcher: CallbackDispatcher;
let httpServer: any = null;

// =================
// PROCESS CLEANUP UTILITIES
// =================

async function cleanupExistingProcesses(logger: FileLogger): Promise<void> {
  try {
    logger.info('🧹 Checking for existing MCP server processes...');
    
    const currentPid = process.pid;
    logger.debug(`Current process PID: ${currentPid}`);
    
    // Find existing Node.js processes running this server, excluding current process
    const { stdout } = await execAsync('ps aux | grep "node.*index.js.*transport=http" | grep -v grep || true');
    
    if (stdout.trim()) {
      const allProcesses = stdout.trim().split('\n');
      
      // Filter out current process and its parent npm process
      const processesToKill = allProcesses.filter(p => {
        const parts = p.trim().split(/\s+/);
        const pid = parts[1];
        return pid !== currentPid.toString();
      });
      
      if (processesToKill.length > 0) {
        logger.info(`Found ${processesToKill.length} existing server process(es) to clean up...`, {
          processes: processesToKill.map(p => {
            const parts = p.trim().split(/\s+/);
            return { pid: parts[1], command: parts.slice(10).join(' ') };
          })
        });
        
        // Kill specific PIDs instead of using pkill to avoid killing ourselves
        const pidsToKill = processesToKill.map(p => {
          const parts = p.trim().split(/\s+/);
          return parts[1];
        });
        
        for (const pid of pidsToKill) {
          try {
            await execAsync(`kill -TERM ${pid} || true`);
            logger.debug(`Sent TERM signal to process ${pid}`);
          } catch (killError) {
            logger.debug(`Could not kill process ${pid}:`, { error: killError });
          }
        }
        
        logger.info('✅ Successfully terminated existing server processes');
        
        // Wait a moment for cleanup
        await new Promise(resolve => setTimeout(resolve, 1000));
      } else {
        logger.info('✅ No existing server processes found (excluding current process)');
      }
    } else {
      logger.info('✅ No existing server processes found');
    }
  } catch (error) {
    logger.warn('⚠️ Error during process cleanup (continuing anyway)', { 
      error: error instanceof Error ? error.message : String(error) 
    });
  }
}

// =================
// MAIN APPLICATION LOGIC
// =================

async function main(
  testInput: string = "default", 
  userHashID: string = "defaultID",
  transport: 'stdio' | 'http' | 'both' = 'stdio'
) {
  const logger = new FileLogger('mcp-server.log', 'MAIN');
  
  try {
    // 0. Clean up any existing server processes first
    await cleanupExistingProcesses(logger);
    
    // 1. Initialize Authentication
    await logger.logServerStart({
      testInput,
      userHashID,
      serverName: 'google-calendar-mcp',
      version: '1.1.0',
      transport
    });

    logger.info(`Starting main application`, {
      testInput,
      userHashID,
      transport,
      workingDirectory: process.cwd(),
      environment: process.env.NODE_ENV || 'development'
    });
    
    logger.info('🔍 Comprehensive logging enabled for:', {
      components: [
        'HTTP requests and responses (all endpoints)',
        'Authentication flow (OAuth callbacks, token validation)',
        'Tool calls (validation, execution, results)',
        'Google API calls (requests, responses, errors)',
        'Error handling (with stack traces)',
        'Session management (SSE transport lifecycle)',
        'Server lifecycle (startup, shutdown)'
      ],
      logLevel: 'INFO, DEBUG, ERROR levels',
      logFile: 'mcp-server.log'
    });

    oauth2Client = await initializeOAuth2Client();
    logger.info('OAuth2 client initialized successfully');
    
    tokenManager = new TokenManager(oauth2Client);
    logger.info('Token manager initialized successfully');
    
    authServer = new AuthServer(oauth2Client);
    logger.info('Auth server initialized successfully');

    // Initialize and start callback dispatcher
    callbackDispatcher = new CallbackDispatcher();
    logger.info('Callback dispatcher initialized successfully');
    const dispatcherSuccess = await callbackDispatcher.start();
    if (!dispatcherSuccess) {
      logger.error('Callback dispatcher failed to start');
      process.exit(1);
    }
    logger.info('Callback dispatcher started successfully on port 3100');

    // 2. Start auth server if authentication is required 
    logger.info('Starting authentication server');
    const authSuccess = await authServer.start(false);
    if (!authSuccess) {
      logger.error('Authentication server failed to start');
      process.exit(1);
    }
    logger.info('Authentication server started successfully');

    // 3. Set up MCP Handlers (shared by both transports)
    setupMCPHandlers(logger);

    // 4. Connect transport(s) based on parameter
    if (transport === 'stdio' || transport === 'both') {
      await setupStdioTransport(logger);
    }
    
    if (transport === 'http' || transport === 'both') {
      await setupHTTPTransport(logger);
    }

    // 5. Set up Graceful Shutdown
    logger.info('Setting up graceful shutdown handlers');
    process.on("SIGINT", cleanup);
    process.on("SIGTERM", cleanup);

  } catch (error: unknown) {
    logger.logError(error as Error, 'Main Application', {
      testInput,
      userHashID,
      transport,
      stage: 'initialization'
    });
    process.exit(1);
  }
}

// =================
// MCP HANDLER SETUP (Shared by both transports)
// =================

function setupMCPHandlers(logger: FileLogger) {
  logger.info('Setting up MCP request handlers');
  
  // List Tools Handler
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    logger.request('ListTools request received');
    const toolDefinitions = getToolDefinitions();
    logger.response('ListTools response sent', { toolCount: toolDefinitions.tools.length });
    return toolDefinitions;
  });

  // Call Tool Handler - handles all inbound tool call requests
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const startTime = Date.now();
    const toolName = request.params.name;
    
    logger.request(`CallTool request received`, {
      toolName,
      paramsCount: Object.keys(request.params.arguments || {}).length
    });

    // Extract userHashID from request
    const requestParams = request.params.arguments;
    const userHashID = requestParams && typeof requestParams === 'object' && requestParams !== null 
      ? (requestParams as any).userHashID as string 
      : "empty";
    
    logger.info(`Processing request for user`, {
      userHashID,
      toolName,
      hasParams: !!requestParams
    });
    
    if (!userHashID || typeof userHashID !== 'string') {
      const errorMsg = "Invalid or missing userHashID parameter";
      logger.error(errorMsg, { providedUserHashID: userHashID, toolName });
      throw new Error(errorMsg);
    }

    // Get the refresh token path for this specific user (using cache first)
    const refreshTokenPath = await getSecureTokenPathWithCacheAndFuzzyMatching(userHashID);
    logger.debug(`Token path resolved`, { 
      userHashID, 
      tokenPath: refreshTokenPath 
    });

    try {
      // Read the user-specific refresh token
      const tokenFileContent = await fs.readFile(refreshTokenPath, 'utf8');
      const tokenFileJSON = JSON.parse(tokenFileContent);
      const refreshToken = tokenFileJSON.refresh_token;
      
      logger.debug(`Token file read successfully`, {
        userHashID,
        hasRefreshToken: !!refreshToken,
        tokenLength: refreshToken ? refreshToken.length : 0
      });

      // Create a new OAuth2Client instance for this specific request
      const userOAuth2Client = await initializeOAuth2Client();
      
      // Set the user-specific credentials on this client
      userOAuth2Client.setCredentials({
        refresh_token: refreshToken,
      });

      // Create a TokenManager for this specific user
      const userTokenManager = new TokenManager(userOAuth2Client, userHashID);
      
      // Validate tokens for this specific user
      logger.info(`Validating tokens for user: ${userHashID}`);
      if (!(await userTokenManager.validateTokensWithUserHash(userHashID))) {
        const errorMsg = "Authentication required. Please run 'npm run auth' to authenticate.";
        logger.logAuthAttempt(userHashID, false, { reason: 'Token validation failed' });
        throw new Error(errorMsg);
      }
      
      logger.logAuthAttempt(userHashID, true);
      
      // Pass the user-specific OAuth2Client to the handler
      const response = await handleCallTool(request, userOAuth2Client);
      
      const duration = Date.now() - startTime;
      logger.logToolCall(toolName, userHashID, requestParams, duration);
      logger.response(`CallTool response sent`, {
        toolName,
        userHashID,
        duration: `${duration}ms`,
        success: true
      });
      
      return response;
    } catch (error) {
      const duration = Date.now() - startTime;
      logger.logError(error as Error, 'CallTool Handler', {
        toolName,
        userHashID,
        duration: `${duration}ms`,
        requestParams
      });
      throw error;
    }
  });
}

// =================
// STDIO TRANSPORT SETUP (Original functionality)
// =================

async function setupStdioTransport(logger: FileLogger) {
  logger.info('Connecting to STDIO transport');
  const transport = new StdioServerTransport();
  await server.connect(transport);
  logger.info('STDIO MCP Server connected and ready to handle requests');
}

// =================
// HTTP TRANSPORT SETUP (New functionality)
// =================

import { createServer } from 'net';

async function findAvailablePort(startPort: number, logger: FileLogger): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    
    const tryPort = (port: number) => {
      server.listen(port, () => {
        const address = server.address();
        const foundPort = typeof address === 'object' && address ? address.port : port;
        server.close(() => resolve(foundPort));
      });
      
      server.on('error', (err: any) => {
        if (err.code === 'EADDRINUSE') {
          logger.debug(`Port ${port} is in use, trying ${port + 1}`);
          tryPort(port + 1);
        } else {
          reject(err);
        }
      });
    };
    
    tryPort(startPort);
  });
}

async function setupHTTPTransport(logger: FileLogger, port?: number) {
  // Use environment variable PORT, or find an available port starting from 4010
  const startPort = port || parseInt(process.env.PORT || '4010');
  const actualPort = await findAvailablePort(startPort, logger);
  
  logger.info(`Setting up HTTP transport on port ${actualPort}`);
  
  const app = express();
  
  // Add request logging middleware for all requests
  app.use((req, res, next) => {
    const startTime = Date.now();
    const clientIP = req.ip || req.socket.remoteAddress;
    const originalSend = res.send;
    
    // Log incoming request
    logger.debug(`📨 Incoming request`, {
      method: req.method,
      url: req.originalUrl,
      clientIP,
      userAgent: req.headers['user-agent'],
      contentType: req.headers['content-type'],
      timestamp: new Date().toISOString()
    });
    
    // Override res.send to log response
    res.send = function(body) {
      const duration = Date.now() - startTime;
      logger.debug(`📤 Outgoing response`, {
        method: req.method,
        url: req.originalUrl,
        statusCode: res.statusCode,
        clientIP,
        duration: `${duration}ms`,
        responseSize: typeof body === 'string' ? body.length : JSON.stringify(body).length
      });
      return originalSend.call(this, body);
    };
    
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
        userIdHash: req.body?.userHashID,
        gmailHashId: req.body?.gmailHashID
      };
    }
    
    return cookieAuth;
  }

  // Add this route to handle auth initiation
    // this is hit during the authentication flow in vapi 
    // so currently we are saving the tokens accordingly 
    // the next step is ensuring that during tool calls, we retrieve the correct tokens
  app.post('/initiate-auth', async (req, res) => {
    // Try cookies first, then fallback to request body or generate new
    const auth = getUserAuth(req);
    let userHashID = auth.userIdHash;
    let gmailHashID = auth.gmailHashId;
    
    // If no existing auth, generate new UUIDs
    if (!userHashID) {
      userHashID = crypto.randomUUID();
      gmailHashID = crypto.randomUUID();
      console.log(`Generated new userHashID: ${userHashID}`);
      console.log(`Generated new gmailHashID: ${gmailHashID}`);
    } else {
      console.log(`Using existing userHashID: ${userHashID}`);
    }
    
    try {
      const oauth2Client = await initializeOAuth2Client();
      const authServer = new AuthServer(oauth2Client, userHashID);
      
      const success = await authServer.start(true, userHashID);
      
      if (authServer.authCompletedSuccessfully) {
        setUserSessionCookies(res, userHashID, gmailHashID!);
        return res.json({ 
          status: 'already_authenticated',
          message: 'User already has valid tokens' 
        });
      }

      // issue could be happening anywhere above this line
      // actually it is because we are not logging in the successful if case
      console.log("checking auth server success", success);
      if (success) {
        const googleAuthUrl = authServer.getGeneratedAuthUrl();
        const port = authServer.getRunningPort();
        console.log("Google Auth URL:", googleAuthUrl);
        
        // Client should handle opening the browser to avoid VS Code prompts
        
        setUserSessionCookies(res, userHashID, gmailHashID!);
        return res.json({
          status: 'auth_required',
          authUrl: googleAuthUrl,
          callbackPort: port,
          message: 'Please visit the auth URL to authenticate'
        });
      } else {
        setUserSessionCookies(res, userHashID, gmailHashID!);
        return res.status(500).json({
          status: 'error',
          message: 'Failed to start authentication flow'
        });
      }
    } catch (error: unknown) {
      // Properly handle the unknown error type
      const errorMessage = error instanceof Error ? error.message : String(error);
      
      setUserSessionCookies(res, userHashID, gmailHashID!);
      return res.status(500).json({
        status: 'error', 
        message: errorMessage
      });
    }
  });

  // Calendar status check endpoint
  app.post('/checkCalendarStatus', async (req, res) => {
    // Read from cookies instead of request body
    const auth = getUserFromCookies(req);
    const userHashID = auth.userIdHash;
    const clientIP = req.ip || req.socket.remoteAddress;
    
    if (!userHashID) {
      return res.status(401).json({
        status: false,
        error: 'No session found. Please authenticate first.'
      });
    }
    
    logger.info(`📊 Calendar status check requested`, {
      userHashID,
      clientIP,
      timestamp: new Date().toISOString()
    });
    
    try {
      
      // Build token file path with cache lookup first, then fuzzy matching
      const tokenFilePath = await getSecureTokenPathWithCacheAndFuzzyMatching(userHashID);
      
      // Check if file exists
      try {
        const tokenFileContent = await fs.readFile(tokenFilePath, 'utf8');
        const tokenData = JSON.parse(tokenFileContent);
        
        logger.debug(`📄 Token file found and parsed`, {
          userHashID,
          hasExpiryDate: !!tokenData.expiry_date,
          clientIP
        });
        
        // Check if expiry_date exists and is valid
        if (!tokenData.expiry_date || typeof tokenData.expiry_date !== 'number') {
          logger.warn('⚠️ Token file missing or invalid expiry_date', {
            userHashID,
            hasExpiryDate: !!tokenData.expiry_date,
            expiryType: typeof tokenData.expiry_date,
            clientIP
          });
          return res.json({
            status: false,
            error: 'Token file missing expiry date'
          });
        }
        
        // Check if token is expired (compare with current time)
        const currentTime = Date.now();
        const isExpired = currentTime >= tokenData.expiry_date;
        
        logger.info(`🔍 Token expiration check completed`, {
          userHashID,
          currentTime,
          expiryDate: tokenData.expiry_date,
          isExpired,
          timeUntilExpiry: isExpired ? 'expired' : `${Math.floor((tokenData.expiry_date - currentTime) / 1000 / 60)}min`,
          clientIP
        });
        
        return res.json({
          status: !isExpired,
          expired: isExpired,
          expiryDate: new Date(tokenData.expiry_date).toISOString(),
          timeUntilExpiry: isExpired ? 0 : tokenData.expiry_date - currentTime
        });
        
      } catch (fileError) {
        // File doesn't exist or can't be read
        if ((fileError as any)?.code === 'ENOENT') {
          logger.info('📭 No token file found for user', {
            userHashID,
            tokenFilePath,
            clientIP
          });
          return res.json({
            status: false,
            error: 'No authentication tokens found'
          });
        } else {
          logger.error('❌ Error reading token file', {
            userHashID,
            error: (fileError as Error).message,
            clientIP
          });
          return res.json({
            status: false,
            error: 'Error reading token file'
          });
        }
      }
      
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      logger.error('❌ Calendar status check error', {
        userHashID,
        error: errorMessage,
        clientIP
      });
      
      return res.status(500).json({
        status: false,
        error: errorMessage
      });
    }
  });

  // Store active transports for session management
  const transports: Record<string, StreamableHTTPServerTransport> = {};
  
  // Main MCP endpoint - handles both GET and POST
  app.all('/mcp', async (req, res) => {
    const requestStart = Date.now();
    const clientIP = req.ip || req.socket.remoteAddress;
    const userAgent = req.headers['user-agent'];

    console.log(`Received ${req.method} request from ${clientIP} to ${req.originalUrl}`);
    
    const jsonRpcRequest = req.method === 'POST' ? req.body : null;
    const toolName = jsonRpcRequest?.params?.name;
    const args = jsonRpcRequest?.params?.arguments || {};
    const userHashID = args?.userHashID;
    console.log("userHashID", userHashID);
    
    logger.info(`🌐 Incoming HTTP request`, {
      method: req.method,
      url: req.originalUrl,
      clientIP,
      userAgent,
      toolName,
      userHashID,
      hasArgs: !!args,
      contentType: req.headers['content-type'],
      accept: req.headers.accept,
      sessionId: req.headers['mcp-session-id'],
      timestamp: new Date().toISOString()
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
          userHashID,
          clientIP,
          reason: 'Complex operation or client preference' 
        });
        
        // Get or create transport for this session
        let transport = sessionId ? transports[sessionId] : null;
        if (!transport) {
          logger.debug(`🔧 Creating new SSE transport`, { sessionId, toolName, userHashID });
          transport = new StreamableHTTPServerTransport({
            sessionIdGenerator: () => sessionId || crypto.randomUUID()
          });
          
          if (sessionId) {
            transports[sessionId] = transport;
            logger.debug(`📝 Registered SSE session`, { sessionId, activeTransports: Object.keys(transports).length });
            
            // Cleanup on close
            transport.onclose = () => {
              delete transports[sessionId];
              logger.info(`🗑️ Cleaned up SSE session`, { sessionId, remainingTransports: Object.keys(transports).length });
            };
          }

          // Connect MCP server to this transport
          logger.debug(`🔌 Connecting MCP server to SSE transport`, { sessionId });
          await server.connect(transport);
          logger.debug(`✅ MCP server connected to SSE transport`, { sessionId });
        } else {
          logger.debug(`♻️ Reusing existing SSE transport`, { sessionId, toolName });
        }

        // Let the transport handle the request/response
        logger.debug(`🚀 Delegating request to SSE transport`, { sessionId, toolName });
        await transport.handleRequest(req, res, jsonRpcRequest);
        
        const duration = Date.now() - requestStart;
        logger.info(`✅ SSE request completed`, {
          toolName,
          userHashID,
          sessionId,
          duration: `${duration}ms`,
          clientIP
        });
        
      } else {
        logger.info(`📄 Using HTTP for ${toolName}`, { 
          toolName, 
          userHashID,
          clientIP,
          reason: 'Simple operation' 
        });
        
        // Handle as regular HTTP request
        if (jsonRpcRequest) {
          let result;
          
          if (jsonRpcRequest.method === 'initialize') {
            logger.info(`🔧 Initialize request received`, { clientIP, userAgent });
            // Handle initialize request
            result = {
              protocolVersion: '2025-03-26',
              capabilities: {
                tools: {},
                notifications: {}
              },
              serverInfo: {
                name: 'google-calendar',
                version: '1.0.0'
              }
            };
            logger.debug(`✅ Initialize response prepared`);
          } else if (jsonRpcRequest.method === 'tools/list') {
            logger.info(`📋 Tools list request received`, { clientIP });
            // Handle tools/list request
            result = getToolDefinitions();
            logger.debug(`✅ Tools list response prepared`, { toolCount: result.tools.length });
          } else if (jsonRpcRequest.method === 'tools/call') {
            logger.info(`🔧 Tool call request received`, { toolName, userHashID, clientIP });
            // Handle tools/call request with existing auth logic
            if (!userHashID) {
              logger.error(`❌ Missing userHashID parameter`, { toolName, clientIP });
              throw new Error('Missing userHashID parameter');
            }
            

            // TODO: i think an important thing to integrate is we can just use 
            // vapi as the mcp client instead of using mcp-use for text based conversations 
            logger.debug(`🔑 Loading tokens for user`, { userHashID });
            // Reuse existing token loading and validation logic
            // pretty relevant to double check 
            const refreshTokenPath = await getSecureTokenPathWithCacheAndFuzzyMatching(userHashID);
            const tokenFileContent = await fs.readFile(refreshTokenPath, 'utf8');
            const tokenFileJSON = JSON.parse(tokenFileContent);
            const refreshToken = tokenFileJSON.refresh_token;
            logger.debug(`✅ Tokens loaded successfully`, { userHashID, hasRefreshToken: !!refreshToken });
            
            const userOAuth2Client = await initializeOAuth2Client();
            userOAuth2Client.setCredentials({ refresh_token: refreshToken });
            
            logger.debug(`🔍 Validating tokens for user`, { userHashID });
            const userTokenManager = new TokenManager(userOAuth2Client, userHashID);
            if (!(await userTokenManager.validateTokensWithUserHash(userHashID))) {
              logger.error(`❌ Token validation failed`, { userHashID, toolName, clientIP });
              throw new Error('Authentication required');
            }
            logger.debug(`✅ Tokens validated successfully`, { userHashID });
            
            logger.debug(`🚀 Executing tool call`, { toolName, userHashID });
            result = await handleCallTool(jsonRpcRequest, userOAuth2Client);
            logger.debug(`✅ Tool call completed`, { toolName, userHashID });
          } else {
            logger.error(`❌ Unknown method`, { method: jsonRpcRequest.method, clientIP });
            throw new Error(`Unknown method: ${jsonRpcRequest.method}`);
          }
          
          const duration = Date.now() - requestStart;
          logger.info(`✅ HTTP request completed`, {
            method: jsonRpcRequest.method,
            toolName,
            userHashID,
            duration: `${duration}ms`,
            clientIP,
            responseSize: JSON.stringify(result).length
          });
          
          // Return JSON-RPC response
          res.json({
            jsonrpc: '2.0',
            id: jsonRpcRequest.id,
            result: result
          });
        } else {
          // GET request - return server info
          const duration = Date.now() - requestStart;
          logger.info(`📊 Server info request`, { 
            clientIP, 
            userAgent,
            duration: `${duration}ms`
          });
          
          res.json({
            server: 'google-calendar-mcp',
            version: '1.0.0',
            transport: 'streamable-http',
            capabilities: ['tools'],
            endpoints: {
              mcp: '/mcp',
              health: '/health'
            }
          });
        }
      }

    } catch (error) {
      const duration = Date.now() - requestStart;
      logger.error('❌ HTTP MCP request error', { 
        error: error instanceof Error ? error.message : String(error), 
        stack: error instanceof Error ? error.stack : undefined,
        toolName,
        userHashID,
        method: req.method,
        clientIP,
        duration: `${duration}ms`,
        url: req.originalUrl
      });
      
      if (!res.headersSent) {
        res.status(500).json({
          jsonrpc: '2.0',
          id: jsonRpcRequest?.id,
          error: {
            code: -32000,
            message: error instanceof Error ? error.message : 'Internal server error',
            data: { toolName, timestamp: new Date().toISOString() }
          }
        });
      }
    }
  });
  
  // Logout endpoint
  app.post('/logout', async (req, res) => {
    const clientIP = req.ip || req.socket.remoteAddress;
    logger.info(`📥 POST /logout request from ${clientIP}`);
    
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
  app.get('/health', (req, res) => {
    const clientIP = req.ip || req.socket.remoteAddress;
    const uptime = process.uptime();
    const memoryUsage = process.memoryUsage();
    
    logger.debug(`❤️ Health check request`, { 
      clientIP, 
      userAgent: req.headers['user-agent'],
      activeSessions: Object.keys(transports).length,
      uptime: `${Math.floor(uptime)}s`
    });
    
    res.json({ 
      status: 'healthy', 
      server: 'google-calendar-mcp',
      transport: 'streamable-http',
      version: '1.0.0',
      timestamp: new Date().toISOString(),
      activeSessions: Object.keys(transports).length,
      uptime: `${Math.floor(uptime)}s`,
      memory: {
        used: Math.round(memoryUsage.heapUsed / 1024 / 1024) + 'MB',
        total: Math.round(memoryUsage.heapTotal / 1024 / 1024) + 'MB'
      }
    });
  });

  // Start HTTP server
  httpServer = app.listen(actualPort, () => {
    logger.info(`🚀 HTTP MCP Server running on http://localhost:${actualPort}`);
    logger.info(`📋 MCP Endpoint: http://localhost:${actualPort}/mcp`);
    logger.info(`❤️ Health Check: http://localhost:${actualPort}/health`);
    console.log(`🚀 HTTP MCP Server running on http://localhost:${actualPort}`);
    console.log(`📋 MCP Endpoint: http://localhost:${actualPort}/mcp`);
    console.log(`❤️ Health Check: http://localhost:${actualPort}/health`);
  });
}

// =================
// CLEANUP LOGIC
// =================

async function cleanup() {
  const logger = new FileLogger('mcp-server.log', 'CLEANUP');
  
  try {
    logger.info('Graceful shutdown initiated');
    
    // Stop callback dispatcher
    if (callbackDispatcher) {
      logger.info('Stopping callback dispatcher');
      await callbackDispatcher.stop();
      logger.info('Callback dispatcher stopped successfully');
    }

    // Stop auth server
    if (authServer) {
      logger.info('Stopping auth server');
      await authServer.stop();
      logger.info('Auth server stopped successfully');
    }
    
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
    
    await logger.logServerStop();
    process.exit(0);
  } catch (error: unknown) {
    logger.logError(error as Error, 'Cleanup Process');
    process.exit(1);
  }
}

// =================
// EXPORTS & EXECUTION GUARD
// =================

export { main, server };

// Parse command line arguments for transport type
const isDirectRun = import.meta.url.startsWith('file://') && process.argv[1] === fileURLToPath(import.meta.url);
if (isDirectRun) {
  const logger = new FileLogger('mcp-server.log', 'STARTUP');
  
  // Parse transport argument
  const args = process.argv.slice(2);
  const transportArg = args.find(arg => arg.startsWith('--transport='));
  const transport = transportArg ? transportArg.split('=')[1] as 'stdio' | 'http' | 'both' : 'stdio';
  
  logger.info(`Starting with transport: ${transport}`);
  
  main("default", "defaultID", transport).catch((error) => {
    logger.logError(error as Error, 'Direct Execution');
    process.exit(1);
  });
}