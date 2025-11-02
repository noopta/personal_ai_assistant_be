import express from 'express';
import http from 'http';
import { FileLogger } from './logger.js';

interface AuthServerInfo {
  userID: string;
  port: number;
  timestamp: number;
}

export class CallbackDispatcher {
  private app: express.Express;
  private server: http.Server | null = null;
  private activeServers: Map<string, AuthServerInfo> = new Map();
  private logger: FileLogger;
  private port: number = 3111;

  constructor() {
    this.app = express();
    this.logger = new FileLogger('callback-dispatcher.log', 'DISPATCHER');
    this.setupRoutes();
  }

  private setupRoutes(): void {
    this.app.use(express.json());
    
    // OAuth callback handler
    this.app.get('/oauth2callback', async (req, res) => {
      const clientIP = req.ip || req.socket.remoteAddress;
      const state = req.query.state as string;
      const code = req.query.code as string;
      const error = req.query.error as string;
      
      this.logger.info('OAuth callback received', {
        hasCode: !!code,
        hasState: !!state,
        hasError: !!error,
        clientIP
      });

      if (!state) {
        this.logger.error('Missing state parameter in OAuth callback');
        res.status(400).send('Missing state parameter');
        return;
      }

      let userID: string;
      try {
        const stateData = JSON.parse(state);
        userID = stateData.userID;
      } catch (error) {
        this.logger.error('Failed to parse state parameter', { state, error });
        res.status(400).send('Invalid state parameter');
        return;
      }

      // Find the auth server for this user
      const authServer = this.activeServers.get(userID);
      if (!authServer) {
        this.logger.error('No active auth server found for user', { userID });
        res.status(404).send(`No active authentication session found for user: ${userID}`);
        return;
      }

      try {
        // Forward the request to the correct auth server
        const forwardUrl = `http://localhost:${authServer.port}/oauth2callback${req.url.substring(req.url.indexOf('?'))}`;
        this.logger.info('Forwarding OAuth callback to auth server', {
          userID,
          targetPort: authServer.port,
          forwardUrl
        });

        const fetch = (await import('node-fetch')).default;
        const response = await fetch(forwardUrl, {
          method: 'GET',
          headers: {
            'X-Forwarded-For': clientIP || '',
            'X-Original-Host': req.headers.host || '',
            'User-Agent': req.headers['user-agent'] || ''
          }
        });

        if (response.ok) {
          const content = await response.text();
          res.status(response.status).send(content);
          
          // Remove the server from active list after successful auth
          this.activeServers.delete(userID);
          this.logger.info('Auth completed, removed server from active list', { userID });
        } else {
          this.logger.error('Auth server returned error', { 
            userID, 
            status: response.status,
            statusText: response.statusText
          });
          res.status(response.status).send(`Authentication failed: ${response.statusText}`);
        }
      } catch (error) {
        this.logger.error('Failed to forward OAuth callback', { 
          userID, 
          targetPort: authServer.port,
          error: error instanceof Error ? error.message : String(error)
        });
        res.status(500).send('Internal server error during authentication');
      }
    });

    // Registration endpoint for auth servers
    this.app.post('/register-auth-server', (req, res) => {
      const { userID, port } = req.body;
      
      if (!userID || !port) {
        res.status(400).json({ error: 'Missing userID or port' });
        return;
      }

      const authServerInfo: AuthServerInfo = {
        userID,
        port,
        timestamp: Date.now()
      };

      this.activeServers.set(userID, authServerInfo);
      this.logger.info('Registered auth server', authServerInfo);
      
      res.json({ success: true, userID, port });
    });

    // Unregistration endpoint for auth servers
    this.app.post('/unregister-auth-server', (req, res) => {
      const { userID } = req.body;
      
      if (!userID) {
        res.status(400).json({ error: 'Missing userID' });
        return;
      }

      const removed = this.activeServers.delete(userID);
      this.logger.info('Unregistered auth server', { userID, existed: removed });
      
      res.json({ success: true, userID, removed });
    });

    // Status endpoint
    this.app.get('/status', (req, res) => {
      const activeCount = this.activeServers.size;
      const servers = Array.from(this.activeServers.entries()).map(([userID, info]) => ({
        userID,
        port: info.port,
        age: Date.now() - info.timestamp
      }));

      res.json({
        status: 'running',
        activeServers: activeCount,
        servers
      });
    });

    // Health check
    this.app.get('/health', (req, res) => {
      res.json({ status: 'healthy', timestamp: new Date().toISOString() });
    });

    // Cleanup old entries periodically
    setInterval(() => {
      const now = Date.now();
      const maxAge = 30 * 60 * 1000; // 30 minutes
      
      for (const [userID, info] of this.activeServers.entries()) {
        if (now - info.timestamp > maxAge) {
          this.activeServers.delete(userID);
          this.logger.info('Cleaned up stale auth server entry', { userID, age: now - info.timestamp });
        }
      }
    }, 60000); // Check every minute
  }

  async start(): Promise<boolean> {
    return new Promise((resolve, reject) => {
      this.server = this.app.listen(this.port, () => {
        this.logger.info(`OAuth callback dispatcher started on port ${this.port}`);
        resolve(true);
      });

      this.server.on('error', (err: NodeJS.ErrnoException) => {
        this.logger.error('Failed to start dispatcher', { error: err.message, code: err.code });
        reject(err);
      });
    });
  }

  async stop(): Promise<void> {
    return new Promise((resolve, reject) => {
      if (this.server) {
        this.server.close((err) => {
          if (err) {
            this.logger.error('Error stopping dispatcher', { error: err.message });
            reject(err);
          } else {
            this.logger.info('Dispatcher stopped successfully');
            this.server = null;
            resolve();
          }
        });
      } else {
        resolve();
      }
    });
  }
}