import express from 'express';
import { OAuth2Client } from 'google-auth-library';
import { TokenManager } from './tokenManager.js';
import http from 'http';
import { loadCredentials } from './client.js';
import { FileLogger } from './logger.js';

export class AuthServer {
  private baseOAuth2Client: OAuth2Client; // Used by TokenManager for validation/refresh
  private flowOAuth2Client: OAuth2Client | null = null; // Used specifically for the auth code flow
  private app: express.Express;
  private server: http.Server | null = null;
  private tokenManager: TokenManager;
  private portRange: { start: number; end: number };
  private userID: string; // Store userID
  private logger: FileLogger;
  public authCompletedSuccessfully = false; // Flag for standalone script
  private generatedAuthUrl: string | null = null; // Store the Google auth URL
  private timeoutHandle: NodeJS.Timeout | null = null; // Auto-cleanup timeout

  constructor(oauth2Client: OAuth2Client, userID: string | null = null) {
    this.baseOAuth2Client = oauth2Client;
    this.userID = userID || "abc123456"; // Store the userID
    this.tokenManager = new TokenManager(oauth2Client, userID || undefined);
    this.app = express();
    this.portRange = { start: 3101, end: 3110 }; // Use ports 3101-3110 for auth servers (multiple concurrent users)
    this.logger = new FileLogger('mcp-server.log', 'AUTH-SERVER');
    this.setupRoutes();
    
    // Log constructor
    this.logger.info(`AuthServer initialized`, {
      userID: userID || "default",
      portRange: this.portRange,
      hasOAuth2Client: !!oauth2Client
    });

    console.log("AuthServer initialized with userID:", this.userID);
  }

  private setupRoutes(): void {
  
    this.logger.debug('Setting up Express routes');
    console.log("Setting up Express routes for userID:", this.userID);
    
    this.app.get('/', (req, res) => {
      const clientIP = req.ip || req.socket.remoteAddress;
      const userAgent = req.headers['user-agent'];
      this.logger.info('🏠 GET / - Auth landing page requested', { 
        clientIP, 
        userAgent,
        userID: this.userID 
      });
      
      // Generate the URL using the active flow client if available, else base
      const clientForUrl = this.flowOAuth2Client || this.baseOAuth2Client;
      const scopes = ['https://www.googleapis.com/auth/calendar'];
      
      // Add state parameter with userID
      const state = JSON.stringify({ userID: this.userID });
      
      const authUrl = clientForUrl.generateAuthUrl({
        access_type: 'offline',
        scope: scopes,
        prompt: 'consent',
        state: state
      });
      
      this.logger.debug(`Generated auth URL with state: ${state}`);
      res.send(`<h1>Google Calendar Authentication</h1><a href="${authUrl}">Authenticate with Google</a>`);
    });

    this.app.get('/oauth2callback', async (req, res) => {
      const clientIP = req.ip || req.socket.remoteAddress;
      const userAgent = req.headers['user-agent'];
      const code = req.query.code as string;
      const state = req.query.state as string;

      console.log("OAuth2 callback received with userID:", this.userID);
      const error = req.query.error as string;
      
      this.logger.info(`🔄 GET /oauth2callback - OAuth callback received`, {
        clientIP,
        userAgent,
        hasCode: !!code,
        hasState: !!state,
        error: error || undefined,
        timestamp: new Date().toISOString()
      });
      
      if (!code) {
        this.logger.error('❌ OAuth2 callback missing authorization code', { 
          clientIP,
          error,
          query: req.query 
        });
        res.status(400).send('Authorization code missing');
        return;
      }
      
      if (error) {
        this.logger.error('❌ OAuth2 authorization error', { 
          clientIP,
          error,
          errorDescription: req.query.error_description 
        });
        res.status(400).send(`Authentication error: ${error}`);
        return;
      }
      
      // Extract userID from state
      let userID: string;
      try {
        const stateData = JSON.parse(state);
        userID = stateData.userID;
        console.log("Parsed userID from state:", userID);
        this.logger.debug(`Parsed userID from state: ${userID}`);
      } catch (error) {
        this.logger.error(`Failed to parse state parameter: ${error}`);
        userID = this.userID; // Fallback to instance userID
        this.logger.debug(`Using fallback userID: ${userID}`);
      }
      
      if (!this.flowOAuth2Client) {
        this.logger.error('Authentication flow not properly initiated - flowOAuth2Client is null');
        res.status(500).send('Authentication flow not properly initiated.');
        return;
      }
      
      try {
        console.log("Exchanging code for tokens for userID:", userID);
        this.logger.info(`🔑 Exchanging authorization code for tokens`, { 
          userID,
          clientIP,
          codeLength: code.length 
        });
        
        const tokenStart = Date.now();
        const { tokens } = await this.flowOAuth2Client.getToken(code);
        const tokenDuration = Date.now() - tokenStart;
        
        this.logger.debug(`✅ Tokens received from Google`, {
          userID,
          hasAccessToken: !!tokens.access_token,
          hasRefreshToken: !!tokens.refresh_token,
          tokenDuration: `${tokenDuration}ms`,
          expiresIn: tokens.expiry_date ? new Date(tokens.expiry_date).toISOString() : undefined
        });
        
        await this.tokenManager.saveTokens(tokens, userID);
        this.authCompletedSuccessfully = true;

        this.logger.info(`🎉 User "${userID}" authenticated successfully`, {
          clientIP,
          tokenDuration: `${tokenDuration}ms`,
          timestamp: new Date().toISOString()
        });
        console.log(`🎉 User "${userID}" authenticated successfully at ${new Date().toISOString()}`);

        // Get the path where tokens were saved
        const tokenPath = this.tokenManager.getTokenPath();
        this.logger.debug(`Tokens saved to: ${tokenPath}`);

        // Send an aesthetic and fun success page
        res.send(`
          <!DOCTYPE html>
          <html lang="en">
          <head>
              <meta charset="UTF-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <title>Google Calendar Authentication Complete</title>
              <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
              <style>
                  :root {
                      --primary-gradient: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                      --calendar-primary: #1a73e8;
                      --calendar-secondary: #4285f4;
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

                  .calendar-logo {
                      display: inline-flex;
                      align-items: center;
                      gap: 8px;
                      margin-bottom: 24px;
                      padding: 12px 20px;
                      background: var(--bg-secondary);
                      border-radius: 12px;
                      border: 1px solid var(--border-color);
                  }

                  .calendar-icon {
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

                  // Log when user closes/navigates away from this page
                  window.addEventListener('beforeunload', () => {
                      navigator.sendBeacon('/auth-complete', JSON.stringify({
                          userID: '${userID}',
                          timestamp: new Date().toISOString(),
                          action: 'browser_close'
                      }));
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

                  <h1>Calendar Connected Successfully</h1>
                  <p class="subtitle">Your Google Calendar has been securely authenticated and connected to the MCP server.</p>

                  <div class="calendar-logo">
                      <svg class="calendar-icon" viewBox="0 0 24 24" fill="none">
                          <path d="M19 3h-1V1h-2v2H8V1H6v2H5c-1.11 0-1.99.9-1.99 2L3 19c0 1.1.89 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm0 16H5V8h14v11zM7 10h5v5H7z" fill="#1a73e8"/>
                      </svg>
                      <span class="service-name">Google Calendar MCP</span>
                  </div>
                  
                  <div class="user-info">
                      <div class="user-label">Authenticated Session ID</div>
                      <div class="user-id">${userID}</div>
                  </div>
                  
                  <div class="actions">
                      <button class="btn btn-primary" onclick="window.close()">
                          Continue & Close Window
                      </button>
                  </div>
                  
                  <p class="footer-text">
                      This window will automatically close in <span id="countdown">5</span> seconds.<br>
                      Your Google Calendar integration is now ready for use.
                  </p>
              </div>
          </body>
          </html>
        `);
        
        // Auto-stop the server after successful authentication
        setTimeout(async () => {
          this.logger.info('Auto-stopping auth server after successful authentication');
          await this.stop();
        }, 6000); // Wait 6 seconds for user to see success page
        
      } catch (error: unknown) {
        this.authCompletedSuccessfully = false;
        const message = error instanceof Error ? error.message : 'Unknown error';
        
        this.logger.error(`❌ User "${userID}" authentication failed`, {
          error: message,
          stack: error instanceof Error ? error.stack : undefined,
          userID,
          clientIP,
          codeLength: code ? code.length : 0,
          timestamp: new Date().toISOString()
        });
        console.error(`❌ User "${userID}" authentication failed: ${message}`);
        
        // Send an HTML error response
        res.status(500).send(`
          <!DOCTYPE html>
          <html lang="en">
          <head>
              <meta charset="UTF-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <title>Authentication Failed</title>
              <style>
                  body { font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background-color: #f4f4f4; margin: 0; }
                  .container { text-align: center; padding: 2em; background-color: #fff; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
                  h1 { color: #F44336; }
                  p { color: #333; }
              </style>
          </head>
          <body>
              <div class="container">
                  <h1>Authentication Failed</h1>
                  <p>An error occurred during authentication:</p>
                  <p><code>${message}</code></p>
                  <p>Please try again or check the server logs.</p>
              </div>
          </body>
          </html>
        `);
        
        // Auto-stop the server after authentication failure
        setTimeout(async () => {
          this.logger.info('Auto-stopping auth server after authentication failure');
          await this.stop();
        }, 10000); // Wait 10 seconds for user to see error page
      }
    });

    // Optional: Add endpoint to capture browser close events
    this.app.post('/auth-complete', express.json(), (req, res) => {
      const clientIP = req.ip || req.socket.remoteAddress;
      const { userID, timestamp, action } = req.body;
      this.logger.info(`📱 Browser event from user`, {
        userID: userID || 'unknown',
        action: action || 'unknown',
        timestamp,
        clientIP,
        userAgent: req.headers['user-agent']
      });
      res.status(200).send('OK');
    });
    
    this.logger.debug('Express routes setup completed');
  }

  async start(openBrowser = true, userHashID: string = "default"): Promise<boolean> {
    this.logger.info(`Starting AuthServer - openBrowser: ${openBrowser}`);
    console.log("AuthServer start called with userID:", this.userID);
    
    // if (await this.tokenManager.validateTokens()) {
    //   this.logger.info('Valid tokens found, authentication already completed');
    //   this.authCompletedSuccessfully = true;
    //   return true;
    // }

    //  We need to eventually pass in the actual userIDHash
    // if (await this.tokenManager.validateTokensWithUserHash("h2ug0lc5olg38hykyrsim5")) {
    if (await this.tokenManager.validateTokensWithUserHash(userHashID)) {
      this.logger.info('Valid tokens found, authentication already completed');
      this.authCompletedSuccessfully = true;
      console.log("Valid tokens found for userID:", this.userID);
      return true;
    }
    
    this.logger.debug('No valid tokens found, starting auth flow');
    console.log("No valid tokens found, starting auth flow for userID:", this.userID);
    
    // Try to start the server and get the port
    const port = await this.startServerOnAvailablePort();
    if (port === null) {
      console.log('Failed to start server - no available ports');
      this.logger.error('Failed to start server - no available ports');
      this.authCompletedSuccessfully = false;
      return false;
    }

    this.logger.info(`Server started successfully on port ${port}`);

    // Register with the callback dispatcher
    await this.registerWithDispatcher(port);

    // Set up auto-cleanup timeout (5 minutes max)
    this.timeoutHandle = setTimeout(async () => {
      this.logger.warn('Auth server timeout reached - auto-stopping to prevent port leak');
      await this.stop();
    }, 5 * 60 * 1000); // 5 minutes

    // Successfully started server on `port`. Now create the flow-specific OAuth client.
    try {
      this.logger.debug('Loading OAuth credentials');
      const { client_id, client_secret } = await loadCredentials();
      // this.flowOAuth2Client = new OAuth2Client(
      //   client_id,
      //   client_secret,
      //   `http://localhost:${port}/oauth2callback`
      // );
      // with our new domain 
      this.flowOAuth2Client = new OAuth2Client({
        clientId: client_id,
        clientSecret: client_secret,
        redirectUri: `https://luciuslab.xyz:3005/oauth2callback`
      });
      console.log("OAuth2 Client created with redirect URI:", `https://luciuslab.xyz:3005/oauth2callback`);
      this.logger.debug(`OAuth2 client created with redirect URI: https://luciuslab.xyz:3005/oauth2callback`);
    } catch (error) {
        console.log('Failed to load OAuth credentials:', error);
        this.logger.error(`Failed to load credentials: ${error}`);
        this.authCompletedSuccessfully = false;
        await this.stop(); // Stop the server we just started
        return false;
    }

    if (openBrowser) {
      console.log("Generating auth URL for client-side browser opening");
      this.logger.info('Generating auth URL for client-side browser opening');
      // Generate Auth URL using the newly created flow client with state parameter
      const state = JSON.stringify({ userID: this.userID });
      
      const authorizeUrl = this.flowOAuth2Client.generateAuthUrl({
        access_type: 'offline',
        scope: ['https://www.googleapis.com/auth/calendar'],
        prompt: 'consent',
        state: state
      });

      console.log("Generated Auth URL:", authorizeUrl);
      this.logger.debug(`Generated auth URL for client: ${authorizeUrl}`);
      // Store the URL for client access
      this.generatedAuthUrl = authorizeUrl;
      // Don't open browser server-side to avoid VS Code prompts
    }

    this.logger.info('Auth flow initiated successfully');
    return true; // Auth flow initiated
  }

  public getGeneratedAuthUrl(): string | null {
    return this.generatedAuthUrl;
  }

  private async startServerOnAvailablePort(): Promise<number | null> {
    console.log("Starting server on available port...");
    this.logger.debug(`Attempting to start server on port range: ${this.portRange.start}-${this.portRange.end}`);
    
    for (let port = this.portRange.start; port <= this.portRange.end; port++) {
      try {
        this.logger.debug(`Trying port ${port}`);
        await new Promise<void>((resolve, reject) => {
          const testServer = this.app.listen(port, () => {
            this.server = testServer; // Assign to class property *only* if successful
            resolve();
          });
          testServer.on('error', (err: NodeJS.ErrnoException) => {
            if (err.code === 'EADDRINUSE') {
              this.logger.debug(`Port ${port} is in use`);
              testServer.close(() => reject(err)); 
            } else {
              this.logger.error(`Server error on port ${port}: ${err.message}`);
              reject(err);
            }
          });
        });
        this.logger.info(`Successfully bound to port ${port}`);
        return port; // Port successfully bound
      } catch (error: unknown) {
        if (!(error instanceof Error && 'code' in error && error.code === 'EADDRINUSE')) {
            this.logger.error(`Unexpected error starting server on port ${port}: ${error}`);
            return null;
        }
        // EADDRINUSE occurred, loop continues
      }
    }
    this.logger.error('No available ports found in range');
    return null; // No port found
  }

  public getRunningPort(): number | null {
    if (this.server) {
      const address = this.server.address();
      if (typeof address === 'object' && address !== null) {
        const port = address.port;
        this.logger.debug(`Retrieved running port: ${port}`);
        return port;
      }
    }
    this.logger.debug('No running server found');
    return null;
  }

  private async registerWithDispatcher(port: number): Promise<void> {
    try {
      const fetch = (await import('node-fetch')).default;
      const response = await fetch('http://localhost:3111/register-auth-server', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userID: this.userID, port })
      });

      if (response.ok) {
        this.logger.info('Successfully registered with callback dispatcher', { userID: this.userID, port });
      } else {
        this.logger.warn('Failed to register with callback dispatcher', { 
          userID: this.userID, 
          port, 
          status: response.status 
        });
      }
    } catch (error) {
      this.logger.warn('Could not reach callback dispatcher', { 
        userID: this.userID, 
        port,
        error: error instanceof Error ? error.message : String(error)
      });
    }
  }

  private async unregisterWithDispatcher(): Promise<void> {
    try {
      const fetch = (await import('node-fetch')).default;
      const response = await fetch('http://localhost:3111/unregister-auth-server', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userID: this.userID })
      });

      if (response.ok) {
        this.logger.info('Successfully unregistered from callback dispatcher', { userID: this.userID });
      } else {
        this.logger.warn('Failed to unregister from callback dispatcher', { 
          userID: this.userID, 
          status: response.status 
        });
      }
    } catch (error) {
      this.logger.warn('Could not reach callback dispatcher for unregistration', { 
        userID: this.userID,
        error: error instanceof Error ? error.message : String(error)
      });
    }
  }

  async stop(): Promise<void> {
    this.logger.info('Stopping AuthServer');
    
    // Unregister from dispatcher first
    await this.unregisterWithDispatcher();
    
    // Clear the timeout to prevent auto-cleanup
    if (this.timeoutHandle) {
      clearTimeout(this.timeoutHandle);
      this.timeoutHandle = null;
    }
    
    return new Promise((resolve, reject) => {
      if (this.server) {
        this.server.close((err) => {
          if (err) {
            this.logger.error(`Error stopping server: ${err.message}`);
            reject(err);
          } else {
            this.logger.info('Server stopped successfully');
            this.server = null;
            resolve();
          }
        });
      } else {
        this.logger.debug('No server to stop');
        resolve();
      }
    });
  }
}