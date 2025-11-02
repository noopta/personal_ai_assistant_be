import { OAuth2Client, Credentials } from 'google-auth-library';
import * as fs from 'fs/promises';
import * as path from 'path';
import { getSecureTokenPath, getSecureTokenPathWithUserHash, getSecureTokenPathWithFuzzyMatching } from './utils.js';
import { GaxiosError } from 'gaxios';
import { FileLogger } from './logger.js';
import { getUserHashCache } from './userHashCache.js';

export class TokenManager {
  private oauth2Client: OAuth2Client;
  private tokenPath: string;
  private tokenPathMap: Map<string, string>;
  private logger: FileLogger;

  // I think the idea is that every time we auth and create a new token 
  // we save the ID to the tokenPathMap 

  // then on subsequent calls, we'll for sure be provided the userID from the client as an argument 
  // which we can then use in retrieveTokenPathWithUserHash 

  // constructor(oauth2Client: OAuth2Client) {
  //   this.oauth2Client = oauth2Client;
  //   this.tokenPath = getSecureTokenPath();
  //   this.setupTokenRefresh();
  // }

  constructor(oauth2Client: OAuth2Client, userID?: string) {
    this.oauth2Client = oauth2Client;
    this.tokenPath = userID 
      ? getSecureTokenPathWithFuzzyMatching(userID)
      : getSecureTokenPath();

    this.tokenPathMap = new Map<string, string>();
    this.logger = new FileLogger('mcp-server.log', 'TOKEN-MANAGER');

    userID ? this.tokenPathMap.set(userID, this.tokenPath) : null;
    this.setupTokenRefresh();
    
    this.logger.info('TokenManager initialized', {
      userID: userID || 'default',
      tokenPath: this.tokenPath,
      hasOAuth2Client: !!oauth2Client
    });
  }

  // Method to expose the token path
  public getTokenPath(): string {
    return this.tokenPath;
  }

  private async ensureTokenDirectoryExists(): Promise<void> {
    try {
        const dir = path.dirname(this.tokenPath);
        await fs.mkdir(dir, { recursive: true });
        console.log('Token directory created:', dir);
    } catch (error: unknown) {
        // Ignore errors if directory already exists, re-throw others
        if (error instanceof Error && 'code' in error && error.code !== 'EEXIST') {
            console.error('Failed to create token directory:', error);
            throw error;
        }
    }
  }

  private async ensureTokenDirectoryExistsWithUserHash(userHashID: string): Promise<void> {
    try {

      const logger = new FileLogger('auth-server.log');
      logger.info(`Ensuring token directory exists with user hash: ${userHashID}`);
      logger.info(`current token path: ${this.tokenPath}`);
      const dir = path.dirname(this.tokenPath);
      await fs.mkdir(dir, { recursive: true });
    } catch (error: unknown) {
      // Ignore errors if directory already exists, re-throw others
      if (error instanceof Error && 'code' in error && error.code !== 'EEXIST') {
          console.error('Failed to create token directory:', error);
          throw error;
      }
    }
  }

  private setupTokenRefresh(): void {
    this.oauth2Client.on("tokens", async (newTokens) => {
      try {
        await this.ensureTokenDirectoryExists();
        const currentTokens = JSON.parse(await fs.readFile(this.tokenPath, "utf-8"));
        const updatedTokens = {
          ...currentTokens,
          ...newTokens,
          refresh_token: newTokens.refresh_token || currentTokens.refresh_token,
        };
        await fs.writeFile(this.tokenPath, JSON.stringify(updatedTokens, null, 2), {
          mode: 0o600,
        });
        console.error("Tokens updated and saved");
      } catch (error: unknown) {
        // Handle case where currentTokens might not exist yet
        if (error instanceof Error && 'code' in error && error.code === 'ENOENT') { 
          try {
             await fs.writeFile(this.tokenPath, JSON.stringify(newTokens, null, 2), { mode: 0o600 });
             console.error("New tokens saved");
          } catch (writeError) {
            console.error("Error saving initial tokens:", writeError);
          }
        } else {
            console.error("Error saving updated tokens:", error);
        }
      }
    });
  }

  async loadSavedTokens(): Promise<boolean> {
    try {
      await this.ensureTokenDirectoryExists();
      if (
        !(await fs
          .access(this.tokenPath)
          .then(() => true)
          .catch(() => false))
      ) {
        console.log("token path: " + this.tokenPath)
        console.error("No token file found at:", this.tokenPath);
        return false;
      }

      const tokens = JSON.parse(await fs.readFile(this.tokenPath, "utf-8"));

      if (!tokens || typeof tokens !== "object") {
        console.error("Invalid token format in file:", this.tokenPath);
        return false;
      }

      this.oauth2Client.setCredentials(tokens);
      return true;
    } catch (error: unknown) {
      console.error("Error loading tokens:", error);
      // Attempt to delete potentially corrupted token file
      if (error instanceof Error && 'code' in error && error.code !== 'ENOENT') { 
          try { 
              await fs.unlink(this.tokenPath); 
              console.error("Removed potentially corrupted token file") 
            } catch (unlinkErr) { /* ignore */ } 
      }
      return false;
    }
  }

  async loadSavedTokensWithUserHash(userHashID: string): Promise<boolean> {
    try {
      // Use fuzzy matching to find the token file
      const fuzzyTokenPath = getSecureTokenPathWithFuzzyMatching(userHashID);
      this.logger.info(`Attempting to load tokens with fuzzy matching`, {
        userHashID,
        originalTokenPath: this.tokenPath,
        fuzzyTokenPath
      });
      
      // Update the token path to use the fuzzy matched path
      this.tokenPath = fuzzyTokenPath;

      await this.ensureTokenDirectoryExistsWithUserHash(userHashID);

      if (
        !(await fs
          .access(this.tokenPath)
          .then(() => true)
          .catch(() => false))
      ) {
        console.log("token path: " + this.tokenPath)
        console.error("No token file found at:", this.tokenPath);
        return false;
      }

      const tokens = JSON.parse(await fs.readFile(this.tokenPath, "utf-8"));

      if (!tokens || typeof tokens !== "object") {
        console.error("Invalid token format in file:", this.tokenPath);
        return false;
      }

      this.oauth2Client.setCredentials(tokens);
      return true;
    } catch (error: unknown) {
      console.error("Error loading tokens:", error);
      // Attempt to delete potentially corrupted token file
      if (error instanceof Error && 'code' in error && error.code !== 'ENOENT') { 
          try { 
              await fs.unlink(this.tokenPath); 
              console.error("Removed potentially corrupted token file") 
            } catch (unlinkErr) { /* ignore */ } 
      }
      return false;
    }
  }

  async refreshTokensIfNeeded(): Promise<boolean> {
    const expiryDate = this.oauth2Client.credentials.expiry_date;
    const isExpired = expiryDate
      ? Date.now() >= expiryDate - 5 * 60 * 1000 // 5 minute buffer
      : !this.oauth2Client.credentials.access_token; // No token means we need one

    this.logger.debug(`Token refresh check`, {
      hasAccessToken: !!this.oauth2Client.credentials.access_token,
      hasRefreshToken: !!this.oauth2Client.credentials.refresh_token,
      expiryDate: expiryDate ? new Date(expiryDate).toISOString() : 'none',
      isExpired
    });

    if (isExpired && this.oauth2Client.credentials.refresh_token) {
      this.logger.info("Token expired or nearing expiry, refreshing...");
      try {
        const response = await this.oauth2Client.refreshAccessToken();
        const newTokens = response.credentials;

        if (!newTokens.access_token) {
          throw new Error("Received invalid tokens during refresh");
        }
        
        // The 'tokens' event listener should handle saving
        this.oauth2Client.setCredentials(newTokens);
        this.logger.info("Token refreshed successfully", {
          hasNewAccessToken: !!newTokens.access_token,
          newExpiryDate: newTokens.expiry_date ? new Date(newTokens.expiry_date).toISOString() : 'none'
        });
        return true;
      } catch (refreshError) {
        if (refreshError instanceof GaxiosError && refreshError.response?.data?.error === 'invalid_grant') {
            this.logger.error("Token refresh failed: Invalid grant. Token likely expired or revoked", {
              error: refreshError.response?.data
            });
            
            // Remove expired token from cache if we have userID
            try {
              const cache = await getUserHashCache();
              // Find the entry in cache that matches this token path
              const allEntries = cache.getAllEntries();
              for (const [userHashID, entry] of Object.entries(allEntries)) {
                if (entry.actualTokenFilename === this.tokenPath) {
                  await cache.removeEntry(userHashID);
                  this.logger.info('Removed expired token from cache', {
                    userHashID,
                    tokenPath: this.tokenPath
                  });
                  break;
                }
              }
            } catch (cacheError) {
              this.logger.warn('Failed to remove expired token from cache', {
                error: cacheError instanceof Error ? cacheError.message : String(cacheError)
              });
            }
            
            return false; // Indicate failure due to invalid grant
        } else {
            this.logger.error("Token refresh failed", {
              error: refreshError instanceof Error ? refreshError.message : String(refreshError)
            });
            return false;
        }
      }
    } else if (!this.oauth2Client.credentials.access_token && !this.oauth2Client.credentials.refresh_token) {
        this.logger.warn("No access or refresh token available. Re-authentication required.");
        return false;
    } else {
        this.logger.debug("Token is valid, no refresh needed");
        return true;
    }
  }

  async validateTokens(): Promise<boolean> {
    if (!this.oauth2Client.credentials || !this.oauth2Client.credentials.access_token) {
        // Try loading first if no credentials set
        if (!(await this.loadSavedTokens())) {
            return false; // No saved tokens to load
        }
        // Check again after loading
        if (!this.oauth2Client.credentials || !this.oauth2Client.credentials.access_token) {
            return false; // Still no token after loading
        }
    }
    return this.refreshTokensIfNeeded();
  }

  async validateTokensWithUserHash(userHashID: string): Promise<boolean> {
    this.logger.info(`Validating tokens for user: ${userHashID}`);
    
    if (!this.oauth2Client.credentials || !this.oauth2Client.credentials.access_token) {
        this.logger.debug(`No credentials or access token found, attempting to load from file`);
        // Try loading first if no credentials set
        if (!(await this.loadSavedTokensWithUserHash(userHashID))) {
            this.logger.warn(`No saved tokens found for user: ${userHashID}`);
            return false; // No saved tokens to load
        }
        // Check again after loading
        if (!this.oauth2Client.credentials || !this.oauth2Client.credentials.access_token) {
            this.logger.error(`Still no access token after loading saved tokens for user: ${userHashID}`);
            return false; // Still no token after loading
        }
        this.logger.info(`Successfully loaded saved tokens for user: ${userHashID}`);
    }
    
    const refreshResult = await this.refreshTokensIfNeeded();
    this.logger.info(`Token validation result for user ${userHashID}: ${refreshResult ? 'SUCCESS' : 'FAILED'}`);
    return refreshResult;
  }


  async saveTokens(tokens: Credentials, originalUserHashID?: string): Promise<void> {
    try {
        await this.ensureTokenDirectoryExists();
        await fs.writeFile(this.tokenPath, JSON.stringify(tokens, null, 2), { mode: 0o600 });
        this.oauth2Client.setCredentials(tokens);
        console.error("Tokens saved successfully to:", this.tokenPath);
        
        // Add to cache if we have the original userHashID
        if (originalUserHashID && this.tokenPath) {
          const cache = await getUserHashCache();
          await cache.addEntry(originalUserHashID, this.tokenPath);
          this.logger.info('Added token file to cache', {
            originalUserHashID,
            tokenPath: this.tokenPath
          });
        }
    } catch (error: unknown) {
        console.error("Error saving tokens:", error);
        throw error;
    }
  }

  async clearTokens(originalUserHashID?: string): Promise<void> {
    try {
      this.oauth2Client.setCredentials({}); // Clear in memory
      await fs.unlink(this.tokenPath);
      console.error("Tokens cleared successfully");
      
      // Remove from cache if we have the original userHashID
      if (originalUserHashID) {
        const cache = await getUserHashCache();
        await cache.removeEntry(originalUserHashID);
        this.logger.info('Removed token file from cache', {
          originalUserHashID,
          tokenPath: this.tokenPath
        });
      }
    } catch (error: unknown) {
      if (error instanceof Error && 'code' in error && error.code === 'ENOENT') {
        // File already gone, which is fine
        console.error("Token file already deleted");
      } else {
        console.error("Error clearing tokens:", error);
        // Don't re-throw, clearing is best-effort
      }
    }
  }
} 