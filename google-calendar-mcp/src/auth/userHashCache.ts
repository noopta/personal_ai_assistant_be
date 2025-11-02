import * as fs from 'fs/promises';
import * as path from 'path';
import { fileURLToPath } from 'url';
import { FileLogger } from './logger.js';

/**
 * Cache system to map original userHashIDs to actual refresh token filenames
 * This solves the issue where token filename obfuscation causes lookup failures
 */

interface CacheEntry {
  originalUserHashID: string;
  actualTokenFilename: string;
  createdAt: number;
  lastAccessed: number;
}

interface CacheData {
  version: string;
  entries: Record<string, CacheEntry>;
}

export class UserHashCache {
  private cacheFilePath: string;
  private cache: CacheData;
  private logger: FileLogger;
  private isDirty: boolean = false;

  constructor() {
    const __dirname = path.dirname(fileURLToPath(import.meta.url));
    const projectRoot = path.join(__dirname, "..");
    this.cacheFilePath = path.join(projectRoot, ".userhash-cache.json");
    this.logger = new FileLogger('mcp-server.log', 'USER-HASH-CACHE');
    
    this.cache = {
      version: "1.0.0",
      entries: {}
    };
  }

  /**
   * Initialize cache by loading from disk
   */
  async initialize(): Promise<void> {
    try {
      await this.loadCache();
      this.logger.info('UserHashCache initialized successfully', {
        entryCount: Object.keys(this.cache.entries).length,
        cacheFilePath: this.cacheFilePath
      });
    } catch (error) {
      this.logger.warn('Failed to load cache, starting with empty cache', {
        error: error instanceof Error ? error.message : String(error)
      });
    }
  }

  /**
   * Load cache from disk
   */
  private async loadCache(): Promise<void> {
    try {
      const cacheContent = await fs.readFile(this.cacheFilePath, 'utf8');
      const loadedCache = JSON.parse(cacheContent) as CacheData;
      
      // Validate cache structure
      if (loadedCache.version && loadedCache.entries) {
        this.cache = loadedCache;
        this.logger.debug('Cache loaded from disk', {
          version: loadedCache.version,
          entryCount: Object.keys(loadedCache.entries).length
        });
      } else {
        throw new Error('Invalid cache structure');
      }
    } catch (error) {
      if ((error as any)?.code === 'ENOENT') {
        this.logger.debug('Cache file does not exist, starting with empty cache');
      } else {
        this.logger.warn('Error loading cache file', {
          error: error instanceof Error ? error.message : String(error)
        });
      }
      // Reset to empty cache on any error
      this.cache = {
        version: "1.0.0",
        entries: {}
      };
    }
  }

  /**
   * Save cache to disk
   */
  private async saveCache(): Promise<void> {
    if (!this.isDirty) {
      return; // No changes to save
    }

    try {
      const cacheContent = JSON.stringify(this.cache, null, 2);
      await fs.writeFile(this.cacheFilePath, cacheContent, { mode: 0o600 });
      this.isDirty = false;
      
      this.logger.debug('Cache saved to disk', {
        entryCount: Object.keys(this.cache.entries).length
      });
    } catch (error) {
      this.logger.error('Failed to save cache to disk', {
        error: error instanceof Error ? error.message : String(error),
        cacheFilePath: this.cacheFilePath
      });
    }
  }

  /**
   * Add or update a cache entry mapping original userHashID to actual token filename
   */
  async addEntry(originalUserHashID: string, actualTokenFilename: string): Promise<void> {
    const now = Date.now();
    
    this.cache.entries[originalUserHashID] = {
      originalUserHashID,
      actualTokenFilename,
      createdAt: this.cache.entries[originalUserHashID]?.createdAt || now,
      lastAccessed: now
    };
    
    this.isDirty = true;
    await this.saveCache();
    
    this.logger.info('Added cache entry', {
      originalUserHashID,
      actualTokenFilename,
      timestamp: new Date(now).toISOString()
    });
  }

  /**
   * Get the actual token filename for a given original userHashID
   */
  async getTokenFilename(originalUserHashID: string): Promise<string | null> {
    const entry = this.cache.entries[originalUserHashID];
    
    if (entry) {
      // Update last accessed time
      entry.lastAccessed = Date.now();
      this.isDirty = true;
      await this.saveCache();
      
      this.logger.debug('Cache hit for userHashID', {
        originalUserHashID,
        actualTokenFilename: entry.actualTokenFilename,
        lastAccessed: new Date(entry.lastAccessed).toISOString()
      });
      
      return entry.actualTokenFilename;
    }
    
    this.logger.debug('Cache miss for userHashID', { originalUserHashID });
    return null;
  }

  /**
   * Remove a cache entry (called when tokens expire or are deleted)
   */
  async removeEntry(originalUserHashID: string): Promise<boolean> {
    if (this.cache.entries[originalUserHashID]) {
      delete this.cache.entries[originalUserHashID];
      this.isDirty = true;
      await this.saveCache();
      
      this.logger.info('Removed cache entry', { originalUserHashID });
      return true;
    }
    
    this.logger.debug('Attempted to remove non-existent cache entry', { originalUserHashID });
    return false;
  }

  /**
   * Check if a cache entry exists
   */
  hasEntry(originalUserHashID: string): boolean {
    return originalUserHashID in this.cache.entries;
  }

  /**
   * Get all cache entries (for debugging/maintenance)
   */
  getAllEntries(): Record<string, CacheEntry> {
    return { ...this.cache.entries };
  }

  /**
   * Clean up old entries that haven't been accessed in a while
   */
  async cleanup(maxAgeMs: number = 30 * 24 * 60 * 60 * 1000): Promise<number> {
    const now = Date.now();
    const cutoffTime = now - maxAgeMs;
    let removedCount = 0;
    
    for (const [userHashID, entry] of Object.entries(this.cache.entries)) {
      if (entry.lastAccessed < cutoffTime) {
        delete this.cache.entries[userHashID];
        removedCount++;
        this.logger.debug('Cleaned up old cache entry', {
          userHashID,
          lastAccessed: new Date(entry.lastAccessed).toISOString(),
          ageInDays: Math.floor((now - entry.lastAccessed) / (24 * 60 * 60 * 1000))
        });
      }
    }
    
    if (removedCount > 0) {
      this.isDirty = true;
      await this.saveCache();
      this.logger.info('Cache cleanup completed', { removedCount });
    }
    
    return removedCount;
  }

  /**
   * Verify that cached token files still exist on disk
   */
  async validateEntries(): Promise<{ valid: number; invalid: number; removed: number }> {
    let validCount = 0;
    let invalidCount = 0;
    let removedCount = 0;
    
    const entriesToRemove: string[] = [];
    
    for (const [userHashID, entry] of Object.entries(this.cache.entries)) {
      try {
        await fs.access(entry.actualTokenFilename);
        validCount++;
        this.logger.debug('Validated cache entry', {
          userHashID,
          tokenFile: entry.actualTokenFilename
        });
      } catch (error) {
        invalidCount++;
        entriesToRemove.push(userHashID);
        this.logger.warn('Invalid cache entry - token file not found', {
          userHashID,
          tokenFile: entry.actualTokenFilename,
          error: error instanceof Error ? error.message : String(error)
        });
      }
    }
    
    // Remove invalid entries
    for (const userHashID of entriesToRemove) {
      delete this.cache.entries[userHashID];
      removedCount++;
    }
    
    if (removedCount > 0) {
      this.isDirty = true;
      await this.saveCache();
    }
    
    this.logger.info('Cache validation completed', {
      valid: validCount,
      invalid: invalidCount,
      removed: removedCount
    });
    
    return { valid: validCount, invalid: invalidCount, removed: removedCount };
  }
}

// Singleton instance
let cacheInstance: UserHashCache | null = null;

/**
 * Get the singleton cache instance
 */
export async function getUserHashCache(): Promise<UserHashCache> {
  if (!cacheInstance) {
    cacheInstance = new UserHashCache();
    await cacheInstance.initialize();
  }
  return cacheInstance;
}