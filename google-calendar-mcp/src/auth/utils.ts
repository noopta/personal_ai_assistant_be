import * as path from 'path';
import * as fs from 'fs';
import { fileURLToPath } from 'url';
import { getSecureTokenPath as getSharedSecureTokenPath, getLegacyTokenPath as getSharedLegacyTokenPath, getAccountMode as getSharedAccountMode } from './paths.js';
import { getUserHashCache } from './userHashCache.js';

// Helper to get the project root directory reliably
function getProjectRoot(): string {
  const __dirname = path.dirname(fileURLToPath(import.meta.url)); 
  // In build output (e.g., build/bundle.js), __dirname is .../build
  // Go up ONE level to get the project root
  const projectRoot = path.join(__dirname, ".."); // Corrected: Go up ONE level
  return path.resolve(projectRoot); // Ensure absolute path
}

// Returns the absolute path for the saved token file.
export function getSecureTokenPath(): string {
  // THIS IS WHERE WE NEED TO APPEND THE USER HASH
  const projectRoot = getProjectRoot();
  const tokenPath = path.join(projectRoot, ".gcp-saved-tokens.json");
  return tokenPath; // Already absolute from getProjectRoot
}

export function getSecureTokenPathWithUserHash(userHash: string): string {
  const projectRoot = getProjectRoot();
  const tokenPath = path.join(projectRoot, "." + userHash + "-gcp-saved-tokens.json");
  return tokenPath; // Already absolute from getProjectRoot
}

// Returns the absolute path for the GCP OAuth keys file.
export function getKeysFilePath(): string {
  const projectRoot = getProjectRoot();
  const keysPath = path.join(projectRoot, "gcp-oauth.keys.json"); 
  return keysPath; // Already absolute from getProjectRoot
} 

// Get the current account mode (normal or test) - delegates to shared implementation
export function getAccountMode(): 'normal' | 'test' {
  return getSharedAccountMode() as 'normal' | 'test';
}

/**
 * Find token file with case-insensitive prefix matching
 * This implements fuzzy matching similar to Gmail-MCP-Server
 */
export function findCaseInsensitiveTokenFile(userHashID: string): string | null {
  try {
    const projectRoot = getProjectRoot();
    const files = fs.readdirSync(projectRoot);
    const targetLower = userHashID.toLowerCase();
    
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
          // Extract the userHashID part from filename (remove . prefix and -gcp-saved-tokens suffix)
          const fileIdMatch = fileLower.match(/^\.(.+)-gcp-saved-tokens/);
          if (fileIdMatch) {
            const fileId = fileIdMatch[1];
            
            // Check if the file ID starts with our search prefix OR vice versa
            if (fileId.startsWith(searchPrefix) || searchPrefix.startsWith(fileId.substring(0, Math.min(fileId.length, searchPrefix.length)))) {
              const fullPath = path.join(projectRoot, file);
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
 * Get token path with cache lookup, then fuzzy matching fallback
 */
export async function getSecureTokenPathWithCacheAndFuzzyMatching(userHash: string): Promise<string> {
  // First try cache lookup
  try {
    const cache = await getUserHashCache();
    const cachedPath = await cache.getTokenFilename(userHash);
    
    if (cachedPath && fs.existsSync(cachedPath)) {
      console.log(`🔍 [TOKEN CHECK] Cache hit: ${cachedPath}`);
      return cachedPath;
    } else if (cachedPath) {
      console.log(`🔍 [TOKEN CHECK] Cache hit but file doesn't exist, removing from cache: ${cachedPath}`);
      await cache.removeEntry(userHash);
    }
  } catch (error) {
    console.log(`⚠️ [TOKEN CHECK] Cache lookup failed: ${error}`);
  }
  
  // Fallback to existing fuzzy matching logic
  return getSecureTokenPathWithFuzzyMatching(userHash);
}

/**
 * Get token path with fuzzy matching fallback (synchronous version)
 */
export function getSecureTokenPathWithFuzzyMatching(userHash: string): string {
  // First try exact match
  const exactPath = getSecureTokenPathWithUserHash(userHash);
  
  // Check if exact file exists
  if (fs.existsSync(exactPath)) {
    console.log(`🔍 [TOKEN CHECK] Exact match found: ${exactPath}`);
    return exactPath;
  }
  
  // If exact match doesn't exist, try fuzzy matching
  console.log(`🔍 [TOKEN CHECK] Exact match not found, trying fuzzy matching for: ${userHash}`);
  const fuzzyPath = findCaseInsensitiveTokenFile(userHash);
  
  if (fuzzyPath) {
    console.log(`🔍 [TOKEN CHECK] Fuzzy match found: ${fuzzyPath}`);
    return fuzzyPath;
  }
  
  // Return exact path even if it doesn't exist (for error handling)
  console.log(`🔍 [TOKEN CHECK] No fuzzy match found, returning exact path: ${exactPath}`);
  return exactPath;
}