#!/usr/bin/env node

// Debug script to isolate the hanging issue
import { OAuth2Client } from 'google-auth-library';
import * as fs from 'fs/promises';
import * as path from 'path';
import { fileURLToPath } from 'url';

function getKeysFilePath() {
  const __dirname = path.dirname(fileURLToPath(import.meta.url));
  const projectRoot = path.join(__dirname, ".");
  return path.resolve(path.join(projectRoot, "gcp-oauth.keys.json"));
}

async function initializeOAuth2Client() {
  try {
    console.log('1. Starting OAuth2 client initialization...');
    const keysContent = await fs.readFile(getKeysFilePath(), "utf-8");
    console.log('2. Keys file read successfully');
    const keys = JSON.parse(keysContent);
    console.log('3. Keys parsed successfully');
    const { client_id, client_secret, redirect_uris } = keys.installed;
    console.log('4. Creating OAuth2Client...');
    const client = new OAuth2Client({
      clientId: client_id,
      clientSecret: client_secret,
      redirectUri: redirect_uris[0]
    });
    console.log('5. OAuth2Client created successfully');
    return client;
  } catch (error) {
    console.error('Error in initializeOAuth2Client:', error);
    throw new Error(`Error loading OAuth keys: ${error instanceof Error ? error.message : error}`);
  }
}

async function main() {
  console.log('Starting debug test...');
  
  try {
    const oauth2Client = await initializeOAuth2Client();
    console.log('✅ OAuth2Client initialization successful');
    console.log('✅ Test completed successfully');
    process.exit(0);
  } catch (error) {
    console.error('❌ Test failed:', error);
    process.exit(1);
  }
}

// Add timeout to prevent hanging
setTimeout(() => {
  console.error('❌ Test timed out after 10 seconds');
  process.exit(1);
}, 10000);

main();