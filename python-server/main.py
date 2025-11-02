import asyncio
import json
import os
import subprocess
import signal
import sys
import time
from flask import Flask, request, jsonify, make_response
from flask_cors import CORS


# Security imports
import os
import re
import hashlib
import time
from functools import wraps
from collections import defaultdict

# Load environment variables
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))

# Rate limiting storage
rate_limit_store = defaultdict(list)

def validate_user_hash_id(hash_id):
    """Validate user hash ID format"""
    if not hash_id or not isinstance(hash_id, str):
        raise ValueError('User hash ID is required and must be a string')
    
    if not re.match(r'^[a-zA-Z0-9_-]{8,64}$', hash_id):
        raise ValueError('Invalid user hash ID format')
    
    return hash_id

def sanitize_input(input_str):
    """Sanitize user input"""
    if not isinstance(input_str, str):
        return input_str
    
    # Remove dangerous characters
    sanitized = re.sub(r'[<>\'"&{}();]', '', input_str)
    # Normalize whitespace
    sanitized = re.sub(r'\s+', ' ', sanitized).strip()
    # Limit length
    return sanitized[:1000]

def rate_limit(max_requests=60, window_seconds=60):
    """Rate limiting decorator"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Get client IP or identifier
            client_id = kwargs.get('userIDHash', 'unknown')
            current_time = time.time()
            
            # Clean old entries
            cutoff_time = current_time - window_seconds
            rate_limit_store[client_id] = [
                req_time for req_time in rate_limit_store[client_id] 
                if req_time > cutoff_time
            ]
            
            # Check rate limit
            if len(rate_limit_store[client_id]) >= max_requests:
                raise Exception(f'Rate limit exceeded. Max {max_requests} requests per {window_seconds} seconds.')
            
            # Add current request
            rate_limit_store[client_id].append(current_time)
            
            return func(*args, **kwargs)
        return wrapper
    return decorator

# Cookie helper functions for HTTP-only cookie management
def set_user_session_cookies(response, user_id_hash, gmail_hash_id):
    """Set secure httpOnly cookies"""
    response.set_cookie(
        'userIDHash',
        value=user_id_hash,
        max_age=30*24*60*60,  # 30 days
        httponly=True,
        secure=False,  # True in production
        samesite='Lax',
        path='/'
    )
    response.set_cookie(
        'gmailHashID',
        value=gmail_hash_id,
        max_age=30*24*60*60,  # 30 days
        httponly=True,
        secure=False,  # True in production
        samesite='Lax',
        path='/'
    )
    return response

def get_user_from_cookies():
    """Read cookies from request"""
    user_id_hash = request.cookies.get('userIDHash')
    gmail_hash_id = request.cookies.get('gmailHashID')
    
    if not user_id_hash or not gmail_hash_id:
        return None, None
    
    return user_id_hash, gmail_hash_id

def clear_user_session_cookies(response):
    """Clear cookies for logout"""
    response.set_cookie('userIDHash', '', max_age=0, path='/')
    response.set_cookie('gmailHashID', '', max_age=0, path='/')
    return response

def get_user_auth():
    """Get user authentication - supports both cookies (new) and body (old) for backward compatibility"""
    # Try cookies first (new way)
    user_id_hash, gmail_hash_id = get_user_from_cookies()
    
    # Fallback to request body (old way) for backward compatibility
    if not user_id_hash:
        try:
            data = request.get_json()
            if data:
                user_id_hash = data.get('userIDHash')
                gmail_hash_id = data.get('gmailHashID')
        except Exception:
            # Handle empty or invalid JSON gracefully
            data = None
    
    return user_id_hash, gmail_hash_id


app = Flask(__name__)

# Configure CORS to support credentials for HTTP-only cookies
CORS(app,
     supports_credentials=True,
     origins=[
         'http://localhost:3000',      # React dev
         'http://localhost:5173',      # Vite dev
         'https://luciuslab.xyz'       # Production
     ],
     allow_headers=['Content-Type', 'Authorization'],
     methods=['GET', 'POST', 'OPTIONS']
)

from dotenv import load_dotenv
from langchain_anthropic import ChatAnthropic
from langchain_openai import ChatOpenAI
from mcp_use import MCPAgent, MCPClient
import logging
from datetime import datetime  # Add this import
import shutil

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create global variables for shared resources and connection pools
import threading
import queue
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Optional, Dict, Any

# Import secure connection pool
import sys
sys.path.append('/home/ubuntu/mcp/shared')
from secure_connection_pool import SecureMCPConnectionPool

# Global connection pool - Enhanced for better scalability
# Use secure connection pool with session isolation and agent pool
connection_pool = SecureMCPConnectionPool(
    pool_size=200,           # 2x increase: support 200 concurrent users
    max_idle_time=300,       # 5 minutes: faster cleanup, better resource usage
    agent_pool_size=4        # Agent pool: 4 agents for parallel processing (reduced for faster init)
)
executor = ThreadPoolExecutor(max_workers=500)  # 2.5x increase: handle 500 concurrent requests

# Legacy global variables (kept for backward compatibility)
client = None
agent = None

def cleanup_ports():
    """Kill any processes using our required ports"""
    import subprocess
    ports = [3001, 5001]
    for port in ports:
        try:
            # Find process using the port
            result = subprocess.run(['lsof', '-ti', f':{port}'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0 and result.stdout.strip():
                pids = result.stdout.strip().split('\n')
                for pid in pids:
                    if pid.strip():
                        print(f"🔪 Killing process {pid} using port {port}")
                        subprocess.run(['kill', '-9', pid.strip()], timeout=5)
                        time.sleep(0.5)  # Give it a moment to clean up
        except Exception as e:
            print(f"⚠️  Could not clean port {port}: {e}")
    time.sleep(1)  # Final cleanup pause

def init_resources():
    global client, agent
    try:
        # Clean up any conflicting ports first
        print("🧹 Cleaning up any conflicting ports...")
        cleanup_ports()
        
        # Check if npx is available
        npx_path = shutil.which("npx")
        if not npx_path:
            logger.error("npx not found in PATH. Please install Node.js.")
            raise RuntimeError("Node.js/npx not found. Please install Node.js and ensure it's in your PATH.")
        
        logger.info(f"Found npx at: {npx_path}")
        
        logger.info("Initializing resources...")
        
        # Load environment variables
        load_dotenv()
        
        # Create configuration dictionary for MCP servers
        config = {
            "mcpServers": {
                "gmail": {
                    "url": "https://luciuslab.xyz:4007/mcp"
                }
            }
        }

        # Create MCPClient from configuration dictionary
        logger.info("Creating MCPClient...")
        client = MCPClient.from_dict(config)

        # Create LLM
        logger.info("Creating ChatAnthropic instance...")
        # llm = ChatAnthropic(
        #     model="claude-3-5-sonnet-20240620",
        #     api_key=os.getenv("ANTHROPIC_API_KEY")
        # )

        llm_api_key = os.getenv("OPENAI_API_KEY")
        if not llm_api_key:
            raise RuntimeError("OPENAI_API_KEY environment variable must be set")

        llm = ChatOpenAI(
            model="gpt-4o-mini",
            api_key=llm_api_key
        )

# notes, if gmail is unauthenticated, we can get the auth link by using the authenticate tool
        # Create agent with the client
        logger.info("Creating MCPAgent...")

        # create a variable for the system prompt that acts like a date. We want the format to be like "May 31, 2025 4:50 PM EST". We want to be able to get the current date and time.
        current_date_time = datetime.now().strftime("%B %d, %Y %I:%M %p %Z")

        system_prompt = open("system_prompt.md", "r").read()
        system_prompt = system_prompt.replace("{insert date and time}", current_date_time)

        agent = MCPAgent(
            llm=llm, client=client, 
            max_steps=30,
            system_prompt=system_prompt
        )
        
        logger.info("Resources initialized successfully")
    except Exception as e:
        logger.error(f"Error during initialization: {e}", exc_info=True)
        raise

async def reinit_resources():
    """Reinitialize resources after authentication"""
    global client, agent
    try:
        logger.info("Reinitializing resources after authentication...")
        
        # Clean up existing client if it exists
        if client:
            try:
                await client.close()
            except Exception as e:
                logger.warning(f"Error closing existing client: {e}")
        
        # Clean up existing agent if it exists
        if agent and hasattr(agent, '_initialized') and agent._initialized:
            try:
                await agent.close()
            except Exception as e:
                logger.warning(f"Error closing existing agent: {e}")
        
        # Recreate everything
        init_resources()
        logger.info("Resources reinitialized successfully")
        
    except Exception as e:
        logger.error(f"Error during reinitialization: {e}", exc_info=True)
        raise

@app.route('/oauth2callback')
def oauth_callback():
    # Handle OAuth callback
    # ... your existing OAuth handling code ...
    
    # Return a beautiful, modern authentication success page
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Authentication Successful</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                overflow: hidden;
            }
            
            .container {
                background: rgba(255, 255, 255, 0.95);
                backdrop-filter: blur(20px);
                border-radius: 20px;
                padding: 60px 40px;
                text-align: center;
                box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
                max-width: 500px;
                width: 90%;
                position: relative;
                animation: slideIn 0.8s ease-out;
            }
            
            .success-icon {
                width: 80px;
                height: 80px;
                background: linear-gradient(135deg, #4CAF50, #45a049);
                border-radius: 50%;
                margin: 0 auto 30px;
                display: flex;
                align-items: center;
                justify-content: center;
                animation: bounce 1s ease-out 0.3s both;
                box-shadow: 0 10px 30px rgba(76, 175, 80, 0.3);
            }
            
            .checkmark {
                color: white;
                font-size: 40px;
                font-weight: bold;
                animation: checkPop 0.5s ease-out 0.8s both;
            }
            
            h1 {
                color: #2c3e50;
                font-size: 32px;
                font-weight: 600;
                margin-bottom: 16px;
                animation: fadeInUp 0.6s ease-out 0.5s both;
            }
            
            .subtitle {
                color: #7f8c8d;
                font-size: 18px;
                margin-bottom: 30px;
                animation: fadeInUp 0.6s ease-out 0.7s both;
            }
            
            .message {
                background: linear-gradient(135deg, #f8f9fa, #e9ecef);
                border-radius: 12px;
                padding: 20px;
                margin: 30px 0;
                border-left: 4px solid #4CAF50;
                animation: fadeInUp 0.6s ease-out 0.9s both;
            }
            
            .message p {
                color: #495057;
                font-size: 16px;
                line-height: 1.5;
            }
            
            .countdown {
                display: inline-flex;
                align-items: center;
                gap: 8px;
                background: rgba(102, 126, 234, 0.1);
                color: #667eea;
                padding: 12px 20px;
                border-radius: 25px;
                font-size: 14px;
                font-weight: 500;
                margin-top: 20px;
                animation: fadeInUp 0.6s ease-out 1.1s both;
            }
            
            .countdown-circle {
                width: 20px;
                height: 20px;
                border: 2px solid #667eea;
                border-top: 2px solid transparent;
                border-radius: 50%;
                animation: spin 1s linear infinite;
            }
            
            .floating-particles {
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                pointer-events: none;
                overflow: hidden;
            }
            
            .particle {
                position: absolute;
                background: rgba(255, 255, 255, 0.6);
                border-radius: 50%;
                animation: float 6s ease-in-out infinite;
            }
            
            .particle:nth-child(1) { left: 10%; animation-delay: 0s; width: 4px; height: 4px; }
            .particle:nth-child(2) { left: 20%; animation-delay: 1s; width: 6px; height: 6px; }
            .particle:nth-child(3) { left: 30%; animation-delay: 2s; width: 3px; height: 3px; }
            .particle:nth-child(4) { left: 40%; animation-delay: 3s; width: 5px; height: 5px; }
            .particle:nth-child(5) { left: 50%; animation-delay: 4s; width: 4px; height: 4px; }
            .particle:nth-child(6) { left: 60%; animation-delay: 5s; width: 6px; height: 6px; }
            .particle:nth-child(7) { left: 70%; animation-delay: 0.5s; width: 3px; height: 3px; }
            .particle:nth-child(8) { left: 80%; animation-delay: 1.5s; width: 5px; height: 5px; }
            .particle:nth-child(9) { left: 90%; animation-delay: 2.5s; width: 4px; height: 4px; }
            
            @keyframes slideIn {
                from {
                    opacity: 0;
                    transform: translateY(50px) scale(0.9);
                }
                to {
                    opacity: 1;
                    transform: translateY(0) scale(1);
                }
            }
            
            @keyframes bounce {
                0%, 20%, 53%, 80%, 100% {
                    transform: translate3d(0, 0, 0);
                }
                40%, 43% {
                    transform: translate3d(0, -15px, 0);
                }
                70% {
                    transform: translate3d(0, -7px, 0);
                }
                90% {
                    transform: translate3d(0, -2px, 0);
                }
            }
            
            @keyframes checkPop {
                0% {
                    transform: scale(0);
                }
                50% {
                    transform: scale(1.2);
                }
                100% {
                    transform: scale(1);
                }
            }
            
            @keyframes fadeInUp {
                from {
                    opacity: 0;
                    transform: translateY(20px);
                }
                to {
                    opacity: 1;
                    transform: translateY(0);
                }
            }
            
            @keyframes spin {
                to {
                    transform: rotate(360deg);
                }
            }
            
            @keyframes float {
                0%, 100% {
                    transform: translateY(0px);
                    opacity: 0.3;
                }
                50% {
                    transform: translateY(-100vh);
                    opacity: 1;
                }
            }
            
            @media (max-width: 600px) {
                .container {
                    padding: 40px 30px;
                    margin: 20px;
                }
                
                h1 {
                    font-size: 28px;
                }
                
                .subtitle {
                    font-size: 16px;
                }
                
                .success-icon {
                    width: 70px;
                    height: 70px;
                }
                
                .checkmark {
                    font-size: 35px;
                }
            }
        </style>
    </head>
    <body>
        <div class="floating-particles">
            <div class="particle"></div>
            <div class="particle"></div>
            <div class="particle"></div>
            <div class="particle"></div>
            <div class="particle"></div>
            <div class="particle"></div>
            <div class="particle"></div>
            <div class="particle"></div>
            <div class="particle"></div>
        </div>
        
        <div class="container">
            <div class="success-icon">
                <div class="checkmark">✓</div>
            </div>
            
            <h1>Authentication Successful!</h1>
            <p class="subtitle">Your account has been connected securely</p>
            
            <div class="message">
                <p>🎉 Great! You're all set. You can now close this tab and return to your application to start using your connected services.</p>
            </div>
            
            <div class="countdown">
                <div class="countdown-circle"></div>
                <span>This window will close automatically in <span id="countdown">5</span> seconds</span>
            </div>
        </div>
        
        <script>
            // Enhanced countdown and auto-close functionality
            let countdownElement = document.getElementById('countdown');
            let timeLeft = 5;
            
            const countdownInterval = setInterval(() => {
                timeLeft--;
                countdownElement.textContent = timeLeft;
                
                if (timeLeft <= 0) {
                    clearInterval(countdownInterval);
                    
                    // Add fade out animation before closing
                    document.querySelector('.container').style.animation = 'fadeOut 0.5s ease-out forwards';
                    
                    setTimeout(() => {
                        try {
                            window.close();
                        } catch (e) {
                            // If window.close() fails (some browsers block it), show alternative message
                            document.querySelector('.container').innerHTML = `
                                <div class="success-icon">
                                    <div class="checkmark">✓</div>
                                </div>
                                <h1>You can close this tab now</h1>
                                <p class="subtitle">Authentication completed successfully</p>
                            `;
                            document.querySelector('.container').style.animation = 'slideIn 0.8s ease-out';
                        }
                    }, 500);
                }
            }, 1000);
            
            // Add fadeOut animation
            const style = document.createElement('style');
            style.textContent = `
                @keyframes fadeOut {
                    to {
                        opacity: 0;
                        transform: translateY(-20px) scale(0.95);
                    }
                }
            `;
            document.head.appendChild(style);
            
            // Add click to close functionality
            document.addEventListener('click', () => {
                clearInterval(countdownInterval);
                try {
                    window.close();
                } catch (e) {
                    console.log('Cannot close window automatically');
                }
            });
            
            // Add keyboard shortcut (Escape to close)
            document.addEventListener('keydown', (e) => {
                if (e.key === 'Escape') {
                    clearInterval(countdownInterval);
                    try {
                        window.close();
                    } catch (e) {
                        console.log('Cannot close window automatically');
                    }
                }
            });
        </script>
    </body>
    </html>
    """

@app.route('/gmail-auth', methods=['POST'])
def gmail_auth():
    try:
        logger.info("Starting Gmail authentication...")
        
        # Try cookies first, then fallback to request body or generate new
        userIDHash, gmailHashID = get_user_auth()
        
        # If no existing auth, generate new UUIDs
        if not userIDHash:
            import uuid
            userIDHash = str(uuid.uuid4())
            gmailHashID = str(uuid.uuid4())
            logger.info(f"Generated new userIDHash: {userIDHash}")
            logger.info(f"Generated new gmailHashID: {gmailHashID}")
        else:
            logger.info(f"Using existing userIDHash: {userIDHash}")
            logger.info(f"Using existing gmailHashID: {gmailHashID}")
        
        # Set environment variables for the subprocess
        env = os.environ.copy()
        env.update({
            'GOOGLE_CLIENT_ID': "894751159754-sfsipla5a47bkq5cq3kbenqnepm39of2.apps.googleusercontent.com",
            'GOOGLE_CLIENT_SECRET': os.getenv('GOOGLE_CLIENT_SECRET'),
            'GOOGLE_REDIRECT_URI': 'http://localhost:3001/oauth2callback'
        })
        
        # Check if required environment variables are set
        if not env.get('GOOGLE_CLIENT_ID') or not env.get('GOOGLE_CLIENT_SECRET'):
            return jsonify({
                'success': False,
                'error': 'Missing GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET environment variables'
            }), 400
        
        logger.info("Running Gmail authentication command...")

        # Use asyncio.run to handle async operations in sync route
        async def run_auth():
            try:
                # First try with shell=True to use system PATH
                process = await asyncio.create_subprocess_shell(
                    f'npx @gongrzhe/server-gmail-autoauth-mcp auth {gmailHashID}',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=env
                )
            except Exception as shell_error:
                logger.warning(f"Shell command failed: {shell_error}")
                # Fallback: try to find npx explicitly
                import shutil
                npx_path = shutil.which('npx')
                if not npx_path:
                    raise RuntimeError('npx command not found. Please ensure Node.js is installed and available in PATH.')
                
                # Use the full path to npx
                
                process = await asyncio.create_subprocess_exec(
                    npx_path, '@gongrzhe/server-gmail-autoauth-mcp', 'auth', gmailHashID,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=env
                )
            
            stdout, stderr = await process.communicate()
            return process, stdout, stderr
        
        process, stdout, stderr = asyncio.run(run_auth())
        
        stdout_text = stdout.decode('utf-8').strip()
        stderr_text = stderr.decode('utf-8').strip()
        
        logger.info(f"Auth command completed with return code: {process.returncode}")
        if stdout_text:
            logger.info(f"Auth stdout: {stdout_text}")
        if stderr_text:
            logger.info(f"Auth stderr: {stderr_text}")
        
        # Look for authentication URL in the output
        auth_url = None
        combined_output = stdout_text + '\n' + stderr_text
        
        for line in combined_output.split('\n'):
            if 'http' in line and ('accounts.google.com' in line or 'oauth' in line.lower()):
                auth_url = line.strip()
                break
        
        if process.returncode == 0:
            # Authentication successful - reinitialize the client and agent
            try:
                asyncio.run(reinit_resources())
                logger.info("Successfully reinitialized resources after authentication")
            except Exception as reinit_error:
                logger.error(f"Failed to reinitialize after auth: {reinit_error}")
                return jsonify({
                    'success': False,
                    'error': f'Authentication succeeded but failed to reinitialize: {str(reinit_error)}'
                }), 500
            
            # Create response with cookies
            response_data = {
                'success': True,
                'output': stdout_text,
                'stderr': stderr_text,
                'auth_url': auth_url,
                'message': 'Authentication completed successfully and resources reinitialized'
            }
            response = make_response(jsonify(response_data))
            
            # Set HTTP-only cookies
            response = set_user_session_cookies(response, userIDHash, gmailHashID)
            
            return response
        else:
            # Even on auth failure, set cookies so user can retry
            response_data = {
                'success': False,
                'output': stdout_text,
                'error': stderr_text,
                'auth_url': auth_url,
                'message': 'Authentication failed or requires user interaction'
            }
            response = make_response(jsonify(response_data), 200)
            response = set_user_session_cookies(response, userIDHash, gmailHashID)
            return response
            
    except FileNotFoundError:
        logger.error("npx command not found - make sure Node.js is installed")
        return jsonify({
            'success': False,
            'error': 'npx command not found. Please ensure Node.js is installed and available in PATH.'
        }), 500
    except Exception as e:
        logger.error(f"Error during Gmail authentication: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/gmail-status', methods=['POST'])
def gmail_auth_status():
    """Check if Gmail is already authenticated by validating credential file"""
    try:
        # Read from cookies instead of request body
        userIDHash, gmail_hash_id = get_user_from_cookies()
        
        if not gmail_hash_id:
            return jsonify({
                'authenticated': False,
                'needs_auth': True,
                'error': 'No session found. Please authenticate first.'
            }), 401
        logger.info(f"Checking Gmail authentication status for user: {gmail_hash_id}")
        
        # Search for credential file with prefix pattern
        import glob
        credential_dir = "/home/ubuntu/mcp/Gmail-MCP-Server/refresh-tokens"
        credential_pattern = f".{gmail_hash_id}-gcp-saved-tokens.json"
        credential_path = os.path.join(credential_dir, credential_pattern)
        
        # Check if credential file exists
        if not os.path.exists(credential_path):
            logger.info(f"Credential file not found at: {credential_path}")
            return jsonify({
                'authenticated': False,
                'needs_auth': True,
                'message': 'No credentials found. Please authenticate again.'
            })
        
        # Read and parse credential file
        try:
            with open(credential_path, 'r') as f:
                credentials = json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Error reading credential file: {e}")
            return jsonify({
                'authenticated': False,
                'needs_auth': True,
                'message': 'Invalid credential file. Please authenticate again.'
            })
        
        # Check if expiry_date field exists
        if 'expiry_date' not in credentials:
            logger.warning(f"No expiry_date field in credential file for user: {gmail_hash_id}")
            return jsonify({
                'authenticated': False,
                'needs_auth': True,
                'message': 'Invalid credential format. Please authenticate again.'
            })
        
        # Parse expiry date and check if expired
        try:
            from datetime import datetime
            # Convert Unix timestamp (milliseconds) to datetime
            expiry_timestamp = int(credentials['expiry_date']) / 1000  # Convert ms to seconds
            expiry_date = datetime.fromtimestamp(expiry_timestamp)
            current_time = datetime.now()
            
            if current_time >= expiry_date:
                logger.info(f"Credentials expired for user: {gmail_hash_id}")
                return jsonify({
                    'authenticated': False,
                    'needs_auth': True,
                    'message': 'Your session has expired. Please authenticate again.'
                })
            
            # Credentials are valid
            logger.info(f"Valid credentials found for user: {gmail_hash_id}")
            return jsonify({
                'authenticated': True,
                'needs_auth': False,
                'message': 'Gmail is authenticated and ready to use.'
            })
            
        except (ValueError, KeyError) as e:
            logger.error(f"Error parsing expiry date: {e}")
            return jsonify({
                'authenticated': False,
                'needs_auth': True,
                'message': 'Invalid expiry date format. Please authenticate again.'
            })
        
    except Exception as e:
        logger.error(f"Error checking Gmail auth status: {e}", exc_info=True)
        return jsonify({
            'authenticated': False,
            'needs_auth': True,
            'error': str(e),
            'message': 'Unable to determine Gmail authentication status'
        })

async def run_subprocess_with_cleanup(cmd, *args, **kwargs):
    process = None
    try:
        process = await asyncio.create_subprocess_exec(cmd, *args, **kwargs)
        return process
    except Exception as e:
        if process:
            try:
                process.terminate()
                await process.wait()
            except:
                pass
        raise e

@app.route('/calendar-auth', methods=['POST'])
def calendar_auth():
    """Sync route handler for calendar authentication"""
    try:
        # Try cookies first, then fallback to request body or generate new
        userIdHash, gmailHashID = get_user_auth()
        
        # If no existing auth, generate new UUIDs
        if not userIdHash:
            import uuid
            userIdHash = str(uuid.uuid4())
            gmailHashID = str(uuid.uuid4()) if not gmailHashID else gmailHashID
            logger.info(f"Generated new userIDHash for calendar: {userIdHash}")
        
        request_data = request.get_json() or {}
        
        # Run the async function
        result = asyncio.run(calendar_auth_async(userIdHash, request_data, gmailHashID))
        
        # If the result is a tuple (response, status_code), handle it
        if isinstance(result, tuple):
            response_data, status_code = result
        else:
            response_data = result
            status_code = 200
        
        # Convert to Flask response and add cookies
        if hasattr(response_data, 'get_json'):
            # It's already a Response object
            response_json = response_data.get_json()
            response = make_response(jsonify(response_json), status_code)
        else:
            # It's JSON data
            response = make_response(response_data, status_code)
        
        # Set cookies for all calendar auth responses
        response = set_user_session_cookies(response, userIdHash, gmailHashID)
        
        return response
    except Exception as e:
        logger.error(f"Error during Calendar authentication: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

async def background_token_polling(token_file_path: str, userIdHash: str):
    """Background task to poll for token file creation"""
    max_wait_time = 300  # 5 minutes
    check_interval = 5   # Check every 5 seconds for background polling
    elapsed_time = 0
    
    print(f"=== BACKGROUND POLLING STARTED ===")
    logger.info(f"=== BACKGROUND POLLING STARTED ===")
    logger.info(f"Monitoring: {token_file_path}")
    
    try:
        while elapsed_time < max_wait_time:
            await asyncio.sleep(check_interval)
            elapsed_time += check_interval
            
            if os.path.exists(token_file_path):
                print(f"=== BACKGROUND: TOKEN FILE FOUND! ===")
                logger.info(f"=== BACKGROUND: TOKEN FILE FOUND! ===")
                
                # Validate token file
                try:
                    with open(token_file_path, 'r') as f:
                        content = f.read()
                        tokens = json.loads(content)
                        
                    if tokens.get('access_token') or tokens.get('refresh_token'):
                        print(f"=== BACKGROUND: VALID TOKENS CONFIRMED ===")
                        logger.info(f"=== BACKGROUND: VALID TOKENS CONFIRMED ===")
                        
                        # Reinitialize resources
                        try:
                            await reinit_resources()
                            print("=== BACKGROUND: Resources reinitialized ===")
                            logger.info("=== BACKGROUND: Resources reinitialized ===")
                        except Exception as reinit_error:
                            logger.error(f"Background reinit failed: {reinit_error}")
                        
                        return  # Success, stop polling
                    
                except Exception as read_error:
                    logger.warning(f"Background: Could not read token file: {read_error}")
            
            print(f"Background poll: {elapsed_time}s elapsed, continuing...")
            logger.info(f"Background poll: {elapsed_time}s elapsed, continuing...")
        
        # Timeout reached
        print(f"=== BACKGROUND POLLING TIMEOUT ===")
        logger.warning(f"=== BACKGROUND POLLING TIMEOUT ===")
        
    except Exception as e:
        logger.error(f"Background polling error: {e}")

async def calendar_auth_async(userIdHash, request_data, gmailHashID):
    """Async helper function for calendar authentication"""
    process = None
    try:
        # Force flush the logs immediately
        print("=== CALENDAR AUTH ENDPOINT CALLED ===")
        logger.info("=== CALENDAR AUTH ENDPOINT CALLED ===")
        
        # Log the request body
        print(f"Request body: {request_data}")
        logger.info(f"Request body: {request_data}")
        if not userIdHash:
            print("ERROR: Missing userIDHash in request")
            logger.error("Missing userIDHash in request")
            return jsonify({
                'success': False,
                'error': 'Missing userIDHash parameter'
            }), 400

        print(f"Starting Google Calendar authentication for user: {userIdHash}")
        logger.info(f"Starting Google Calendar authentication for user: {userIdHash}")
        
        # Set the working directory to your google-calendar-mcp project
        calendar_project_dir = "/home/ubuntu/mcp/google-calendar-mcp"
        
        # Check if npm is available first
        npm_path = shutil.which("npm")
        if not npm_path:
            print("ERROR: npm not found in PATH")
            logger.error("npm not found in PATH. Please install Node.js.")
            return jsonify({
                'success': False,
                'error': 'npm command not found. Please install Node.js and ensure it\'s in your PATH.'
            }), 500
        
        print(f"Found npm at: {npm_path}")
        logger.info(f"Found npm at: {npm_path}")
        
        # Check if the calendar project directory exists
        if not os.path.exists(calendar_project_dir):
            print(f"ERROR: Calendar project directory does not exist: {calendar_project_dir}")
            logger.error(f"Calendar project directory does not exist: {calendar_project_dir}")
            return jsonify({
                'success': False,
                'error': f'Calendar project directory not found: {calendar_project_dir}'
            }), 500
        
        # Expected token file path
        token_file_path = os.path.join(calendar_project_dir, f".{userIdHash}-gcp-saved-tokens.json")
        print(f"Token file path: {token_file_path}")
        logger.info(f"Will monitor token file at: {token_file_path}")
        
        # Check if token file already exists (cleanup from previous runs)
        if os.path.exists(token_file_path):
            print(f"Token file already exists, removing: {token_file_path}")
            logger.info(f"Token file already exists, removing: {token_file_path}")
            try:
                os.remove(token_file_path)
                print("Existing token file removed successfully")
            except Exception as cleanup_error:
                print(f"WARNING: Could not remove existing token file: {cleanup_error}")
                logger.warning(f"Could not remove existing token file: {cleanup_error}")
        
        print(f"Running Calendar authentication in directory: {calendar_project_dir}")
        logger.info(f"Running Calendar authentication in directory: {calendar_project_dir}")
        
        # Start the npm process
        try:
            process = await asyncio.create_subprocess_exec(
                npm_path, 'run', 'auth', '--', userIdHash,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=calendar_project_dir
            )
            print(f"Authentication process started with PID: {process.pid}")
            logger.info(f"Authentication process started with PID: {process.pid}")
        except Exception as process_error:
            print(f"ERROR: Failed to start authentication process: {process_error}")
            logger.error(f"Failed to start authentication process: {process_error}")
            return jsonify({
                'success': False,
                'error': f'Failed to start authentication process: {str(process_error)}'
            }), 500
        
        # Wait for OAuth URL generation (should happen quickly)
        print("=== WAITING FOR OAUTH URL ===")
        logger.info("=== WAITING FOR OAUTH URL ===")
        
        oauth_url = None
        url_wait_time = 30  # Wait up to 30 seconds for URL
        start_time = time.time()
        
        try:
            # Read output in real-time using readline
            auth_url_found = False
            output_lines = []
            
            while time.time() - start_time < url_wait_time and not auth_url_found:
                try:
                    # Try to read a line from stdout
                    if process.stdout:
                        line = await asyncio.wait_for(process.stdout.readline(), timeout=1.0)
                        if line:
                            line_text = line.decode('utf-8').strip()
                            output_lines.append(line_text)
                            print(f"Auth process output: {line_text}")
                            logger.info(f"Auth process output: {line_text}")
                            
                            # Check for OAuth URL
                            if 'Generated Auth URL:' in line_text:
                                oauth_url = line_text.replace('Generated Auth URL: ', '').strip()
                                print(f"Found OAuth URL: {oauth_url}")
                                logger.info(f"Found OAuth URL: {oauth_url}")
                                auth_url_found = True
                                break
                            elif 'https://accounts.google.com/o/oauth2' in line_text:
                                oauth_url = line_text.strip()
                                print(f"Found OAuth URL: {oauth_url}")
                                logger.info(f"Found OAuth URL: {oauth_url}")
                                auth_url_found = True
                                break
                        else:
                            # No more output, check if process finished
                            if process.returncode is not None:
                                print("Process finished, checking final output...")
                                logger.info("Process finished, checking final output...")
                                break
                                
                except asyncio.TimeoutError:
                    # No output in 1 second, continue waiting
                    continue
                except Exception as e:
                    print(f"Error reading process output: {e}")
                    logger.error(f"Error reading process output: {e}")
                    break
            
            # If we found a URL, return it immediately
            if oauth_url:
                print(f"=== OAUTH URL FOUND, RETURNING TO USER ===")
                logger.info(f"=== OAUTH URL FOUND, RETURNING TO USER ===")
                
                # Start background polling for token file
                asyncio.create_task(background_token_polling(token_file_path, userIdHash))
                
                return jsonify({
                    'success': True,
                    'auth_url': oauth_url,
                    'message': 'Please visit the auth URL to complete authentication. The system will automatically detect when you complete the process.',
                    'userIdHash': userIdHash,
                    'token_file_path': token_file_path
                })
            else:
                print("=== NO OAUTH URL FOUND IN OUTPUT ===")
                logger.error("=== NO OAUTH URL FOUND IN OUTPUT ===")
                
        except Exception as url_error:
            print(f"ERROR: Error waiting for OAuth URL: {url_error}")
            logger.error(f"Error waiting for OAuth URL: {url_error}")
        
        # Fallback: if no URL found, continue with old polling method
        print(f"=== FALLING BACK TO POLLING METHOD ===")
        logger.info(f"=== FALLING BACK TO POLLING METHOD ===")
        
        # Poll for token file creation
        max_wait_time = 300  # 5 minutes
        check_interval = 2   # Check every 2 seconds
        elapsed_time = 0
        poll_count = 0
        
        print(f"=== STARTING POLLING LOOP ===")
        print(f"Max wait: {max_wait_time}s, check interval: {check_interval}s")
        print(f"Monitoring: {token_file_path}")
        logger.info(f"=== STARTING POLLING LOOP ===")
        logger.info(f"Max wait: {max_wait_time}s, check interval: {check_interval}s")
        logger.info(f"Monitoring: {token_file_path}")
        
        try:
            while elapsed_time < max_wait_time:
                poll_count += 1
                print(f"POLL #{poll_count}: Elapsed {elapsed_time}s/{max_wait_time}s")
                logger.info(f"POLL #{poll_count}: Elapsed {elapsed_time}s/{max_wait_time}s")
                
                # Check for token file
                print(f"Checking if file exists: {token_file_path}")
                file_exists = os.path.exists(token_file_path)
                print(f"File exists: {file_exists}")
                
                if file_exists:
                    print(f"TOKEN FILE FOUND! Path: {token_file_path}")
                    logger.info(f"TOKEN FILE FOUND! Path: {token_file_path}")
                    
                    # Check file size to ensure it's not empty
                    try:
                        file_size = os.path.getsize(token_file_path)
                        print(f"Token file size: {file_size} bytes")
                        logger.info(f"Token file size: {file_size} bytes")
                        
                        if file_size > 0:
                            # Give it a moment to ensure file is fully written
                            print("Waiting 2 seconds for file to be completely written...")
                            logger.info("Waiting 2 seconds for file to be completely written...")
                            await asyncio.sleep(2)
                            
                            # Try to read and validate the token file
                            try:
                                with open(token_file_path, 'r') as f:
                                    content = f.read()
                                    print(f"File content length: {len(content)} characters")
                                    print(f"File content preview: {content[:200]}...")
                                    logger.info(f"File content length: {len(content)} characters")
                                    logger.info(f"File content preview: {content[:200]}...")
                                    
                                    tokens = json.loads(content)
                                    print(f"Successfully parsed JSON. Keys: {list(tokens.keys())}")
                                    logger.info(f"Successfully parsed JSON. Keys: {list(tokens.keys())}")
                                    
                                    if tokens.get('access_token') or tokens.get('refresh_token'):
                                        print("=== VALID TOKENS FOUND! ===")
                                        logger.info("=== VALID TOKENS FOUND! ===")
                                        
                                        # Get process output if available
                                        stdout_text = ""
                                        stderr_text = ""
                                        
                                        if process.returncode is not None:
                                            try:
                                                stdout, stderr = await process.communicate()
                                                stdout_text = stdout.decode('utf-8').strip()
                                                stderr_text = stderr.decode('utf-8').strip()
                                                print(f"Process output captured")
                                                logger.info(f"Process output captured")
                                            except Exception as comm_error:
                                                print(f"WARNING: Could not get process output: {comm_error}")
                                                logger.warning(f"Could not get process output: {comm_error}")
                                        else:
                                            print("Process still running, tokens saved successfully")
                                            logger.info("Process still running, tokens saved successfully")
                                            stdout_text = "Process completed successfully"
                                            
                                            # Clean up the running process
                                            try:
                                                process.terminate()
                                                await asyncio.wait_for(process.wait(), timeout=5.0)
                                                print("Process terminated successfully after token creation")
                                                logger.info("Process terminated successfully after token creation")
                                            except asyncio.TimeoutError:
                                                print("Process didn't terminate gracefully, killing it")
                                                logger.warning("Process didn't terminate gracefully, killing it")
                                                process.kill()
                                                await process.wait()
                                                print("Process killed")
                                                logger.info("Process killed")
                                        
                                        # Authentication successful - reinitialize
                                        try:
                                            print("Reinitializing resources...")
                                            logger.info("Reinitializing resources...")
                                            await reinit_resources()
                                            print("Successfully reinitialized resources")
                                            logger.info("Successfully reinitialized resources")
                                        except Exception as reinit_error:
                                            print(f"ERROR: Failed to reinitialize: {reinit_error}")
                                            logger.error(f"Failed to reinitialize: {reinit_error}")
                                            return jsonify({
                                                'success': False,
                                                'error': f'Authentication succeeded but failed to reinitialize: {str(reinit_error)}'
                                            }), 500
                                        
                                        return jsonify({
                                            'success': True,
                                            'output': stdout_text,
                                            'stderr': stderr_text,
                                            'message': 'Calendar authentication completed successfully and resources reinitialized',
                                            'userIdHash': userIdHash,
                                            'token_file_path': token_file_path,
                                            'polls_taken': poll_count,
                                            'elapsed_time': elapsed_time
                                        })
                                    else:
                                        print("Token file doesn't contain access_token or refresh_token")
                                        logger.warning("Token file doesn't contain access_token or refresh_token")
                                        
                            except json.JSONDecodeError as json_error:
                                print(f"WARNING: Token file contains invalid JSON: {json_error}")
                                logger.warning(f"Token file contains invalid JSON: {json_error}")
                            except Exception as read_error:
                                print(f"WARNING: Could not read token file: {read_error}")
                                logger.warning(f"Could not read token file: {read_error}")
                        else:
                            print("Token file exists but is empty, continuing to wait...")
                            logger.info("Token file exists but is empty, continuing to wait...")
                            
                    except Exception as size_error:
                        print(f"WARNING: Could not get file size: {size_error}")
                        logger.warning(f"Could not get file size: {size_error}")
                
                # Wait before next check
                print(f"Sleeping for {check_interval} seconds...")
                logger.info(f"Sleeping for {check_interval} seconds...")
                await asyncio.sleep(check_interval)
                elapsed_time += check_interval
                print(f"Sleep completed, elapsed time now: {elapsed_time}s")
                logger.info(f"Sleep completed, elapsed time now: {elapsed_time}s")
        
        except Exception as polling_error:
            print(f"ERROR: Error in polling loop: {polling_error}")
            logger.error(f"Error in polling loop: {polling_error}", exc_info=True)
            raise
        
        # Timeout reached
        print(f"=== TIMEOUT REACHED ===")
        print(f"Polled {poll_count} times over {elapsed_time} seconds")
        logger.error(f"=== TIMEOUT REACHED ===")
        logger.error(f"Polled {poll_count} times over {elapsed_time} seconds")
        
        # Clean up process
        if process.returncode is None:
            print("Terminating npm process due to timeout")
            logger.info("Terminating npm process due to timeout")
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=10.0)
                print("Process terminated successfully")
                logger.info("Process terminated successfully")
            except asyncio.TimeoutError:
                print("Process didn't terminate gracefully, killing it")
                logger.warning("Process didn't terminate gracefully, killing it")
                process.kill()
                await process.wait()
                print("Process killed")
                logger.info("Process killed")
        
        # Get any output for debugging
        try:
            stdout, stderr = await process.communicate()
            stdout_text = stdout.decode('utf-8').strip()
            stderr_text = stderr.decode('utf-8').strip()
            print(f"Final process stdout: {stdout_text}")
            print(f"Final process stderr: {stderr_text}")
            logger.info(f"Final process stdout: {stdout_text}")
            logger.info(f"Final process stderr: {stderr_text}")
        except Exception as final_comm_error:
            print(f"ERROR: Could not get final process output: {final_comm_error}")
            logger.error(f"Could not get final process output: {final_comm_error}")
            stdout_text = "Could not read process output"
            stderr_text = "Could not read process output"
        
        return jsonify({
            'success': False,
            'message': f'Authentication timed out after {elapsed_time}s - no tokens found. Polled {poll_count} times.',
            'timeout': True,
            'output': stdout_text,
            'error': stderr_text,
            'elapsed_time': elapsed_time,
            'polls_taken': poll_count,
            'token_file_path': token_file_path
        }), 408
        
    except Exception as e:
        if process:
            try:
                process.terminate()
                await process.wait()
            except:
                pass
        print(f"ERROR: Error during Calendar authentication: {e}")
        logger.error(f"Error during Calendar authentication: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        # Always clean up the process if it's still running
        if process and process.returncode is None:
            try:
                print("Cleaning up running process in finally block")
                logger.info("Cleaning up running process in finally block")
                process.terminate()
                await asyncio.wait_for(process.wait(), timeout=5.0)
                print("Process cleaned up successfully")
                logger.info("Process cleaned up successfully")
            except asyncio.TimeoutError:
                print("Process didn't terminate gracefully in finally, killing it")
                logger.warning("Process didn't terminate gracefully in finally, killing it")
                process.kill()
                await process.wait()
                print("Process killed in finally")
                logger.info("Process killed in finally")
            except Exception as cleanup_error:
                print(f"Error during process cleanup in finally: {cleanup_error}")
                logger.error(f"Error during process cleanup in finally: {cleanup_error}")

@app.route('/calendar-status', methods=['POST'])
def calendar_auth_status():
    """Check if Google Calendar is already authenticated by validating credential file"""
    try:
        # Read from cookies instead of request body
        user_id_hash, gmailHashID = get_user_from_cookies()
        
        if not user_id_hash:
            return jsonify({
                'authenticated': False,
                'needs_auth': True,
                'error': 'No session found. Please authenticate first.'
            }), 401
        logger.info(f"Checking Google Calendar authentication status for user: {user_id_hash}")
        
        # Search for credential file with prefix pattern
        import glob
        credential_dir = "/home/ubuntu/mcp/google-calendar-mcp"
        credential_pattern = f".{user_id_hash}*"
        credential_files = glob.glob(os.path.join(credential_dir, credential_pattern))
        
        # Check if any credential file exists with the prefix
        if not credential_files:
            logger.info(f"No credential file found with prefix: .{user_id_hash}")
            return jsonify({
                'authenticated': False,
                'needs_auth': True,
                'message': 'No credentials found. Please authenticate again.'
            })
        
        # Use the first matching file
        credential_path = credential_files[0]
        logger.info(f"Found credential file: {credential_path}")
        
        # Read and parse credential file
        try:
            with open(credential_path, 'r') as f:
                credentials = json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Error reading credential file: {e}")
            return jsonify({
                'authenticated': False,
                'needs_auth': True,
                'message': 'Invalid credential file. Please authenticate again.'
            })
        
        # Check if expiry_date field exists
        if 'expiry_date' not in credentials:
            logger.warning(f"No expiry_date field in credential file for user: {user_id_hash}")
            return jsonify({
                'authenticated': False,
                'needs_auth': True,
                'message': 'Invalid credential format. Please authenticate again.'
            })
        
        # Parse expiry date and check if expired
        try:
            from datetime import datetime
            # Convert Unix timestamp (milliseconds) to datetime
            expiry_timestamp = int(credentials['expiry_date']) / 1000  # Convert ms to seconds
            expiry_date = datetime.fromtimestamp(expiry_timestamp)
            current_time = datetime.now()
            
            if current_time >= expiry_date:
                logger.info(f"Credentials expired for user: {user_id_hash}")
                return jsonify({
                    'authenticated': False,
                    'needs_auth': True,
                    'message': 'Your session has expired. Please authenticate again.'
                })
            
            # Credentials are valid
            logger.info(f"Valid credentials found for user: {user_id_hash}")
            return jsonify({
                'authenticated': True,
                'needs_auth': False,
                'message': 'Calendar is authenticated and ready to use.'
            })
            
        except (ValueError, KeyError) as e:
            logger.error(f"Error parsing expiry date: {e}")
            return jsonify({
                'authenticated': False,
                'needs_auth': True,
                'message': 'Invalid expiry date format. Please authenticate again.'
            })
        
    except Exception as e:
        logger.error(f"Error checking Calendar auth status: {e}", exc_info=True)
        return jsonify({
            'authenticated': False,
            'needs_auth': True,
            'error': str(e),
            'message': 'Unable to determine calendar authentication status'
        })

@app.route('/agent', methods=['POST'])
def run_agent():
    """Scalable agent endpoint using connection pooling"""
    request_id = f"req_{int(time.time() * 1000)}_{threading.current_thread().ident}"
    
    try:
        logger.info(f"[{request_id}] Received request to /agent endpoint")
        data = request.get_json()
        if not data or 'query' not in data:
            logger.warning(f"[{request_id}] Missing query parameter in request")
            return jsonify({'error': 'Missing query parameter'}), 400
            
        query = data['query']
        
        # Read authentication from cookies instead of request body
        userIDHash, gmailHashID = get_user_from_cookies()
        
        if not userIDHash or not gmailHashID:
            return jsonify({
                'error': 'Authentication required. Please authenticate with Gmail and Calendar first.'
            }), 401
        
        # Console logging for hash IDs
        print(f"🔍 [AGENT REQUEST] gmailHashID: {gmailHashID}")
        print(f"🔍 [AGENT REQUEST] userIDHash: {userIDHash}")
        print(f"🔍 [AGENT REQUEST] Query: {query[:100]}...")
        
        logger.info(f"[{request_id}] Processing query for user {userIDHash}: {query[:50]}...")

        # Submit to thread pool for processing
        logger.info(f"[{request_id}] Submitting to thread pool")
        future = executor.submit(process_agent_request, request_id, query, gmailHashID, userIDHash)
        logger.info(f"[{request_id}] Submitted to thread pool, waiting for result")
        
        try:
            # Wait for result with extended timeout to match agent execution timeout
            logger.info(f"[{request_id}] Calling future.result() with 330s timeout")
            result = future.result(timeout=120)  # 2 minute timeout - optimized for faster response
            logger.info(f"[{request_id}] Got result from thread pool: {type(result)}")
            logger.info(f"[{request_id}] Result content preview: {str(result)[:300]}...")
            
            # Check if result indicates authentication error
            if isinstance(result, str) and ("authentication expired" in result.lower() or "re-authenticate" in result.lower()):
                logger.warning(f"[{request_id}] Authentication error in result - should trigger re-auth flow")
            
            logger.info(f"[{request_id}] Creating JSON response")
            response_data = {'result': result}
            response = jsonify(response_data)
            logger.info(f"[{request_id}] JSON response created: {len(str(result))} chars")
            logger.info(f"[{request_id}] Response data keys: {list(response_data.keys())}")
            logger.info(f"[{request_id}] Request completed successfully, returning response to Flask")
            
            # Force flush logs to ensure we see this
            import sys
            sys.stdout.flush()
            
            return response
            
        except TimeoutError:
            logger.error(f"[{request_id}] Request timed out after 330 seconds")
            return jsonify({'error': 'Request timed out after 5.5 minutes'}), 408
            
    except Exception as e:
        logger.error(f"[{request_id}] Error processing request: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


def process_agent_request(request_id: str, query: str, gmailHashID: str, userIDHash: str):
    """Process agent request in isolated environment"""
    agent = None
    
    try:
        logger.info(f"[{request_id}] Getting agent from connection pool")
        
        # Get agent from connection pool
        agent = connection_pool.get_agent(userIDHash)
        
        # Prepare query with context
        generalInfo = f"Additional information: userIDHash: {userIDHash} also, when making tool calls for google-calendar-mcp, pass in the following string as an argument to the main function when starting the server: {userIDHash}"
        gmailGeneralInfo = f"More Additional information: gmailHashID: {gmailHashID} also, when making tool calls for the gmail-mcp server for email related tasks, pass in the following string as an argument to the main function when starting the server and for gmail related tool calls: {gmailHashID}"
        full_query = query + " \n " + generalInfo + " \n " + gmailGeneralInfo
        
        logger.info(f"[{request_id}] Running agent synchronously for scalability")
        
        # Run agent synchronously to avoid event loop conflicts
        result = run_agent_sync(agent, full_query, userIDHash, request_id)
        
        logger.info(f"[{request_id}] Agent execution completed, preparing to return result")
        logger.info(f"[{request_id}] Result type in process_agent_request: {type(result)}")
        logger.info(f"[{request_id}] Result preview in process_agent_request: {str(result)[:200]}...")
        
        # Return agent to pool BEFORE returning result to prevent blocking
        if agent:
            logger.info(f"[{request_id}] Returning agent to connection pool")
            try:
                connection_pool.return_agent(userIDHash)
                logger.info(f"[{request_id}] Agent returned to pool successfully")
            except Exception as pool_error:
                logger.warning(f"[{request_id}] Error returning agent to pool: {pool_error}")
        
        logger.info(f"[{request_id}] Returning result to Flask from process_agent_request")
        return result
        
    except Exception as e:
        logger.error(f"[{request_id}] Error in agent processing: {e}", exc_info=True)
        # Return agent to pool even on error
        if agent:
            try:
                logger.info(f"[{request_id}] Returning agent to pool after error")
                connection_pool.return_agent(userIDHash)
            except Exception as pool_error:
                logger.warning(f"[{request_id}] Error returning agent to pool after error: {pool_error}")
        raise


# Global shared event loop for all agent operations
_shared_loop = None
_loop_thread = None

def get_shared_event_loop():
    """Get or create the shared event loop"""
    global _shared_loop, _loop_thread
    
    if _shared_loop is None or _shared_loop.is_closed():
        import threading
        
        def run_event_loop():
            global _shared_loop
            _shared_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(_shared_loop)
            try:
                _shared_loop.run_forever()
            except Exception as e:
                logger.error(f"Shared event loop error: {e}")
            finally:
                _shared_loop.close()
        
        _loop_thread = threading.Thread(target=run_event_loop, daemon=True)
        _loop_thread.start()
        
        # Wait for loop to be ready
        import time
        while _shared_loop is None:
            time.sleep(0.01)
    
    return _shared_loop

def shutdown_shared_event_loop():
    """Gracefully shutdown the shared event loop"""
    global _shared_loop, _loop_thread
    
    if _shared_loop and not _shared_loop.is_closed():
        logger.info("Shutting down shared event loop...")
        _shared_loop.call_soon_threadsafe(_shared_loop.stop)
        
        if _loop_thread and _loop_thread.is_alive():
            _loop_thread.join(timeout=5.0)
        
        _shared_loop = None
        _loop_thread = None
        logger.info("Shared event loop shutdown complete")

def run_agent_sync(agent, full_query: str, userIDHash: str, request_id: str):
    """Run agent using shared event loop"""
    try:
        logger.info(f"[{request_id}] Using shared event loop for agent execution")
        
        # Get shared event loop
        loop = get_shared_event_loop()
        
        # Run agent execution in shared loop
        future = asyncio.run_coroutine_threadsafe(
            _agent_execution(agent, full_query, userIDHash, request_id),
            loop
        )
        
        # Wait for result with timeout and periodic progress updates
        import time
        import concurrent.futures
        start_time = time.time()
        timeout = 90   # 1.5 minute timeout - optimized for responsiveness
        
        while True:
            try:
                result = future.result(timeout=30)  # Check every 30 seconds
                logger.info(f"[{request_id}] Agent execution completed after {time.time() - start_time:.1f}s")
                return result
            except concurrent.futures.TimeoutError:
                elapsed = time.time() - start_time
                if elapsed >= timeout:
                    logger.error(f"[{request_id}] Agent execution timed out after {elapsed:.1f}s")
                    raise TimeoutError(f"Agent execution timed out after {elapsed:.1f}s")
                else:
                    logger.info(f"[{request_id}] Agent still running... {elapsed:.1f}s elapsed")
                    continue
        
    except Exception as e:
        logger.error(f"[{request_id}] Error in agent execution: {e}", exc_info=True)
        raise

async def _agent_execution(agent, full_query: str, userIDHash: str, request_id: str):
    """Internal async agent execution"""
    # Initialize if needed - check if connections are actually working
    needs_init = not hasattr(agent, '_initialized') or not agent._initialized
    
    if needs_init:
        logger.info(f"[{request_id}] Agent not initialized, initializing now...")
        await asyncio.wait_for(agent.initialize(), timeout=15.0)  # Faster initialization
        logger.info(f"[{request_id}] Agent initialized successfully")
    else:
        logger.info(f"[{request_id}] Agent already initialized, verifying connections")
        # Test if connections are still valid by testing actual MCP server connectivity
        try:
            # More comprehensive connection test - check if MCP servers respond
            if hasattr(agent, '_sessions') and agent._sessions:
                logger.info(f"[{request_id}] Testing MCP server connectivity...")
                
                # Test Gmail MCP server connection
                gmail_working = False
                calendar_working = False
                
                try:
                    # Check if Gmail session exists and is responsive
                    if 'gmail' in agent._sessions:
                        gmail_session = agent._sessions['gmail']
                        if hasattr(gmail_session, 'session_info') and gmail_session.session_info:
                            gmail_working = True
                            logger.info(f"[{request_id}] Gmail MCP server connection verified")
                        else:
                            logger.warning(f"[{request_id}] Gmail MCP server connection lost")
                    
                    # Check if Calendar session exists and is responsive  
                    if 'google-calendar' in agent._sessions:
                        calendar_session = agent._sessions['google-calendar']
                        if hasattr(calendar_session, 'session_info') and calendar_session.session_info:
                            calendar_working = True
                            logger.info(f"[{request_id}] Calendar MCP server connection verified")
                        else:
                            logger.warning(f"[{request_id}] Calendar MCP server connection lost")
                            
                except Exception as session_check_error:
                    logger.warning(f"[{request_id}] Error checking MCP sessions: {session_check_error}")
                
                # If any critical connections are down, reinitialize
                if not gmail_working or not calendar_working:
                    logger.info(f"[{request_id}] MCP server connections compromised, reinitializing...")
                    await asyncio.wait_for(agent.initialize(), timeout=15.0)  # Faster initialization
                    logger.info(f"[{request_id}] Agent reinitialized with fresh MCP connections")
                else:
                    logger.info(f"[{request_id}] All MCP server connections verified, reusing")
            else:
                logger.info(f"[{request_id}] No active sessions found, reinitializing...")
                await asyncio.wait_for(agent.initialize(), timeout=15.0)  # Faster initialization
                logger.info(f"[{request_id}] Agent reinitialized successfully")
        except Exception as e:
            logger.warning(f"[{request_id}] Connection verification failed, reinitializing: {e}")
            await asyncio.wait_for(agent.initialize(), timeout=15.0)  # Faster initialization
            logger.info(f"[{request_id}] Agent reinitialized after connection failure")
    
    # Run the agent query with extended timeout for MCP operations
    logger.info(f"[{request_id}] Starting agent execution")
    try:
        result = await asyncio.wait_for(
            agent.run(query=full_query, userHashId=userIDHash), 
            timeout=90.0   # 1.5 minute timeout for faster response cycles
        )
        
        # Log the result for debugging
        logger.info(f"[{request_id}] Agent execution completed successfully")
        logger.info(f"[{request_id}] Result type: {type(result)}")
        logger.info(f"[{request_id}] Result preview: {str(result)[:500]}...")
        
        # Check for authentication errors in the result
        if isinstance(result, str) and ("authentication expired" in result.lower() or "re-authenticate" in result.lower()):
            logger.warning(f"[{request_id}] Authentication error detected in result")
            logger.warning(f"[{request_id}] This should trigger a re-authentication flow on the client side")
        
        return result
        
    except asyncio.TimeoutError:
        logger.error(f"[{request_id}] Agent execution timed out - likely MCP server connection issue")
        # Try to gracefully handle the timeout
        raise TimeoutError("MCP server connection timeout - please check server status")
    except Exception as execution_error:
        logger.error(f"[{request_id}] Agent execution failed: {execution_error}")
        logger.error(f"[{request_id}] Error type: {type(execution_error)}")
        
        # Check if this is an MCP tool error
        if "MCP tool" in str(execution_error) or "tool call" in str(execution_error).lower():
            logger.error(f"[{request_id}] MCP tool execution error detected - connection issues")
            # Force agent reinitialization on next request
            if hasattr(agent, '_initialized'):
                agent._initialized = False
        raise execution_error


@app.route('/logout', methods=['POST'])
def logout():
    """Clear user session cookies for logout"""
    try:
        response = make_response(jsonify({
            'success': True,
            'message': 'Logged out successfully'
        }))
        
        response = clear_user_session_cookies(response)
        
        return response, 200
    except Exception as e:
        logger.error(f"Error during logout: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint for load balancers"""
    try:
        pool_stats = {
            'active_sessions': len(connection_pool.user_sessions) if hasattr(connection_pool, 'user_sessions') else 0,
            'max_pool_size': connection_pool.pool_size if hasattr(connection_pool, 'pool_size') else 50,
            'executor_active_threads': len(executor._threads) if hasattr(executor, '_threads') else 0,
            'status': 'healthy',
            'timestamp': time.time()
        }
        return jsonify(pool_stats)
    except Exception as e:
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 500


@app.route('/metrics', methods=['GET'])
def metrics():
    """Metrics endpoint for monitoring"""
    try:
        with connection_pool.pool_lock:
            user_sessions = dict(connection_pool.user_sessions) if hasattr(connection_pool, 'user_sessions') else {}
        
        metrics_data = {
            'connection_pool': {
                'active_sessions': len(user_sessions),
                'max_pool_size': connection_pool.pool_size if hasattr(connection_pool, 'pool_size') else 50,
                'max_idle_time': connection_pool.max_idle_time if hasattr(connection_pool, 'max_idle_time') else 300
            },
            'thread_pool': {
                'max_workers': executor._max_workers,
                'active_threads': len(executor._threads) if hasattr(executor, '_threads') else 0
            },
            'active_users': list(user_sessions.keys()) if user_sessions else [],
            'timestamp': time.time()
        }
        return jsonify(metrics_data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/agent-with-auth-check', methods=['POST'])
def run_agent_with_auth_check():
    """Run agent with automatic auth status checking for both Gmail and Calendar"""
    try:
        logger.info("Received request to /agent-with-auth-check endpoint")
        data = request.get_json()
        if not data or 'query' not in data:
            logger.warning("Missing query parameter in request")
            return jsonify({'error': 'Missing query parameter'}), 400
            
        query = data['query']
        logger.info(f"Processing query with auth check: {query}")
        
        # Check if the query involves Gmail
        if any(keyword in query.lower() for keyword in ['gmail', 'email', 'mail']):
            try:
                logger.info("Query involves Gmail, checking authentication status...")
                auth_status = gmail_auth_status()
                auth_data = auth_status.get_json()
                
                if auth_data.get('needs_auth', True):
                    return jsonify({
                        'service': 'gmail',
                        'needs_auth': True,
                        'message': 'Gmail authentication required. Please call /gmail-auth endpoint first.',
                        'auth_status': auth_data.get('message', 'Authentication required')
                    }), 401
                    
            except Exception as auth_check_error:
                logger.warning(f"Gmail auth check failed, proceeding anyway: {auth_check_error}")
        
        # Check if the query involves Calendar
        if any(keyword in query.lower() for keyword in ['calendar', 'event', 'meeting', 'appointment', 'schedule']):
            try:
                logger.info("Query involves Calendar, checking authentication status...")
                auth_status = calendar_auth_status()
                auth_data = auth_status.get_json()
                
                if auth_data.get('needs_auth', True):
                    return jsonify({
                        'service': 'calendar',
                        'needs_auth': True,
                        'message': 'Google Calendar authentication required. Please call /calendar-auth endpoint first.',
                        'auth_status': auth_data.get('message', 'Authentication required')
                    }), 401
                    
            except Exception as auth_check_error:
                logger.warning(f"Calendar auth check failed, proceeding anyway: {auth_check_error}")
        
        # Proceed with the original query if authentication is OK
        async def run_query():
            return await agent.run(query)
        
        result = asyncio.run(run_query())
        logger.info("Query processed successfully")
        
        return jsonify({'result': result})
        
    except Exception as e:
        logger.error(f"Error processing request: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

async def cleanup():
    global client, agent
    try:
        logger.info("Starting cleanup...")
        
        # Clean up agent first
        if agent:
            try:
                if hasattr(agent, '_initialized') and agent._initialized:
                    logger.info("Closing agent connections...")
                    await asyncio.wait_for(agent.close(), timeout=10.0)
                    logger.info("Agent connections closed successfully")
            except Exception as e:
                logger.warning(f"Error closing agent: {e}")
        
        # Clean up client
        if client:
            try:
                logger.info("Closing client connections...")
                await asyncio.wait_for(client.close(), timeout=10.0)
                logger.info("Client connections closed successfully")
            except Exception as e:
                logger.warning(f"Error closing client: {e}")
        
        logger.info("Cleanup completed successfully")
        
    except Exception as e:
        logger.error(f"Error during cleanup: {e}", exc_info=True)

async def shutdown_handler():
    """Handle graceful shutdown"""
    logger.info("Shutdown signal received, cleaning up...")
    await cleanup()
    logger.info("Cleanup completed, exiting...")

def signal_handler(signum, frame):
    """Handle shutdown signals"""
    logger.info(f"Received signal {signum}, initiating shutdown...")
    
    # Shutdown shared event loop
    shutdown_shared_event_loop()
    
    # Get the current event loop and schedule cleanup
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(shutdown_handler())
    except RuntimeError:
        # If no event loop is running, just exit
        logger.info("No event loop running, exiting immediately...")
        sys.exit(0)

def start_oauth_callback_server():
    """Start a separate server on port 3001 for OAuth callbacks"""
    from flask import Flask
    oauth_app = Flask(__name__)
    
    @oauth_app.route('/oauth2callback')
    def oauth_callback_3001():
        # Return the same beautiful authentication success page
        return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Authentication Successful</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                overflow: hidden;
            }
            
            .container {
                background: rgba(255, 255, 255, 0.95);
                backdrop-filter: blur(20px);
                border-radius: 20px;
                padding: 60px 40px;
                text-align: center;
                box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
                max-width: 500px;
                width: 90%;
                position: relative;
                animation: slideIn 0.8s ease-out;
            }
            
            .success-icon {
                width: 80px;
                height: 80px;
                background: linear-gradient(135deg, #4CAF50, #45a049);
                border-radius: 50%;
                margin: 0 auto 30px;
                display: flex;
                align-items: center;
                justify-content: center;
                animation: bounce 1s ease-out 0.3s both;
                box-shadow: 0 10px 30px rgba(76, 175, 80, 0.3);
            }
            
            .checkmark {
                color: white;
                font-size: 40px;
                font-weight: bold;
                animation: checkPop 0.5s ease-out 0.8s both;
            }
            
            h1 {
                color: #2c3e50;
                font-size: 32px;
                font-weight: 600;
                margin-bottom: 16px;
                animation: fadeInUp 0.6s ease-out 0.5s both;
            }
            
            .subtitle {
                color: #7f8c8d;
                font-size: 18px;
                margin-bottom: 30px;
                animation: fadeInUp 0.6s ease-out 0.7s both;
            }
            
            .message {
                background: linear-gradient(135deg, #f8f9fa, #e9ecef);
                border-radius: 12px;
                padding: 20px;
                margin: 30px 0;
                border-left: 4px solid #4CAF50;
                animation: fadeInUp 0.6s ease-out 0.9s both;
            }
            
            .message p {
                color: #495057;
                font-size: 16px;
                line-height: 1.5;
            }
            
            .countdown {
                display: inline-flex;
                align-items: center;
                gap: 8px;
                background: rgba(102, 126, 234, 0.1);
                color: #667eea;
                padding: 12px 20px;
                border-radius: 25px;
                font-size: 14px;
                font-weight: 500;
                margin-top: 20px;
                animation: fadeInUp 0.6s ease-out 1.1s both;
            }
            
            .countdown-circle {
                width: 20px;
                height: 20px;
                border: 2px solid #667eea;
                border-top: 2px solid transparent;
                border-radius: 50%;
                animation: spin 1s linear infinite;
            }
            
            .floating-particles {
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                pointer-events: none;
                overflow: hidden;
            }
            
            .particle {
                position: absolute;
                background: rgba(255, 255, 255, 0.6);
                border-radius: 50%;
                animation: float 6s ease-in-out infinite;
            }
            
            .particle:nth-child(1) { left: 10%; animation-delay: 0s; width: 4px; height: 4px; }
            .particle:nth-child(2) { left: 20%; animation-delay: 1s; width: 6px; height: 6px; }
            .particle:nth-child(3) { left: 30%; animation-delay: 2s; width: 3px; height: 3px; }
            .particle:nth-child(4) { left: 40%; animation-delay: 3s; width: 5px; height: 5px; }
            .particle:nth-child(5) { left: 50%; animation-delay: 4s; width: 4px; height: 4px; }
            .particle:nth-child(6) { left: 60%; animation-delay: 5s; width: 6px; height: 6px; }
            .particle:nth-child(7) { left: 70%; animation-delay: 0.5s; width: 3px; height: 3px; }
            .particle:nth-child(8) { left: 80%; animation-delay: 1.5s; width: 5px; height: 5px; }
            .particle:nth-child(9) { left: 90%; animation-delay: 2.5s; width: 4px; height: 4px; }
            
            @keyframes slideIn {
                from {
                    opacity: 0;
                    transform: translateY(50px) scale(0.9);
                }
                to {
                    opacity: 1;
                    transform: translateY(0) scale(1);
                }
            }
            
            @keyframes bounce {
                0%, 20%, 53%, 80%, 100% {
                    transform: translate3d(0, 0, 0);
                }
                40%, 43% {
                    transform: translate3d(0, -15px, 0);
                }
                70% {
                    transform: translate3d(0, -7px, 0);
                }
                90% {
                    transform: translate3d(0, -2px, 0);
                }
            }
            
            @keyframes checkPop {
                0% {
                    transform: scale(0);
                }
                50% {
                    transform: scale(1.2);
                }
                100% {
                    transform: scale(1);
                }
            }
            
            @keyframes fadeInUp {
                from {
                    opacity: 0;
                    transform: translateY(20px);
                }
                to {
                    opacity: 1;
                    transform: translateY(0);
                }
            }
            
            @keyframes spin {
                to {
                    transform: rotate(360deg);
                }
            }
            
            @keyframes float {
                0%, 100% {
                    transform: translateY(0px);
                    opacity: 0.3;
                }
                50% {
                    transform: translateY(-100vh);
                    opacity: 1;
                }
            }
            
            @media (max-width: 600px) {
                .container {
                    padding: 40px 30px;
                    margin: 20px;
                }
                
                h1 {
                    font-size: 28px;
                }
                
                .subtitle {
                    font-size: 16px;
                }
                
                .success-icon {
                    width: 70px;
                    height: 70px;
                }
                
                .checkmark {
                    font-size: 35px;
                }
            }
        </style>
    </head>
    <body>
        <div class="floating-particles">
            <div class="particle"></div>
            <div class="particle"></div>
            <div class="particle"></div>
            <div class="particle"></div>
            <div class="particle"></div>
            <div class="particle"></div>
            <div class="particle"></div>
            <div class="particle"></div>
            <div class="particle"></div>
        </div>
        
        <div class="container">
            <div class="success-icon">
                <div class="checkmark">✓</div>
            </div>
            
            <h1>Gmail Authentication Successful!</h1>
            <p class="subtitle">Your Gmail account has been connected securely</p>
            
            <div class="message">
                <p>🎉 Perfect! Your Gmail is now connected. You can close this tab and return to your application to start using Gmail features.</p>
            </div>
            
            <div class="countdown">
                <div class="countdown-circle"></div>
                <span>This window will close automatically in <span id="countdown">5</span> seconds</span>
            </div>
        </div>
        
        <script>
            // Enhanced countdown and auto-close functionality
            let countdownElement = document.getElementById('countdown');
            let timeLeft = 5;
            
            const countdownInterval = setInterval(() => {
                timeLeft--;
                countdownElement.textContent = timeLeft;
                
                if (timeLeft <= 0) {
                    clearInterval(countdownInterval);
                    
                    // Add fade out animation before closing
                    document.querySelector('.container').style.animation = 'fadeOut 0.5s ease-out forwards';
                    
                    setTimeout(() => {
                        try {
                            window.close();
                        } catch (e) {
                            // If window.close() fails (some browsers block it), show alternative message
                            document.querySelector('.container').innerHTML = `
                                <div class="success-icon">
                                    <div class="checkmark">✓</div>
                                </div>
                                <h1>You can close this tab now</h1>
                                <p class="subtitle">Gmail authentication completed successfully</p>
                            `;
                            document.querySelector('.container').style.animation = 'slideIn 0.8s ease-out';
                        }
                    }, 500);
                }
            }, 1000);
            
            // Add fadeOut animation
            const style = document.createElement('style');
            style.textContent = `
                @keyframes fadeOut {
                    to {
                        opacity: 0;
                        transform: translateY(-20px) scale(0.95);
                    }
                }
            `;
            document.head.appendChild(style);
            
            // Add click to close functionality
            document.addEventListener('click', () => {
                clearInterval(countdownInterval);
                try {
                    window.close();
                } catch (e) {
                    console.log('Cannot close window automatically');
                }
            });
            
            // Add keyboard shortcut (Escape to close)
            document.addEventListener('keydown', (e) => {
                if (e.key === 'Escape') {
                    clearInterval(countdownInterval);
                    try {
                        window.close();
                    } catch (e) {
                        console.log('Cannot close window automatically');
                    }
                }
            });
        </script>
    </body>
    </html>
    """
    
    try:
        oauth_app.run(host='0.0.0.0', port=3001, debug=False, use_reloader=False)
    except Exception as e:
        logger.error(f"Failed to start OAuth callback server on port 3001: {e}")
        # If port 3001 is busy, log the error but don't crash the main server
        logger.warning("OAuth callback server failed to start - Gmail auth may use fallback")

if __name__ == "__main__":
    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # Initialize legacy resources (for backward compatibility)
        init_resources()
        
        # Start connection pool cleanup thread
        connection_pool.start_cleanup_thread()
        logger.info("Connection pool initialized and cleanup thread started")
        
        logger.info("Starting scalable server...")
        
        # Start OAuth callback server on port 3001 in a separate thread
        oauth_thread = threading.Thread(target=start_oauth_callback_server, daemon=True)
        oauth_thread.start()
        logger.info("OAuth callback server started on port 3001")
        
        # Try to use a production WSGI server if available
        try:
            from waitress import serve
            logger.info("Using Waitress production server for high concurrency")
            serve(
                app,
                host='0.0.0.0',
                port=5001,
                threads=200,  # High thread count for concurrent requests
                connection_limit=1000,  # Connection limit
                cleanup_interval=30,  # Connection cleanup interval
                send_bytes=65536  # Buffer size
            )
        except ImportError:
            try:
                # Import for production deployment (not used in development)
                from gunicorn.app.wsgiapp import WSGIApplication  # noqa: F401
                logger.info("Using Gunicorn production server")
                # This won't work directly in this context, but shows the intent
                raise ImportError("Gunicorn requires different startup")
            except ImportError:
                logger.warning("Production servers not available, using Flask dev server")
                logger.warning("For production, install: pip install waitress")
                
                # Use Flask dev server with high thread count
                app.run(
                    host='0.0.0.0',
                    port=5001,
                    debug=False,
                    threaded=True,
                    processes=1  # Keep as 1 to avoid shared state issues
                )
            
    except Exception as e:
        logger.error(f"Fatal server error: {e}", exc_info=True)
    finally:
        # Clean up resources
        logger.info("Shutting down connection pool...")
        try:
            connection_pool.shutdown()
            executor.shutdown(wait=True)
        except Exception as pool_cleanup_error:
            logger.error(f"Error during connection pool cleanup: {pool_cleanup_error}")
        
        try:
            asyncio.run(cleanup())
        except Exception as cleanup_error:
            logger.error(f"Error during final cleanup: {cleanup_error}")
    
    logger.info("Server shutdown complete")
    sys.exit(0)
