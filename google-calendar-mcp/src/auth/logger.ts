import * as fs from 'fs/promises';
import * as path from 'path';

export class FileLogger {
  private logPath: string;
  private context: string;
  
  constructor(logFileName: string, context?: string) {
    this.logPath = path.join(process.cwd(), logFileName);
    this.context = context || 'MAIN';
  }
  
  private async log(level: 'INFO' | 'ERROR' | 'DEBUG' | 'WARN' | 'REQUEST' | 'RESPONSE', message: string, metadata?: any): Promise<void> {
    const timestamp = new Date().toISOString();
    const contextInfo = this.context ? `[${this.context}]` : '';
    let logEntry = `[${timestamp}] [${level}] ${contextInfo} ${message}`;
    
    if (metadata) {
      logEntry += `\n  Metadata: ${JSON.stringify(metadata, null, 2)}`;
    }
    
    logEntry += '\n';
    
    try {
      await fs.appendFile(this.logPath, logEntry);
    } catch (error) {
      console.error(`Log write failed: ${error}`);
    }
  }
  
  async info(message: string, metadata?: any): Promise<void> {
    await this.log('INFO', message, metadata);
  }
  
  async error(message: string, metadata?: any): Promise<void> {
    await this.log('ERROR', message, metadata);
  }
  
  async debug(message: string, metadata?: any): Promise<void> {
    await this.log('DEBUG', message, metadata);
  }
  
  async warn(message: string, metadata?: any): Promise<void> {
    await this.log('WARN', message, metadata);
  }
  
  async request(message: string, requestData?: any): Promise<void> {
    await this.log('REQUEST', message, requestData);
  }
  
  async response(message: string, responseData?: any): Promise<void> {
    await this.log('RESPONSE', message, responseData);
  }
  
  async logServerStart(serverInfo: any): Promise<void> {
    await this.info('=== MCP SERVER STARTING ===', {
      timestamp: new Date().toISOString(),
      pid: process.pid,
      platform: process.platform,
      nodeVersion: process.version,
      memoryUsage: process.memoryUsage(),
      ...serverInfo
    });
  }
  
  async logServerStop(): Promise<void> {
    await this.info('=== MCP SERVER STOPPING ===', {
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      memoryUsage: process.memoryUsage()
    });
  }
  
  async logAuthAttempt(userHashID: string, success: boolean, details?: any): Promise<void> {
    const level = success ? 'INFO' : 'ERROR';
    const message = `Authentication ${success ? 'succeeded' : 'failed'} for user: ${userHashID}`;
    await this.log(level, message, details);
  }
  
  async logToolCall(toolName: string, userHashID: string, params: any, duration?: number): Promise<void> {
    await this.info(`Tool call: ${toolName}`, {
      userHashID,
      parameters: params,
      duration: duration ? `${duration}ms` : undefined
    });
  }
  
  async logError(error: Error, context?: string, additionalData?: any): Promise<void> {
    await this.error(`${context ? `[${context}] ` : ''}${error.message}`, {
      name: error.name,
      stack: error.stack,
      ...additionalData
    });
  }
} 