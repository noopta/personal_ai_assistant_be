import { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { OAuth2Client } from "google-auth-library";
import { GaxiosError } from 'gaxios';
import { calendar_v3, google } from "googleapis";
import { FileLogger } from "../../auth/logger.js";


export abstract class BaseToolHandler {
    protected logger: FileLogger;
    
    constructor() {
        this.logger = new FileLogger('mcp-server.log', `TOOL-${this.constructor.name.toUpperCase()}`);
    }
    
    abstract runTool(args: any, oauth2Client: OAuth2Client): Promise<CallToolResult>;

    protected handleGoogleApiError(error: unknown): void {
        this.logger.error(`Google API error occurred`, {
            errorType: error instanceof GaxiosError ? 'GaxiosError' : typeof error,
            errorCode: error instanceof GaxiosError ? error.response?.data?.error : 'unknown',
            errorMessage: error instanceof Error ? error.message : String(error),
            statusCode: error instanceof GaxiosError ? error.response?.status : undefined
        });
        
        if (
            error instanceof GaxiosError &&
            error.response?.data?.error === 'invalid_grant'
        ) {
            throw new Error(
                'Google API Error: Authentication token is invalid or expired. Please re-run the authentication process (e.g., `npm run auth`).'
            );
        }
        throw error;
    }

    protected getCalendar(auth: OAuth2Client): calendar_v3.Calendar {
        this.logger.debug(`Creating Google Calendar API instance`);
        return google.calendar({ version: 'v3', auth });
    }
}
