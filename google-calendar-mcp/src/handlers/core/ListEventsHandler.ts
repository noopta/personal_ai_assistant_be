import { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { OAuth2Client } from "google-auth-library";
import { ListEventsArgumentsSchema } from "../../schemas/validators.js";
import { BaseToolHandler } from "./BaseToolHandler.js";
import { google, calendar_v3 } from 'googleapis';
import { z } from 'zod';
import { formatEventList } from "../utils.js";

export class ListEventsHandler extends BaseToolHandler {
    async runTool(args: any, oauth2Client: OAuth2Client): Promise<CallToolResult> {
        this.logger.info('ListEvents tool execution started', {
            rawArgs: args,
            hasOAuth2Client: !!oauth2Client
        });
        
        try {
            const validArgs = ListEventsArgumentsSchema.parse(args);
            this.logger.debug('Arguments validated successfully', validArgs);
            
            const events = await this.listEvents(oauth2Client, validArgs);
            
            this.logger.info('Events retrieved successfully', {
                eventCount: events.length,
                calendarId: validArgs.calendarId,
                timeRange: {
                    from: validArgs.timeMin,
                    to: validArgs.timeMax
                }
            });
            
            const formattedText = formatEventList(events);
            
            return {
                content: [{
                    type: "text",
                    text: formattedText,
                }],
            };
        } catch (error) {
            this.logger.error('ListEvents tool execution failed', {
                error: error instanceof Error ? error.message : String(error),
                args
            });
            throw error;
        }
    }

    private async listEvents(
        client: OAuth2Client,
        args: z.infer<typeof ListEventsArgumentsSchema>
    ): Promise<calendar_v3.Schema$Event[]> {
        this.logger.debug('Making Google Calendar API request', {
            calendarId: args.calendarId,
            timeMin: args.timeMin,
            timeMax: args.timeMax,
            singleEvents: true,
            orderBy: 'startTime'
        });
        
        try {
            const calendar = this.getCalendar(client);
            const response = await calendar.events.list({
                calendarId: args.calendarId,
                timeMin: args.timeMin,
                timeMax: args.timeMax,
                singleEvents: true,
                orderBy: 'startTime',
            });
            
            const events = response.data.items || [];
            this.logger.debug('Google Calendar API response received', {
                itemCount: events.length,
                hasNextPageToken: !!response.data.nextPageToken
            });
            
            return events;
        } catch (error) {
            this.logger.error('Google Calendar API request failed', {
                calendarId: args.calendarId,
                error: error instanceof Error ? error.message : String(error)
            });
            throw this.handleGoogleApiError(error);
        }
    }
}
