import { CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { OAuth2Client } from 'google-auth-library';
import { BaseToolHandler } from "./core/BaseToolHandler.js";
import { ListCalendarsHandler } from "./core/ListCalendarsHandler.js";
import { ListEventsHandler } from "./core/ListEventsHandler.js";
import { SearchEventsHandler } from "./core/SearchEventsHandler.js";
import { ListColorsHandler } from "./core/ListColorsHandler.js";
import { CreateEventHandler } from "./core/CreateEventHandler.js";
import { UpdateEventHandler } from "./core/UpdateEventHandler.js";
import { DeleteEventHandler } from "./core/DeleteEventHandler.js";
import { FreeBusyEventHandler } from "./core/FreeBusyEventHandler.js";
import { FileLogger } from "../auth/logger.js";

/**
 * Handles incoming tool calls, validates arguments, calls the appropriate service,
 * and formats the response.
 *
 * @param request The CallToolRequest containing tool name and arguments.
 * @param oauth2Client The authenticated OAuth2 client instance.
 * @returns A Promise resolving to the CallToolResponse.
 */
export async function handleCallTool(request: typeof CallToolRequestSchema._type, oauth2Client: OAuth2Client) {
    const { name, arguments: args } = request.params;
    const startTime = Date.now();

    const logger = new FileLogger('mcp-server.log', 'TOOL-HANDLER');
    
    logger.info(`Handling tool call: ${name}`, {
        toolName: name,
        argumentKeys: Object.keys(args || {}),
        argumentCount: Object.keys(args || {}).length
    });
    
    try {
        const handler = getHandler(name);
        logger.debug(`Handler found for tool: ${name}`, {
            handlerClass: handler.constructor.name
        });
        
        const result = await handler.runTool(args, oauth2Client);
        const duration = Date.now() - startTime;
        
        logger.info(`Tool call completed successfully: ${name}`, {
            toolName: name,
            duration: `${duration}ms`,
            success: true,
            resultType: typeof result,
            hasContent: !!(result && (result as any).content)
        });
        
        return result;
    } catch (error: unknown) {
        const duration = Date.now() - startTime;
        logger.error(`Tool call failed: ${name}`, {
            toolName: name,
            duration: `${duration}ms`,
            error: error instanceof Error ? error.message : String(error),
            stack: error instanceof Error ? error.stack : undefined,
            arguments: args
        });
        // Re-throw the error to be handled by the main server logic or error handler
        throw error;
    }
}

// records all the tool names
const handlerMap: Record<string, BaseToolHandler> = {
    "list-calendars": new ListCalendarsHandler(),
    "list-events": new ListEventsHandler(),
    "search-events": new SearchEventsHandler(),
    "list-colors": new ListColorsHandler(),
    "create-event": new CreateEventHandler(),
    "update-event": new UpdateEventHandler(),
    "delete-event": new DeleteEventHandler(),
    "get-freebusy": new FreeBusyEventHandler(),
};

function getHandler(toolName: string): BaseToolHandler {
    const logger = new FileLogger('mcp-server.log', 'TOOL-HANDLER');
    
    const handler = handlerMap[toolName];
    if (!handler) {
        logger.error(`Unknown tool requested: ${toolName}`, {
            availableTools: Object.keys(handlerMap),
            requestedTool: toolName
        });
        throw new Error(`Unknown tool: ${toolName}`);
    }
    
    logger.debug(`Handler resolved for tool: ${toolName}`, {
        handlerType: handler.constructor.name
    });
    
    return handler;
}
