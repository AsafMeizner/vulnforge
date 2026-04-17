import type { Express, Request, Response } from 'express';
import { mcpTools } from './tools.js';

// Simple SSE-based MCP server implementation
// Compatible with MCP protocol over HTTP/SSE transport

export function setupMcpServer(app: Express): void {
  // SSE endpoint - clients connect here to receive MCP messages
  app.get('/mcp', (req: Request, res: Response) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.flushHeaders();

    // Send server capabilities
    const serverInfo = {
      jsonrpc: '2.0',
      method: 'notifications/initialized',
      params: {
        serverInfo: {
          name: 'vulnforge-mcp',
          version: '1.0.0',
        },
        capabilities: {
          tools: {},
        },
      },
    };

    res.write(`data: ${JSON.stringify(serverInfo)}\n\n`);

    // Keep connection alive
    const heartbeat = setInterval(() => {
      res.write(': heartbeat\n\n');
    }, 15000);

    req.on('close', () => {
      clearInterval(heartbeat);
    });
  });

  // JSON-RPC endpoint for MCP messages
  app.post('/mcp', async (req: Request, res: Response) => {
    try {
      const { jsonrpc, id, method, params } = req.body;

      if (jsonrpc !== '2.0') {
        res.status(400).json({ error: 'Expected JSON-RPC 2.0' });
        return;
      }

      let result: any;

      switch (method) {
        case 'initialize':
          result = {
            protocolVersion: '2024-11-05',
            serverInfo: {
              name: 'vulnforge-mcp',
              version: '1.0.0',
            },
            capabilities: {
              tools: {},
            },
          };
          break;

        case 'tools/list':
          result = {
            tools: mcpTools.map(t => ({
              name: t.name,
              description: t.description,
              inputSchema: t.inputSchema,
            })),
          };
          break;

        case 'tools/call': {
          const toolName = params?.name;
          const toolArgs = params?.arguments || {};

          const tool = mcpTools.find(t => t.name === toolName);
          if (!tool) {
            res.json({
              jsonrpc: '2.0',
              id,
              error: { code: -32601, message: `Tool not found: ${toolName}` },
            });
            return;
          }

          try {
            const toolResult = await tool.handler(toolArgs);
            result = {
              content: [
                {
                  type: 'text',
                  text: typeof toolResult === 'string' ? toolResult : JSON.stringify(toolResult, null, 2),
                },
              ],
            };
          } catch (toolErr: any) {
            result = {
              content: [
                {
                  type: 'text',
                  text: `Error: ${toolErr.message}`,
                },
              ],
              isError: true,
            };
          }
          break;
        }

        case 'ping':
          result = {};
          break;

        default:
          res.json({
            jsonrpc: '2.0',
            id,
            error: { code: -32601, message: `Method not found: ${method}` },
          });
          return;
      }

      res.json({ jsonrpc: '2.0', id, result });
    } catch (err: any) {
      console.error('[MCP] Error handling request:', err.message);
      res.status(500).json({
        jsonrpc: '2.0',
        id: req.body?.id,
        error: { code: -32603, message: err.message },
      });
    }
  });

  // MCP discovery endpoint
  app.get('/mcp/tools', (_req: Request, res: Response) => {
    res.json({
      tools: mcpTools.map(t => ({
        name: t.name,
        description: t.description,
        inputSchema: t.inputSchema,
      })),
    });
  });
}
