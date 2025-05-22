# Step-by-Step Guide to Test Kinde Integration

This guide walks you through setting up and testing the MCP server with Kinde authentication.

## 1. Set Up Your Kinde Account

1. Sign up for a free account at [kinde.com](https://kinde.com/)
2. Create a new business from your dashboard
3. Navigate to "Applications" in the sidebar and click "Create Application"
4. Choose "Regular Web Application"
5. Name your application (e.g., "MCP Server")
6. Click "Create Application"

## 2. Configure Your Kinde Application

1. In your newly created application, navigate to the "Configuration" tab
2. Under "Redirect URLs", add:
   ```
   http://localhost:8788/callback
   ```
   (For local testing)
3. Also add your production URL if you're deploying to Cloudflare Workers:
   ```
   https://mcp-auth0-oidc.<your-subdomain>.workers.dev/callback
   ```
4. Under "Allowed Logout URLs", add:
   ```
   http://localhost:8788
   ```
   (For local testing)
5. Save your changes
6. Note your Client ID and Client Secret from the "Keys" section

## 3. Configure API Permissions (Optional)

If you need specific permissions for your API:

1. Go to "APIs" in the sidebar and click "Create API"
2. Name your API (e.g., "Todos API")
3. Set an identifier (e.g., "todos-api") - this will be your audience value
4. Add permissions (e.g., "read:todos", "write:todos")
5. Save your changes

## 4. Configure Environment Variables

For local development:

1. Create a `.dev.vars` file in your project root with the following:
   ```
   KINDE_DOMAIN=your-business-name.kinde.com
   KINDE_CLIENT_ID=your-client-id
   KINDE_CLIENT_SECRET=your-client-secret
   KINDE_SCOPE="openid profile email offline"
   KINDE_AUDIENCE=your-api-identifier (if you created an API in step 3)
   NODE_ENV=development
   API_BASE_URL=http://localhost:8789 (or your API URL)
   ```

## 5. Update KV Namespace

1. Create a KV namespace:
   ```
   wrangler kv:namespace create "OAUTH_KV"
   ```
2. Update your wrangler.jsonc with the KV ID from the output:
   ```
   "kv_namespaces": [
     {
       "binding": "OAUTH_KV",
       "id": "<Your KV ID here>"
     }
   ]
   ```

## 6. Run the MCP Server Locally

1. Install dependencies:
   ```
   npm install
   ```
2. Start the development server:
   ```
   npm run dev
   ```
3. The server should now be running at http://localhost:8788

## 7. Test the Authentication

1. Install the MCP Inspector:
   ```
   npm install -g mcp-inspector
   ```
2. Connect to your local MCP server:
   ```
   mcp-inspector --url http://localhost:8788/sse --transport sse
   ```
3. This should open your browser and redirect you to the Kinde login page
4. Complete the authentication flow
5. Once authenticated, you should be able to use the MCP tools

## 8. Deploy to Cloudflare (Optional)

If you want to deploy to Cloudflare:

1. Set your secrets:
   ```
   wrangler secret put KINDE_DOMAIN
   wrangler secret put KINDE_CLIENT_ID
   wrangler secret put KINDE_CLIENT_SECRET
   wrangler secret put KINDE_AUDIENCE
   wrangler secret put KINDE_SCOPE
   wrangler secret put API_BASE_URL
   ```
2. Deploy your worker:
   ```
   npm run deploy
   ```
3. Test the deployed version with the Cloudflare Workers AI LLM Playground

## 9. Using With Claude Desktop

1. Open Claude Desktop
2. Go to Settings -> Developer -> Edit Config
3. Add the configuration for your MCP server:
   ```json
   {
     "mcpServers": {
       "todos": {
         "command": "npx",
         "args": [
           "mcp-remote",
           "https://mcp-auth0-oidc.<your-subdomain>.workers.dev/sse"
         ]
       }
     }
   }
   ```
4. Restart Claude Desktop
5. Authenticate when prompted
6. Try asking Claude to use one of your tools

## Troubleshooting

- **Authentication Errors**: Check that your redirect URLs are properly configured in Kinde
- **Token Errors**: Ensure your scopes and audience values match what's expected
- **Connection Issues**: Verify that your MCP server is running and accessible
- **CORS Errors**: You may need to add additional CORS headers if accessing from different origins
- **API Errors**: Make sure your API is running and accessible from the MCP server 