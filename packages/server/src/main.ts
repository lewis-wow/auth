import { createServer } from 'node:http';
import { createServerAdapter } from '@whatwg-node/server';
import { github } from './providers/github';
import { createAuth } from './router';

const authServer = createAuth({
  providers: {
    github: github<{ id: string }>({
      clientId: process.env.GITHUB_CLIENT_ID!,
      clientSecret: process.env.GITHUB_CLIENT_SECRET!,
    }),
  },
});

const serverAdapter = createServerAdapter(authServer.fetch);

const server = createServer(serverAdapter);

server.listen(4000, () => {
  console.log(`auth server running on http://localhost:4000`);
});
