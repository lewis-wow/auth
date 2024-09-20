import { createServer } from 'node:http';
import { createServerAdapter } from '@whatwg-node/server';
import { github } from './providers/github';
import { google } from './providers/google';
import { createAuth } from './router';

const authServer = createAuth({
  providers: {
    github: github(),
    google: google({
      redirectURI: '',
    }),
  },
  session: ({ provider, profile }) => {
    if (provider === 'github') {
      profile;
    }
  },
});

const serverAdapter = createServerAdapter(authServer.fetch);

const server = createServer(serverAdapter);

server.listen(4000, () => {
  console.log(`auth server running on http://localhost:4000`);
});
