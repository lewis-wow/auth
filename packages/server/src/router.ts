import { generateCodeVerifier, OAuth2RequestError } from 'arctic';
import { error, IttyRouter, withCookies } from 'itty-router';
import { serializeCookie } from 'oslo/cookie';
import type {
  AnyOAuthProvider,
  inferProfileFromOAuthProvider,
} from './OAuthProvider';

export type CreateAuthArgs<
  TProviders extends Record<string, AnyOAuthProvider>,
> = {
  providers: TProviders;
  basePath?: string;
  session: (
    opts: {
      [K in keyof TProviders]: {
        provider: K;
        profile: inferProfileFromOAuthProvider<TProviders[K]>;
      };
    }[keyof TProviders],
  ) => void;
};

export const createAuth = <
  TProviders extends Record<string, AnyOAuthProvider>,
>({
  providers,
  basePath = '/api/auth',
}: CreateAuthArgs<TProviders>) => {
  const router = IttyRouter();

  router.get(
    `${basePath}/signin/:provider`,
    withCookies,
    async ({ params }) => {
      if (params.provider === undefined) {
        return error(400);
      }

      if (!(params.provider in providers)) {
        return error(400);
      }

      const provider = providers[params.provider]!;
      const { url, state } = await provider.createAuthorizationURL();

      const headers = new Headers({
        'Set-Cookie': serializeCookie(provider.options.stateCookieName, state, {
          path: '/',
          secure: process.env.NODE_ENV === 'production',
          httpOnly: true,
          maxAge: 60 * 10,
          sameSite: 'lax',
        }),
        Location: url.toString(),
      });

      return new Response(null, {
        status: 302,
        headers,
      });
    },
  );

  router.get(
    `${basePath}/callback/:provider`,
    withCookies,
    async ({ params, query, cookies }) => {
      if (params.provider === undefined) {
        return error(400);
      }

      if (!(params.provider in providers)) {
        return error(400);
      }

      const provider = providers[params.provider]!;

      const code = query.code?.toString() ?? null;
      const codeVerifier = query.code_verifier?.toString() ?? null;
      const state = query.state?.toString() ?? null;
      const storedState: string | null = cookies.oauth_state ?? null;

      try {
        const user = await provider.validateAuthorizationCode({
          code,
          codeVerifier,
          state,
          storedState,
        });

        console.log({ user });

        return Response.json(user);
      } catch (e) {
        return new Response(null, {
          status: e instanceof OAuth2RequestError ? 400 : 500,
        });
      }
    },
  );

  return router;
};
