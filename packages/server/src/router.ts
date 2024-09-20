import { generateState, OAuth2RequestError } from 'arctic';
import { error, IttyRouter, withCookies } from 'itty-router';
import { serializeCookie } from 'oslo/cookie';
import type { AnyOAuth2Provider } from './types';

export type CreateAuthArgs<
  TProviders extends Record<string, AnyOAuth2Provider>,
> = {
  providers: TProviders;
  basePath?: string;
};

export const createAuth = <
  TProviders extends Record<string, AnyOAuth2Provider>,
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

      const state = generateState();
      const provider = providers[params.provider]!;
      const url = await provider.arcticProvider.createAuthorizationURL(state);
      const headers = new Headers({
        'Set-Cookie': serializeCookie(provider.oauthStateCookieName, state, {
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
      const state = query.state?.toString() ?? null;
      const storedState: string | null = cookies.oauth_state ?? null;

      if (!code || !state || !storedState || state !== storedState) {
        console.log(code, state, storedState);

        return error(400);
      }

      try {
        const tokens =
          await provider.arcticProvider.validateAuthorizationCode(code);
        const userResponse = await fetch(provider.apiURL, {
          headers: {
            Authorization: `Bearer ${tokens.accessToken}`,
          },
        });

        const githubUser = await userResponse.json();

        console.log({ githubUser });
      } catch (e) {
        return new Response(null, {
          status: e instanceof OAuth2RequestError ? 400 : 500,
        });
      }
    },
  );

  return router;
};
