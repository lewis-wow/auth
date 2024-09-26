import { OAuth2RequestError } from 'arctic';
import type { Lucia } from 'lucia';
import type { AnyOAuthProvider } from './OAuthProvider';
import type { MaybePromise } from './types';

export type SessionFn<
  TUser extends { id: string },
  TSessionUser extends { id: string },
> = (opts: { user: TUser }) => MaybePromise<TSessionUser>;

export type AnySessionFn = SessionFn<{ id: string }, { id: string }>;

export type UserFn<
  TProfile extends object,
  TUser extends { id: string },
> = (opts: { profile: TProfile }) => MaybePromise<TUser>;

export type AnyUserFn = UserFn<object, { id: string }>;

export const createSession = async (args: {
  code: string;
  codeVerifier?: string;
  provider: AnyOAuthProvider;
  userFn: AnyUserFn;
  sessionFn: AnySessionFn;
  lucia: Lucia;
  redirectURL: string | URL;
}) => {
  try {
    const tokens = await args.provider.validateAuthorizationCode({
      code: args.code,
      codeVerifier: args.codeVerifier,
    });

    const userResponse = await fetch(args.provider.issuer, {
      headers: {
        Authorization: `Bearer ${tokens.accessToken}`,
      },
    });

    const profile: object = await userResponse.json();

    const user = await args.userFn({ profile });

    const userSession = await args.sessionFn({ user });

    const session = await args.lucia.createSession(userSession.id, userSession);
    const sessionCookie = args.lucia.createSessionCookie(session.id);

    const headers = new Headers({
      'Set-Cookie': sessionCookie.serialize(),
      Location: args.redirectURL.toString(),
    });

    return new Response(null, {
      status: 302,
      headers: headers,
    });
  } catch (error) {
    if (error instanceof OAuth2RequestError) {
      return new Response(null, {
        status: 400,
      });
    }

    return new Response(null, {
      status: 500,
    });
  }
};
