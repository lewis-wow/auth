import type { Cookie, Lucia } from 'lucia';
import { parseCookies } from 'oslo/cookie';
import type { AnyOAuthProvider } from './OAuthProvider';
import type { MaybePromise } from './types';

export type BaseSession = {
  user: {
    id: string;
  };
  expiresAt: Date;
  fresh: boolean;
  id: string;
};

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

export type SessionFactoryOptions = {
  userFn: AnyUserFn;
  sessionFn: AnySessionFn;
  lucia: Lucia;
};

export class SessionFactory {
  userFn: AnyUserFn;
  sessionFn: AnySessionFn;
  lucia: Lucia;

  constructor(options: SessionFactoryOptions) {
    this.userFn = options.userFn;
    this.sessionFn = options.sessionFn;
    this.lucia = options.lucia;
  }

  async create(args: {
    provider: AnyOAuthProvider;
    code: string;
    codeVerifier?: string;
  }): Promise<BaseSession> {
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

    const user = await this.userFn({ profile });

    const userSession = await this.sessionFn({ user });

    const session = await this.lucia.createSession(userSession.id, userSession);

    return {
      user: userSession,
      id: session.id,
      expiresAt: session.expiresAt,
      fresh: session.fresh,
    };
  }

  async destroy(session: BaseSession): Promise<Cookie> {
    await this.lucia.invalidateSession(session.id);
    const sessionCookie = this.lucia.createBlankSessionCookie();

    return sessionCookie;
  }

  async fromRequest(request: Request): Promise<BaseSession | null> {
    const authorizationHeader = request.headers.get('Authorization');
    const cookiesHeader = request.headers.get('Cookies');

    if (authorizationHeader === null && cookiesHeader === null) {
      throw new TypeError(
        `SessionFactory.fromRequest cannot read session id from null Authorization header and null Cookie header.`,
      );
    }

    if (authorizationHeader) {
      return this.fromToken(authorizationHeader);
    }

    if (cookiesHeader) {
      return this.fromCookies(cookiesHeader);
    }

    return null;
  }

  async fromToken(bearerToken: string): Promise<BaseSession | null> {
    const sessionId = this.lucia.readBearerToken(bearerToken);

    if (!sessionId) {
      throw new TypeError(
        'SessionFactory.fromToken cannot read session id from bearer token.',
      );
    }

    const { session, user } = await this.lucia.validateSession(sessionId);

    if (session === null) {
      return null;
    }

    return {
      user,
      id: session.id,
      expiresAt: session.expiresAt,
      fresh: session.fresh,
    };
  }

  async fromCookies(
    cookieStore: string | Record<string, string> | Map<string, string>,
  ) {
    const parsedCookies =
      typeof cookieStore === 'string'
        ? parseCookies(cookieStore)
        : cookieStore instanceof Map
          ? cookieStore
          : new Map(Object.entries(cookieStore));

    const sessionId = parsedCookies.get(this.lucia.sessionCookieName);

    if (!sessionId) {
      throw new TypeError(
        `SessionFactory.fromCookies cannot read session id from cookie ${this.lucia.sessionCookieName}.`,
      );
    }

    const { session, user } = await this.lucia.validateSession(sessionId);

    if (session === null) {
      return null;
    }

    return {
      user,
      id: session.id,
      expiresAt: session.expiresAt,
      fresh: session.fresh,
    };
  }
}
