import {
  GitHub,
  OAuth2RequestError,
  type OAuth2Provider,
  type OAuth2ProviderWithPKCE,
} from 'arctic';
import {
  Lucia,
  TimeSpan,
  type Adapter,
  type SessionCookieOptions as LuciaSessionCookieOptions,
  type SessionCookieAttributesOptions,
} from 'lucia';
import type { TimeSpanUnit } from 'oslo';
import { parseCookies } from 'oslo/cookie';
import type { MaybePromise } from './types';

export interface SessionCookieOptions extends SessionCookieAttributesOptions {
  name: LuciaSessionCookieOptions['name'];
  expires: LuciaSessionCookieOptions['expires'];
}

export type BaseSession = {
  id: string;
};

export type Session = BaseSession | null;

export type SessionFn<
  TUser extends object,
  TSession extends BaseSession,
> = (opts: { user: TUser }) => MaybePromise<TSession>;

export type AuthOptions<
  TUser extends object,
  TSession extends BaseSession,
  TAuthProviders extends ReadonlyArray<AuthProvider<BaseClass, { id: string }>>,
> = {
  adapter: Adapter;
  providers: TAuthProviders;
  sessionExpiresIn?: `${number}${TimeSpanUnit}` | TimeSpan;
  cookies?: {
    session?: SessionCookieOptions;
  };
  session: SessionFn<TUser, TSession>;
};

export class Auth<
  TUser extends object,
  TSession extends BaseSession,
  const TAuthProviders extends ReadonlyArray<
    AuthProvider<BaseClass, { id: string }>
  >,
> {
  lucia: Lucia;
  sessionFn: SessionFn<TUser, TSession>;

  constructor(options: AuthOptions<TUser, TSession, TAuthProviders>) {
    this.sessionFn = options.session;

    const timeSpanRegex = /(\d+)(ms|s|m|h|d|w)/;
    const timeSpanParsedStringOptions =
      typeof options.sessionExpiresIn === 'string'
        ? timeSpanRegex.exec(options.sessionExpiresIn)
        : undefined;

    if (timeSpanParsedStringOptions === null) {
      throw new TypeError(
        'sessionExpiresIn options was in bad format, allowed format is (\\d+)(ms|s|m|h|d|w)',
      );
    }

    const sessionExpiresIn =
      timeSpanParsedStringOptions === undefined
        ? (options.sessionExpiresIn as TimeSpan | undefined)
        : new TimeSpan(
            parseInt(timeSpanParsedStringOptions[0]),
            timeSpanParsedStringOptions[1] as TimeSpanUnit,
          );

    this.lucia = new Lucia(options.adapter, {
      sessionExpiresIn: sessionExpiresIn,
      sessionCookie: {
        expires: options?.cookies?.session?.expires ?? false,
        name: options?.cookies?.session?.name,
        attributes: {
          domain: options?.cookies?.session?.domain,
          path: options?.cookies?.session?.path,
          sameSite: options?.cookies?.session?.sameSite,
          secure:
            options?.cookies?.session?.secure ??
            process.env.NODE_ENV === 'production',
        },
      },
      getSessionAttributes: (attributes) => {
        return {};
      },
      getUserAttributes: (attributes) => {
        return {};
      },
    });
  }

  async createSession(
    args: { code: string; issuer: string; redirectURL: string | URL } & (
      | {
          provider: OAuth2Provider;
          codeVerifier?: undefined;
        }
      | {
          provider: OAuth2ProviderWithPKCE;
          codeVerifier: string;
        }
    ),
  ) {
    try {
      const tokens = await args.provider.validateAuthorizationCode(
        args.code,
        args.codeVerifier as string,
      );

      const userResponse = await fetch(args.issuer, {
        headers: {
          Authorization: `Bearer ${tokens.accessToken}`,
        },
      });

      const user = await userResponse.json();

      const userSession = await this.sessionFn({ user });

      const session = await this.lucia.createSession(
        userSession.id,
        userSession,
      );
      const sessionCookie = this.lucia.createSessionCookie(session.id);

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
  }

  async getServerSession(
    req: Request,
  ): Promise<
    { user: TUser; session: TSession } | { user: null; session: null }
  > {
    const requestCookies = req.headers.get('cookies');
    const cookies = requestCookies ? parseCookies(requestCookies) : undefined;

    const sessionId = cookies?.get(this.lucia.sessionCookieName);

    if (!sessionId) {
      return { user: null, session: null };
    }

    const result = await this.lucia.validateSession(sessionId);

    // next.js throws when you attempt to set cookie when rendering page
    let headers = new Headers();

    try {
      if (result.session && result.session.fresh) {
        const sessionCookie = this.lucia.createSessionCookie(result.session.id);

        headers.set('Set-Cookie', sessionCookie.serialize());
      }

      if (!result.session) {
        const sessionCookie = this.lucia.createBlankSessionCookie();

        headers.set('Set-Cookie', sessionCookie.serialize());
      }
    } catch {}

    return result as any;
  }

  async logout(args: { session: Session; redirectURL: URL | string }) {
    if (!args.session) {
      throw new TypeError('Session was null in logout.');
    }

    await this.lucia.invalidateSession(args.session.id);
    const sessionCookie = this.lucia.createBlankSessionCookie();

    const headers = new Headers({
      'Set-Cookie': sessionCookie.serialize(),
      Location: args.redirectURL.toString(),
    });

    return new Response(null, {
      status: 302,
      headers: headers,
    });
  }
}

export class AuthBuilder<TUser extends object> {
  create<
    TSession extends BaseSession,
    const TAuthProviders extends ReadonlyArray<
      AuthProvider<BaseClass, { id: string }>
    >,
  >(options: AuthOptions<TUser, TSession, TAuthProviders>) {
    return new Auth<TUser, TSession, TAuthProviders>(options);
  }
}

type BaseClass =
  | {
      new (...args: any[]): OAuth2Provider;
    }
  | {
      new (...args: any[]): OAuth2ProviderWithPKCE;
    };

class AuthProvider<T extends BaseClass, const TOptions extends { id: string }> {
  id: TOptions['id'];
  arctic: OAuth2Provider | OAuth2ProviderWithPKCE;

  constructor(
    arctic: T,
    options: TOptions & {
      name?: string;
      clientId?: string;
      clientSecret?: string;
    } & (ConstructorParameters<T>[2] extends undefined
        ? {}
        : ConstructorParameters<T>[2]),
  ) {
    const clientId =
      options.clientId ??
      process.env[`${(options.name ?? arctic.name).toUpperCase()}_CLIENT_ID`]!;

    const clientSecret =
      options.clientId ??
      process.env[
        `${(options.name ?? arctic.name).toUpperCase()}_CLIENT_SECRET`
      ]!;

    this.id = options.id;
    this.arctic = new arctic(clientId, clientSecret, options);
  }
}

const provider = new AuthProvider(GitHub, { id: 'github' });

const auth = new AuthBuilder<{ id: string }>().create({
  adapter: {} as any,
  providers: [provider],
  session: ({ user }) => {
    return {
      id: user.id,
    };
  },
});
