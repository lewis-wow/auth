import {
  Lucia,
  TimeSpan,
  type Adapter,
  type SessionCookieOptions as LuciaSessionCookieOptions,
  type SessionCookieAttributesOptions,
} from 'lucia';
import type { TimeSpanUnit } from 'oslo';
import type { UserFn } from './createSession';
import type { AnyOAuthProvider } from './OAuthProvider';
import { SessionFactory, type SessionFn } from './SessionFactory';

export interface SessionCookieOptions extends SessionCookieAttributesOptions {
  name: LuciaSessionCookieOptions['name'];
  expires: LuciaSessionCookieOptions['expires'];
}

export type AuthOptions = {
  adapter: Adapter;
  providers: AnyOAuthProvider[];
  redirectURL: string | URL;
  sessionExpiresIn?: `${number}${TimeSpanUnit}` | TimeSpan;
  cookies?: {
    session?: SessionCookieOptions;
  };
  user: UserFn<object, { id: string }>;
  session: SessionFn<{ id: string }, { id: string }>;
};

export const auth = (options: AuthOptions) => {
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

  const lucia = new Lucia(options.adapter, {
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
  });

  const sessionFactory = new SessionFactory({
    lucia,
    sessionFn: options.session,
    userFn: options.user,
  });

  const getSession = (request: Request) => sessionFactory.fromRequest(request);

  const signOut = async (request: Request): Promise<Response> => {
    const session = await getSession(request);

    if (!session) {
      return new Response();
    }

    const blankCookie = await sessionFactory.destroy(session);

    const headers = new Headers({
      'Set-Cookie': blankCookie.serialize(),
      Location: options.redirectURL.toString(),
    });

    return new Response(null, {
      status: 302,
      headers: headers,
    });
  };

  return {
    lucia,
    getSession,
    signOut,
  };
};

const { lucia, getSession, signOut } = auth({
  adapter: {} as any,
  providers: [],
  redirectURL: '',
  user: () => {
    return {
      id: '',
    };
  },
  session: ({ user }) => {
    return {
      id: user.id,
    };
  },
});
