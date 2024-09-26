import {
  Lucia,
  TimeSpan,
  type Adapter,
  type SessionCookieOptions as LuciaSessionCookieOptions,
  type SessionCookieAttributesOptions,
} from 'lucia';
import type { AnyOAuthProvider } from './OAuthProvider';
import { SessionFactory, type SessionFn, type UserFn } from './SessionFactory';

export interface SessionCookieOptions extends SessionCookieAttributesOptions {
  name: LuciaSessionCookieOptions['name'];
  expires: LuciaSessionCookieOptions['expires'];
}

export type AuthOptions = {
  adapter: Adapter;
  providers: AnyOAuthProvider[];
  redirectURL: string | URL;
  sessionExpiresIn?: TimeSpan;
  cookies?: {
    session?: SessionCookieOptions;
  };
  user: UserFn<object, { id: string }>;
  session: SessionFn<{ id: string }, { id: string }>;
};

export const auth = (options: AuthOptions) => {
  const lucia = new Lucia(options.adapter, {
    sessionExpiresIn: options.sessionExpiresIn,
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

  const signIn = async (request: Request): Promise<Response> => {
    const url = new URL(request.url);

    const code = url.searchParams.get('code');
    const state = url.searchParams.get('state');
    sessionFactory.create;

    return new Response();
  };

  return {
    lucia,
    getSession,
    signOut,
    signIn,
  };
};

const { lucia, getSession, signOut, signIn } = auth({
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
