import {
  generateCodeVerifier,
  generateState,
  type OAuth2Provider as ArcticOAuth2Provider,
  type OAuth2ProviderWithPKCE,
} from 'arctic';
import type { MaybePromise } from './types';

export type OAuthProviderArgs = {
  clientId?: string;
  clientSecret?: string;
};

export type OAuthProviderOptions<
  TOAuthProviderName extends string,
  TOutputProfile extends object,
> = {
  providerName: TOAuthProviderName;
  issuer: string;
  stateCookieName: string;
  profile?: (opts: { profile: any }) => TOutputProfile;
} & (
  | {
      arctic: ArcticOAuth2Provider;
      pkce: false;
    }
  | {
      arctic: OAuth2ProviderWithPKCE;
      pkce: true;
    }
);

export class OAuthProvider<
  TOAuthProviderName extends string,
  TOutputProfile extends object,
> {
  constructor(
    public options: OAuthProviderOptions<TOAuthProviderName, TOutputProfile>,
  ) {}

  async createAuthorizationURL(): Promise<{
    url: URL;
    state: string;
    codeVerifier: string;
  }> {
    const state = generateState();
    const codeVerifier = generateCodeVerifier();

    const url = await this.options.arctic.createAuthorizationURL(
      state,
      this.options.pkce ? codeVerifier : (undefined as never),
    );

    return { url, state, codeVerifier };
  }

  async validateAuthorizationCode(args: {
    code: string | null;
    codeVerifier: string | null;
    state: string | null;
    storedState: string | null;
  }): Promise<unknown> {
    if (
      !args.code ||
      !args.state ||
      !args.storedState ||
      args.state !== args.storedState ||
      (this.options.pkce && !args.codeVerifier)
    ) {
      throw new Error('Invalid credentials.');
    }

    const tokens = await this.options.arctic.validateAuthorizationCode(
      args.code,
      this.options.pkce ? args.codeVerifier! : (undefined as never),
    );

    const userResponse = await fetch(this.options.issuer, {
      headers: {
        Authorization: `Bearer ${tokens.accessToken}`,
      },
    });

    const user = await userResponse.json();

    return user;
  }
}

export type AnyOAuthProvider = OAuthProvider<string, object>;

export type inferProfileFromOAuthProvider<T> =
  T extends OAuthProvider<string, infer Profile> ? Profile : never;

export type ProfileOverrideFunction<
  TProfile extends object,
  TNextProfile extends object,
> = (args: { profile: TProfile }) => MaybePromise<TNextProfile>;
