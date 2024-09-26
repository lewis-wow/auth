import {
  generateCodeVerifier,
  generateState,
  type OAuth2Provider as ArcticOAuth2Provider,
  type OAuth2ProviderWithPKCE,
  type Tokens,
} from 'arctic';

export type OAuthProviderArgs = {
  clientId?: string;
  clientSecret?: string;
};

export type ArcticOptions =
  | {
      provider: ArcticOAuth2Provider;
      pkce: false;
    }
  | {
      provider: OAuth2ProviderWithPKCE;
      pkce: true;
    };

export type OAuthProviderOptions = {
  id?: string;
  issuer: string;
  stateCookieName: string;
  arctic: ArcticOptions;
};

export class OAuthProvider<TProfile extends object> {
  id?: string;
  issuer: string;
  stateCookieName: string;
  arctic: ArcticOptions;

  constructor(public options: OAuthProviderOptions) {
    this.id = options.id;
    this.issuer = options.issuer;
    this.stateCookieName = options.stateCookieName;
    this.arctic = options.arctic;
  }

  async createAuthorizationURL(): Promise<{
    url: URL;
    state: string;
    codeVerifier: string;
  }> {
    const state = generateState();
    const codeVerifier = generateCodeVerifier();

    const url = await this.arctic.provider.createAuthorizationURL(
      state,
      this.arctic.pkce ? codeVerifier : (undefined as never),
    );

    return { url, state, codeVerifier };
  }

  async validateAuthorizationCode(args: {
    code: string;
    codeVerifier?: string;
  }): Promise<Tokens> {
    if (this.arctic.pkce && !args.codeVerifier) {
      throw new Error(
        'OAuthProvider.validateAuthorizationCode code verifier cannot be empty when using pkce provider.',
      );
    }

    const tokens = await this.arctic.provider.validateAuthorizationCode(
      args.code,
      this.arctic.pkce ? args.codeVerifier! : (undefined as never),
    );

    return tokens;
  }
}

export type AnyOAuthProvider = OAuthProvider<object>;
