import { OAuthProvider } from '@/OAuthProvider';
import { Google as ArcticGoogle } from 'arctic';

export type GoogleProfile = {
  aud: string;
  azp: string;
  email: string;
  email_verified: boolean;
  exp: number;
  family_name?: string;
  given_name: string;
  hd?: string;
  iat: number;
  iss: string;
  jti?: string;
  locale?: string;
  name: string;
  nbf?: number;
  picture: string;
  sub: string;
} & Record<string, unknown>;

export type GoogleOptions = {
  clientId?: string;
  clientSecret?: string;
  redirectURI: string;
};

export class Google extends OAuthProvider<GoogleProfile> {
  constructor(options: GoogleOptions) {
    super({
      issuer: 'https://accounts.google.com',
      stateCookieName: 'google_oauth_state',
      arctic: {
        provider: new ArcticGoogle(
          (options?.clientId ?? process.env.GITHUB_CLIENT_ID)!,
          (options?.clientSecret ?? process.env.GITHUB_CLIENT_SECRET)!,
          options.redirectURI,
        ),
        pkce: true,
      },
    });
  }
}
