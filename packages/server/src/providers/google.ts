import {
  OAuthProvider,
  type OAuthProviderArgs,
  type ProfileOverrideFunction,
} from '@/provider';
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

export function google(
  args: OAuthProviderArgs & {
    redirectURI: string;
    enterpriseDomain?: string;
  },
): OAuthProvider<'google', GoogleProfile>;

export function google<P extends object>(
  args: OAuthProviderArgs & {
    profile: ProfileOverrideFunction<GoogleProfile, P>;
    redirectURI: string;
    enterpriseDomain?: string;
  },
): OAuthProvider<'google', P>;

export function google<P extends object>(
  args: OAuthProviderArgs & {
    profile?: ProfileOverrideFunction<GoogleProfile, P>;
    redirectURI: string;
    enterpriseDomain?: string;
  },
) {
  return new OAuthProvider({
    providerName: 'google',
    issuer: 'https://accounts.google.com',
    stateCookieName: 'google_oauth_state',
    arctic: new ArcticGoogle(
      (args?.clientId ?? process.env.GITHUB_CLIENT_ID)!,
      (args?.clientSecret ?? process.env.GITHUB_CLIENT_SECRET)!,
      args.redirectURI,
    ),
    pkce: true,
    ...args,
  });
}
