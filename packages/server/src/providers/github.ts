import {
  OAuthProvider,
  type OAuthProviderArgs,
  type ProfileOverrideFunction,
} from '@/provider';
import { GitHub as ArcticGitHub } from 'arctic';

/** @see https://docs.github.com/en/rest/users/users#get-the-authenticated-user */
export type GitHubProfile = {
  login: string;
  id: number;
  node_id: string;
  avatar_url: string;
  gravatar_id: string | null;
  url: string;
  html_url: string;
  followers_url: string;
  following_url: string;
  gists_url: string;
  starred_url: string;
  subscriptions_url: string;
  organizations_url: string;
  repos_url: string;
  events_url: string;
  received_events_url: string;
  type: string;
  site_admin: boolean;
  name: string | null;
  company: string | null;
  blog: string | null;
  location: string | null;
  email: string | null;
  hireable: boolean | null;
  bio: string | null;
  twitter_username?: string | null;
  public_repos: number;
  public_gists: number;
  followers: number;
  following: number;
  created_at: string;
  updated_at: string;
  private_gists?: number;
  total_private_repos?: number;
  owned_private_repos?: number;
  disk_usage?: number;
  suspended_at?: string | null;
  collaborators?: number;
  two_factor_authentication: boolean;
  plan?: {
    collaborators: number;
    name: string;
    space: number;
    private_repos: number;
  };
  [claim: string]: unknown;
};

export function github(
  args?: OAuthProviderArgs & {
    redirectURI?: string;
    enterpriseDomain?: string;
  },
): OAuthProvider<'github', GitHubProfile>;

export function github<P extends object>(
  args: OAuthProviderArgs & {
    profile: ProfileOverrideFunction<GitHubProfile, P>;
    redirectURI?: string;
    enterpriseDomain?: string;
  },
): OAuthProvider<'github', P>;

export function github<P extends object>(
  args?: OAuthProviderArgs & {
    profile?: ProfileOverrideFunction<GitHubProfile, P>;
    redirectURI?: string;
    enterpriseDomain?: string;
  },
) {
  return new OAuthProvider({
    providerName: 'github',
    issuer: 'https://api.github.com/user',
    stateCookieName: 'github_oauth_state',
    arctic: new ArcticGitHub(
      (args?.clientId ?? process.env.GITHUB_CLIENT_ID)!,
      (args?.clientSecret ?? process.env.GITHUB_CLIENT_SECRET)!,
      args,
    ),
    pkce: false,
    ...args,
  });
}
