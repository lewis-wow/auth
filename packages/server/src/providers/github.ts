import {
  OAuth2ProviderBrand,
  type OAuth2Provider,
  type OAuth2ProviderArgs,
} from '@/types';
import { GitHub } from 'arctic';

export type GithubProviderArgs = OAuth2ProviderArgs & {
  redirectURI?: string;
  enterpriseDomain?: string;
};

export const github = <TUserShape extends object = {}>({
  clientId,
  clientSecret,
  redirectURI,
  enterpriseDomain,
}: GithubProviderArgs): OAuth2Provider<'github', TUserShape> => {
  const arcticProvider = new GitHub(clientId, clientSecret, {
    redirectURI,
    enterpriseDomain,
  });

  return {
    arcticProvider,
    providerName: 'github',
    apiURL: 'https://api.github.com/user',
    oauthStateCookieName: 'github_oauth_state',
    __brand: OAuth2ProviderBrand,
    __userShape: {} as TUserShape,
  };
};
