import { type OAuth2Provider as ArcticOAuth2Provider } from 'arctic';

export type OAuth2ProviderArgs = {
  clientId: string;
  clientSecret: string;
};

export const OAuth2ProviderBrand: unique symbol = Symbol('OAuth2ProviderBrand');

export type OAuth2Provider<
  TOAuth2ProviderName extends string,
  TUserShape extends object,
> = {
  arcticProvider: ArcticOAuth2Provider;
  providerName: TOAuth2ProviderName;
  apiURL: string;
  oauthStateCookieName: string;
  __brand: typeof OAuth2ProviderBrand;
  __userShape: TUserShape;
};

export type AnyOAuth2Provider = OAuth2Provider<string, object>;

export type ErrorMessage<T extends string> = T;

export type UniqueOAuth2ProvidersArray<
  TOAuth2Providers extends unknown[],
  SeenNames extends string[] = [],
> = TOAuth2Providers extends [infer First, ...infer Rest]
  ? First extends { providerName: infer Name extends string }
    ? Name extends SeenNames[number]
      ? ErrorMessage<`Duplicate provider: ${Name}`>
      : UniqueOAuth2ProvidersArray<Rest, [...SeenNames, Name]>
    : never
  : TOAuth2Providers;
