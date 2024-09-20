export type ErrorMessage<T extends string> = T;

export type MaybePromise<T> = Promise<T> | T;
