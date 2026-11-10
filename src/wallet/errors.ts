export class WalletError extends Error {
  /** `detail` is the message without its code, for an error that adds a next step to another one. */
  constructor(readonly code: string, readonly detail: string) { super(`${code}: ${detail}`); }
}
