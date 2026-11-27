export class WalletError extends Error {
  /** `detail` is the message without its code, for an error that adds a next step to another one. */
  constructor(readonly code: string, readonly detail: string) { super(`${code}: ${detail}`); }
}

/**
 * The configured RPCs answered differently, for example one lags behind the others. It refuses a spend like any
 * validation failure, but it says nothing about the wallet, so a recheck can treat it as an RPC outage.
 */
export class RpcDisagreementError extends WalletError {
  constructor(detail: string) { super("validation_failed", detail); }
}
