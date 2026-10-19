export class WalletError extends Error {
  constructor(readonly code: string, message: string) { super(`${code}: ${message}`); }
}
