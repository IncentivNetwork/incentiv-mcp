import { isTransportFailure } from "../agent-registry.js";
import { BundlerUnavailableError } from "../userop.js";
import { RpcDisagreementError, WalletError } from "./errors.js";

/**
 * An RPC or bundler that could not answer, or configured RPCs that disagree, as rpc_unavailable: neither says
 * anything about the wallet or the request. Any other error is returned unchanged.
 */
export const rpcOutage = (error: unknown) => error instanceof RpcDisagreementError || (!(error instanceof WalletError) && (isTransportFailure(error) || error instanceof BundlerUnavailableError))
  ? new WalletError("rpc_unavailable", "Could not read chain state from RPC; retry this request") : error;
