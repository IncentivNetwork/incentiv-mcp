import { BaseError, BlockNotFoundError, ContractFunctionRevertedError, ContractFunctionZeroDataError, HttpRequestError, InternalRpcError, InvalidInputRpcError, LimitExceededRpcError, ResourceUnavailableRpcError, TimeoutError } from "viem";

/**
 * The contract itself refused the call. viem also reports a node's -32603 internal error as a revert, which says nothing
 * about the contract. Some nodes report a revert without data as -32000 "execution reverted", which viem does not decode.
 */
export function isContractRejection(error: unknown): boolean {
  if (!(error instanceof BaseError)) return false;
  if (error.walk(cause => cause instanceof ContractFunctionZeroDataError || (cause instanceof InvalidInputRpcError && /revert/i.test(cause.message)))) return true;
  const reverted = error.walk(cause => cause instanceof ContractFunctionRevertedError) as ContractFunctionRevertedError | null;
  if (!reverted) return false;
  return !error.walk(cause => cause instanceof InternalRpcError) || !!reverted.data || !!reverted.signature || /revert/i.test(reverted.reason ?? "");
}
/** The RPC failed to answer, so the call may succeed on retry. */
export function isTransportFailure(error: unknown): boolean {
  // Some nodes report contract reverts as -32603; an answer from the contract is never retryable.
  if (!(error instanceof BaseError) || isContractRejection(error)) return false;
  // A lagging node behind a load-balanced URL misses the pinned block, or answers -32000 ("header not found",
  // "missing trie node"), as the pin verification transport also retries. Some nodes use -32000 for a revert without data.
  return !!error.walk(cause => cause instanceof InvalidInputRpcError ? !/revert/i.test(cause.message)
    : [HttpRequestError, TimeoutError, InternalRpcError, LimitExceededRpcError, ResourceUnavailableRpcError, BlockNotFoundError].some(type => cause instanceof type));
}
