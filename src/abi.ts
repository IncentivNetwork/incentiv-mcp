import { parseAbi } from "viem";

export const erc20Abi = parseAbi([
  "function balanceOf(address owner) view returns (uint256)",
  "function decimals() view returns (uint8)",
  "function symbol() view returns (string)",
  "function name() view returns (string)",
  "function transfer(address to, uint256 amount) returns (bool)",
  "function approve(address spender, uint256 amount) returns (bool)",
  "function allowance(address owner, address spender) view returns (uint256)",
]);

export const entryPointAbi = parseAbi([
  "struct PackedUserOperation { address sender; uint256 nonce; bytes initCode; bytes callData; bytes32 accountGasLimits; uint256 preVerificationGas; bytes32 gasFees; bytes paymasterAndData; bytes signature; }",
  "function getNonce(address sender, uint192 key) view returns (uint256)",
  "function getUserOpHash(PackedUserOperation userOp) view returns (bytes32)",
  "function balanceOf(address account) view returns (uint256)",
]);

export const accountFactoryAbi = parseAbi([
  "function getAddress(address owner, bytes32[2] publicKey, uint256 salt) view returns (address)",
  "function createAccount(address owner, bytes32[2] publicKey, uint256 salt) returns (address)",
  "function isDeployedByFactory(address account) view returns (bool)",
]);

export const accountAbi = parseAbi([
  "function execute(address dest, uint256 value, bytes func)",
  "function executeBatch(address[] dest, uint256[] value, bytes[] func)",
  "function owner() view returns (address)",
]);

export const bulkBalanceReaderAbi = parseAbi([
  "function readBalances(address owner, address[] tokens) view returns (uint256[] balances)",
]);

// enum RejectionReason { APPROVED, PENDING, GLOBAL_BLACKLIST, INCOMING_BLACKLIST,
//                        INCOMING_WHITELIST, OUTGOING_BLACKLIST, OUTGOING_WHITELIST }
export const transferGateAbi = parseAbi([
  "struct ApprovalResult { uint8 reject; address tokenAddress; uint256 tokenAmount; address tokenFrom; address tokenRecipient; }",
  "function checkApproval(address target, uint256 value, bytes data) view returns (ApprovalResult result)",
  "function globalBlacklist(address account) view returns (bool)",
]);

export const TRANSFER_GATE_REASONS = [
  "APPROVED",
  "PENDING", // held in escrow until the counterparty / gate approves
  "GLOBAL_BLACKLIST",
  "INCOMING_BLACKLIST",
  "INCOMING_WHITELIST",
  "OUTGOING_BLACKLIST",
  "OUTGOING_WHITELIST",
] as const;

// Uniswap V3 QuoterV2-style quoter (declared view: executed via eth_call).
export const quoterAbi = parseAbi([
  "function factory() view returns (address)",
  "struct QuoteExactInputSingleParams { address tokenIn; address tokenOut; uint256 amountIn; uint24 fee; uint160 sqrtPriceLimitX96; }",
  "struct QuoteExactOutputSingleParams { address tokenIn; address tokenOut; uint256 amount; uint24 fee; uint160 sqrtPriceLimitX96; }",
  "function quoteExactInputSingle(QuoteExactInputSingleParams params) view returns (uint256 amountOut, uint160 sqrtPriceX96After, uint32 initializedTicksCrossed, uint256 gasEstimate)",
  "function quoteExactOutputSingle(QuoteExactOutputSingleParams params) view returns (uint256 amountIn, uint160 sqrtPriceX96After, uint32 initializedTicksCrossed, uint256 gasEstimate)",
  "function quoteExactInput(bytes path, uint256 amountIn) view returns (uint256 amountOut, uint160[] sqrtPriceX96AfterList, uint32[] initializedTicksCrossedList, uint256 gasEstimate)",
]);

// Uniswap V3 SwapRouter (V1 shape, verified by selector probe on the deployed router).
export const swapRouterAbi = parseAbi([
  "function factory() view returns (address)",
  "struct ExactInputSingleParams { address tokenIn; address tokenOut; uint24 fee; address recipient; uint256 deadline; uint256 amountIn; uint256 amountOutMinimum; uint160 sqrtPriceLimitX96; }",
  "struct ExactInputParams { bytes path; address recipient; uint256 deadline; uint256 amountIn; uint256 amountOutMinimum; }",
  "function exactInputSingle(ExactInputSingleParams params) payable returns (uint256 amountOut)",
  "function exactInput(ExactInputParams params) payable returns (uint256 amountOut)",
  "function unwrapWETH9(uint256 amountMinimum, address recipient) payable",
  "function refundETH() payable",
]);

export const dexFactoryAbi = parseAbi([
  "function getPool(address tokenA, address tokenB, uint24 fee) view returns (address)",
]);
export const dexPoolAbi = parseAbi([
  "function factory() view returns (address)",
  "function token0() view returns (address)",
  "function token1() view returns (address)",
  "function fee() view returns (uint24)",
]);

export const wcentAbi = parseAbi([
  "function deposit() payable",
  "function withdraw(uint256 amount)",
]);

export const paymasterAbi = parseAbi([
  "function quoter() view returns (address)",
  "function wcent() view returns (address)",
  "function gasEstimateCoefficient() view returns (uint256)",
  "function usdcToken() view returns (address)",
  "function usdcPoolFee() view returns (uint24)",
  "function minPaymentUsdc() view returns (uint256)",
  "function minTransactionGas() view returns (uint256)",
  "function maxVerificationGas() view returns (uint256)",
  "function getDeposit() view returns (uint256)",
]);
