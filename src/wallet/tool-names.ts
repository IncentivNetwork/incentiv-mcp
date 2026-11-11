/**
 * The local wallet's tools, in registration order. registerWalletTools must register exactly these (a test
 * checks it), and the docs derive the wallet group, list and count from them.
 */
export const WALLET_TOOL_NAMES: readonly string[] = ["create_agent_wallet", "get_agent_wallet", "send_transfer", "send_swap", "get_agent_operation", "get_agent_registry_status", "prepare_agent_link", "sign_agent_link", "link_agent", "unlink_agent"];
