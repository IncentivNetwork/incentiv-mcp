import { canonicalJson, configurationId, parseConfig, type Config } from "./config.js";
import { NetworkError } from "./network.js";

// Only the reproduced September 2026 implementation is eligible for this transition.
export const PREVIOUS_ACCOUNT_NETWORK_ID = "0xd2710c6ff1e86a0c66fb2274612b5f8b770e7b4956cd59ca70b7edc328b11d49";
export const CURRENT_ACCOUNT_NETWORK_ID = "0xf7beea402d23219daa3790b6685ca14119813c0b802ff570696836bdda260101";

export function previousImplementationConfig(config: Config): Config {
  const previous = parseConfig(config);
  if (previous.identity.networkId !== CURRENT_ACCOUNT_NETWORK_ID) throw new NetworkError("wallet_network_mismatch", "No reviewed implementation upgrade exists for this network identity");
  previous.identity.accountImplementation = {
    address: "0x43fb62a71d0Ce27FD6AB70347A438d67eC2DFC6C",
    codeHash: "0x5efcc9dcde58e749aed6800567d5f730366970b6a3fd89e3372fb9566a4316d3",
  };
  previous.identity.accountVersion = "incentiv-account-beacon-v1";
  previous.identity.networkId = configurationId(previous.identity, "networkId");
  if (previous.identity.networkId !== PREVIOUS_ACCOUNT_NETWORK_ID) throw new NetworkError("wallet_network_mismatch", "Implementation upgrade would change account derivation or another identity field");
  previous.manifest.networkId = previous.identity.networkId;
  previous.manifest.manifestId = configurationId(previous.manifest, "manifestId");
  return parseConfig(previous);
}

export function assertImplementationUpgrade(previous: Config, proposed: Config): void {
  const expected = previousImplementationConfig(proposed), actual = parseConfig(previous);
  if (canonicalJson(actual.identity) !== canonicalJson(expected.identity) || canonicalJson(actual.manifest) !== canonicalJson(expected.manifest) || actual.accountCreationCode !== expected.accountCreationCode) {
    throw new NetworkError("wallet_network_mismatch", "Implementation upgrade cannot change capabilities, derivation or an unrelated network identity");
  }
}
