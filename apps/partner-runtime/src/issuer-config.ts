import * as core from "@unsw-vc/identity-core-node";
import type { IssuerConfig } from "./issuer.js";
function exact(value: unknown, keys: string): value is Record<string, unknown> {
  return (
    !!value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).sort().join() === keys
  );
}
function publicKey(value: unknown) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).some(
      (key) => !["kty", "crv", "x", "y", "kid"].includes(key),
    )
  )
    throw Error("invalid issuer configuration");
  core.publicJwkSha256Thumbprint(value as core.PublicJwk);
}
export function validateIssuerConfig(value: unknown): IssuerConfig {
  if (
    !exact(
      value,
      "databaseUrl,definitions,registryDid,registryOrigin,trustAnchorJwk,walletProviderDid,walletProviderJwk",
    )
  )
    throw Error("invalid issuer configuration");
  const config = value as unknown as IssuerConfig;
  const registry = new URL(config.registryOrigin),
    database = new URL(config.databaseUrl);
  if (
    registry.protocol !== "https:" ||
    registry.origin !== config.registryOrigin ||
    registry.username ||
    registry.password ||
    !["postgres:", "postgresql:"].includes(database.protocol) ||
    !database.pathname.slice(1) ||
    database.hash
  )
    throw Error("invalid issuer configuration");
  if (
    new URL(core.didWebToHttpsUrl(config.registryDid)).origin !==
      registry.origin ||
    new URL(core.didWebToHttpsUrl(config.walletProviderDid)).protocol !==
      "https:"
  )
    throw Error("invalid issuer configuration");
  publicKey(config.trustAnchorJwk);
  publicKey(config.walletProviderJwk);
  if (
    !Array.isArray(config.definitions) ||
    config.definitions.length < 1 ||
    config.definitions.length > 16
  )
    throw Error("invalid issuer configuration");
  const configurations = new Set(),
    references = new Set();
  for (const entry of config.definitions) {
    if (
      !exact(
        entry,
        "authorizationId,configurationId,credentialType,definitionId,definitionVersion",
      ) ||
      typeof entry.configurationId !== "string" ||
      !/^[a-zA-Z0-9_-]{1,64}$/.test(entry.configurationId) ||
      typeof entry.authorizationId !== "string" ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(
        entry.authorizationId,
      ) ||
      configurations.has(entry.configurationId) ||
      references.has(entry.authorizationId) ||
      typeof entry.definitionId !== "string" ||
      entry.definitionId.length > 256 ||
      typeof entry.definitionVersion !== "string" ||
      !/^[A-Za-z0-9._-]{1,64}$/.test(entry.definitionVersion) ||
      typeof entry.credentialType !== "string" ||
      entry.credentialType.length > 128
    )
      throw Error("invalid issuer configuration");
    configurations.add(entry.configurationId);
    references.add(entry.authorizationId);
  }
  return config;
}
