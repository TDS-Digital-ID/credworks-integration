import { validateIssuerConfig } from "./issuer-config.js";
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  readSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { createServer, type IncomingMessage, type Server } from "node:http";
import { timingSafeEqual } from "node:crypto";
import {
  buildDidWebDocument,
  didWebFromHost,
  persistentSigningKey,
  signCompactJwsJson,
  type PublicJwk,
} from "@unsw-vc/identity-core-node";

import {
  EvidenceCache,
  VerificationError,
  validateVerifierConfig,
  type VerifierConfig,
  type EvidenceFetcher,
} from "./evidence-cache.js";
import { Issuer, IssuerProtocolFailure, type IssuerConfig } from "./issuer.js";
import { Sessions } from "./sessions.js";
import { readPrivate } from "./revocation-proofs.js";

export type RuntimeConfig = {
  verifier?: VerifierConfig;
  issuer?: IssuerConfig;
  origin: string;
  stateDir: string;
  unlockKey: string;
  managementToken: string;
  publicPort: number;
  managementPort: number;
};
export function configFromEnv(env = process.env): RuntimeConfig {
  const required = (name: string) => {
    const value = env[name];
    if (!value) throw Error("invalid runtime configuration");
    return value;
  };
  const url = new URL(required("PARTNER_ORIGIN"));
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.pathname !== "/" ||
    url.search ||
    url.hash
  )
    throw Error("PARTNER_ORIGIN must be an HTTPS origin");
  const port = (name: string, fallback: number) => {
    const value = env[name] ?? String(fallback);
    if (!/^\d+$/.test(value) || Number(value) > 65535)
      throw Error("invalid runtime port");
    return Number(value);
  };
  const unlockKey = required("PARTNER_UNLOCK_KEY");
  if (!/^[A-Za-z0-9_-]{43}$/.test(unlockKey))
    throw Error(
      "unlock key must be 32 random bytes encoded as unpadded base64url",
    );
  const managementToken = required("PARTNER_MANAGEMENT_TOKEN");
  if (
    Buffer.byteLength(managementToken) < 32 ||
    Buffer.byteLength(managementToken) > 256
  )
    throw Error("management token must contain 32 to 256 bytes");
  return {
    issuer: env.PARTNER_ISSUER_CONFIG
      ? readIssuerConfig(env.PARTNER_ISSUER_CONFIG)
      : undefined,
    verifier: env.PARTNER_VERIFIER_CONFIG
      ? readVerifierConfig(env.PARTNER_VERIFIER_CONFIG)
      : undefined,
    origin: url.origin,
    stateDir: required("PARTNER_STATE_DIR"),
    unlockKey,
    managementToken,
    publicPort: port("PARTNER_PUBLIC_PORT", 3080),
    managementPort: port("PARTNER_MANAGEMENT_PORT", 3081),
  };
}

function readIssuerConfig(path: string): IssuerConfig {
  return validateIssuerConfig(readConfig(path));
}
function readVerifierConfig(path: string): VerifierConfig {
  return validateVerifierConfig(readConfig(path));
}
function readConfig(path: string): unknown {
  const fd = openSync(
    path,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  try {
    const info = fstatSync(fd);
    if (!info.isFile() || info.size > 16384)
      throw Error("invalid runtime configuration file");
    const bytes = Buffer.alloc(info.size + 1);
    let size = 0;
    while (size < bytes.length) {
      const count = readSync(fd, bytes, size, bytes.length - size, null);
      if (count === 0) break;
      size += count;
    }
    if (size !== info.size) throw Error("runtime configuration file changed");
    return JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(0, size)),
    );
  } finally {
    closeSync(fd);
  }
}

export type RuntimeIdentity = {
  did: string;
  keyId: string;
  publicJwk: PublicJwk;
};
export function openIdentity(
  config: RuntimeConfig,
  bootstrap = false,
): RuntimeIdentity {
  const did = didWebFromHost(new URL(config.origin).host);
  const keyId = `${did}#key-1`;
  const manifestPath = join(config.stateDir, "identity.json");
  if (bootstrap) mkdirSync(config.stateDir, { mode: 0o700 }); // Existing or partial state must never be replaced.
  const directory = lstatSync(config.stateDir);
  if (!directory.isDirectory() || (directory.mode & 0o077) !== 0)
    throw Error("identity directory must be private (0700)");
  const manifest = bootstrap
    ? undefined
    : (JSON.parse(readPrivate(manifestPath, 65536)) as {
        version: number;
        origin: string;
        publicJwk: PublicJwk;
      });
  if (
    !bootstrap &&
    (!manifest || manifest.version !== 1 || manifest.origin !== config.origin)
  )
    throw Error("identity configuration mismatch");
  const publicJwk = persistentSigningKey({
    path: join(config.stateDir, "signing-key.sealed"),
    unlockKey: config.unlockKey,
    keyId,
    create: bootstrap,
  });
  if (
    manifest &&
    JSON.stringify(manifest.publicJwk) !== JSON.stringify(publicJwk)
  )
    throw Error("identity public key mismatch");
  if (bootstrap)
    writeFileSync(
      manifestPath,
      JSON.stringify({ version: 1, origin: config.origin, publicJwk }) + "\n",
      { mode: 0o600, flag: "wx" },
    );
  return { did, keyId, publicJwk };
}

async function textBody(
  request: IncomingMessage,
  limit: number,
): Promise<string> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const read = async () => {
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const chunk of request) {
      size += chunk.length;
      if (size > limit) throw new VerificationError("REQUEST_TOO_LARGE", 413);
      chunks.push(chunk);
    }
    return new TextDecoder("utf-8", { fatal: true }).decode(
      Buffer.concat(chunks),
    );
  };
  try {
    return await Promise.race([
      read(),
      new Promise<never>((_, reject) => {
        timer = setTimeout(
          () => reject(new VerificationError("REQUEST_DEADLINE", 408)),
          5000,
        );
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}
async function body(request: IncomingMessage): Promise<unknown> {
  return JSON.parse(await textBody(request, 4096));
}
function sendError(
  response: import("node:http").ServerResponse,
  error: unknown,
) {
  response.statusCode = error instanceof VerificationError ? error.status : 400;
  response.setHeader("content-type", "application/json");
  response.end(
    JSON.stringify({
      error: {
        code:
          error instanceof VerificationError
            ? error.code
            : "SESSION_BAD_REQUEST",
      },
    }),
    () => response.req.destroy(),
  );
}
function listen(server: Server, port: number, host: string): Promise<string> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      server.off("error", reject);
      const address = server.address();
      if (!address || typeof address === "string")
        return reject(Error("listen failed"));
      resolve(`http://127.0.0.1:${address.port}`);
    });
  });
}
export async function startRuntime(
  config: RuntimeConfig,
  identity: RuntimeIdentity,
  dependencies: { clock?: () => number; fetchEvidence?: EvidenceFetcher } = {},
) {
  config = structuredClone(config);
  if (config.issuer) config.issuer = validateIssuerConfig(config.issuer);
  identity = structuredClone(identity);
  const clock = dependencies.clock ?? (() => Math.floor(Date.now() / 1000));
  const cache = config.verifier
    ? new EvidenceCache(
        config.verifier,
        identity,
        clock,
        dependencies.fetchEvidence,
        config.stateDir,
      )
    : undefined;
  if (cache) await cache.refresh();
  const sessions = cache
    ? new Sessions(config.origin, identity, cache, clock)
    : undefined;
  const issuer = config.issuer
    ? new Issuer(
        config.issuer,
        config.origin,
        identity,
        clock,
        dependencies.fetchEvidence,
        sessions ? (binding) => sessions.validateBinding(binding) : undefined,
        { stateDir: config.stateDir, unlockKey: config.unlockKey },
      )
    : undefined;
  if (issuer) {
    try {
      await issuer.start();
    } catch (error) {
      await issuer.state.close();
      throw error;
    }
  }
  const document = buildDidWebDocument(identity.did, [identity.publicJwk]);
  const publicServer = createServer(async (request, response) => {
    response.setHeader("cache-control", "no-store");
    response.setHeader("referrer-policy", "no-referrer");
    if (issuer && request.url?.startsWith("/partner-renewals/")) {
      try {
        const url = new URL(request.url, "http://runtime.invalid");
        const match = /^\/partner-renewals\/([A-Za-z0-9_-]{22})$/.exec(
          url.pathname,
        );
        const authorize =
          /^\/partner-renewals\/([A-Za-z0-9_-]{22})\/authorize$/.exec(
            url.pathname,
          );
        const action =
          /^\/partner-renewals\/([A-Za-z0-9_-]{22})\/(status|cancel)$/.exec(
            url.pathname,
          );
        const confirm =
          /^\/partner-renewals\/([A-Za-z0-9_-]{22})\/receipts\/([A-Za-z0-9_-]{43})\/successors\/([A-Za-z0-9_-]{22})\/confirm$/.exec(
            url.pathname,
          );
        let result: unknown;
        if (request.method === "GET" && match)
          result = await issuer.renewalRequest(match[1]!, url.searchParams);
        else if (
          request.method === "POST" &&
          authorize &&
          !url.search &&
          request.headers["content-type"]?.split(";")[0] === "application/json"
        )
          result = await issuer.authorizeRenewal(
            authorize[1]!,
            JSON.parse(await textBody(request, 16384)),
          );
        else if (
          request.method === "POST" &&
          (action || confirm) &&
          !url.search &&
          request.headers["content-type"]?.split(";")[0] === "application/json"
        )
          result = await issuer.renewalOperation(
            (action ?? confirm)![1]!,
            confirm ? "confirm" : (action![2] as "cancel" | "status"),
            JSON.parse(await textBody(request, 16384)),
            confirm?.[2],
            confirm?.[3],
          );
        else throw new VerificationError("ISSUER_RENEWAL_BAD_REQUEST");
        response.setHeader("content-type", "application/json");
        response.setHeader("referrer-policy", "no-referrer");
        response.end(JSON.stringify(result));
      } catch (error) {
        sendError(
          response,
          error instanceof VerificationError
            ? error
            : new VerificationError(
                error instanceof SyntaxError
                  ? "ISSUER_RENEWAL_BAD_REQUEST"
                  : "ISSUER_STATE_UNAVAILABLE",
                error instanceof SyntaxError ? 400 : 503,
              ),
        );
      }
      return;
    }
    if (issuer && request.url?.startsWith("/oid4vci/")) {
      try {
        const url = new URL(request.url, "http://runtime.invalid");
        const offerMatch = /^\/oid4vci\/offers\/([A-Za-z0-9_-]{22})$/.exec(
          url.pathname,
        );
        let result: unknown;
        if (request.method === "GET" && offerMatch)
          result = await issuer.retrieveOffer(offerMatch[1]!, url.searchParams);
        else if (
          request.method === "POST" &&
          request.url === "/oid4vci/token" &&
          request.headers["content-type"]?.split(";")[0] ===
            "application/x-www-form-urlencoded"
        )
          result = await issuer.token(
            new URLSearchParams(await textBody(request, 4096)),
          );
        else if (request.method === "POST" && request.url === "/oid4vci/nonce")
          result = await issuer.nonce();
        else if (
          request.method === "POST" &&
          request.url === "/oid4vci/credential" &&
          request.headers["content-type"]?.split(";")[0] === "application/json"
        )
          result = await issuer.credential(
            request.headers.authorization,
            JSON.parse(await textBody(request, 131072)),
          );
        else if (
          request.method === "GET" &&
          request.url === "/oid4vci/status/revocation.jwt"
        ) {
          response.setHeader("content-type", "application/statuslist+jwt");
          response.end(await issuer.status());
          return;
        } else throw new IssuerProtocolFailure("invalid_request");
        response.setHeader("content-type", "application/json");
        response.setHeader("referrer-policy", "no-referrer");
        response.end(JSON.stringify(result));
      } catch (error) {
        response.statusCode =
          error instanceof IssuerProtocolFailure ||
          error instanceof VerificationError
            ? error.status
            : error instanceof SyntaxError
              ? 400
              : 500;
        response.setHeader("content-type", "application/json");
        response.end(
          JSON.stringify({
            error:
              error instanceof IssuerProtocolFailure
                ? error.code
                : error instanceof VerificationError
                  ? error.code.toLowerCase()
                  : error instanceof SyntaxError
                    ? "invalid_request"
                    : "server_error",
          }),
        );
      }
      return;
    }
    if (
      issuer &&
      request.method === "GET" &&
      request.url === "/.well-known/oauth-authorization-server"
    ) {
      response.setHeader("content-type", "application/json");
      response.end(
        JSON.stringify({
          issuer: config.origin,
          token_endpoint: `${config.origin}/oid4vci/token`,
          grant_types_supported: [
            "urn:ietf:params:oauth:grant-type:pre-authorized_code",
          ],
          response_types_supported: [],
          token_endpoint_auth_methods_supported: ["none"],
          "pre-authorized_grant_anonymous_access_supported": true,
        }),
      );
      return;
    }
    if (
      issuer &&
      request.method === "GET" &&
      request.url === "/.well-known/openid-credential-issuer"
    ) {
      try {
        response.setHeader("content-type", "application/json");
        response.end(JSON.stringify(await issuer.metadata()));
      } catch (error) {
        sendError(response, error);
      }
      return;
    }
    const match = /^\/oid4vp\/(request|response)\/([A-Za-z0-9_-]{43})$/.exec(
      request.url ?? "",
    );
    if (sessions && match) {
      try {
        if (request.method === "GET" && match[1] === "request") {
          response.setHeader("content-type", "application/oauth-authz-req+jwt");
          response.end(sessions.request(match[2]!));
          return;
        }
        if (request.method === "POST" && match[1] === "response") {
          if (
            request.headers["content-type"]?.split(";")[0] !==
            "application/x-www-form-urlencoded"
          )
            throw new VerificationError("RESPONSE_BAD_REQUEST");
          const form = new URLSearchParams(await textBody(request, 131072));
          response.setHeader("content-type", "application/json");
          response.end(
            JSON.stringify(await sessions.complete(match[2]!, form)),
          );
          return;
        }
        throw new VerificationError("SESSION_NOT_FOUND", 404);
      } catch (error) {
        sendError(response, error);
        return;
      }
    }
    response.setHeader("content-type", "application/json");
    if (request.method === "GET" && request.url === "/.well-known/did.json") {
      try {
        const keys = await issuer?.keys?.ready();
        response.end(
          JSON.stringify(
            keys
              ? buildDidWebDocument(
                  identity.did,
                  keys.keys
                    .filter((key) => key.publicJwk)
                    .map((key) => key.publicJwk!),
                )
              : document,
          ),
        );
      } catch (error) {
        sendError(response, error);
      }
    } else {
      response.statusCode = 404;
      response.end('{"error":"not_found"}');
    }
  });
  const managementServer = createServer(async (request, response) => {
    response.setHeader("content-type", "application/json");
    response.setHeader("cache-control", "no-store");
    const expected = Buffer.from(`Bearer ${config.managementToken}`);
    const actual = Buffer.from(request.headers.authorization ?? "");
    if (
      actual.length !== expected.length ||
      !timingSafeEqual(actual, expected)
    ) {
      response.statusCode = 401;
      response.end('{"error":"unauthorized"}');
      return;
    }
    if (
      issuer &&
      (request.url === "/management/issuer/keys" ||
        /^\/management\/issuer\/keys\/(stage|proof|activate|abandon)$/.test(
          request.url ?? "",
        ))
    ) {
      try {
        const operation =
          request.url === "/management/issuer/keys"
            ? "inspect"
            : request.url!.split("/").at(-1)!;
        if (request.method !== (operation === "inspect" ? "GET" : "POST"))
          throw new VerificationError("ISSUER_KEY_BAD_REQUEST", 400);
        const input =
          operation === "inspect"
            ? undefined
            : JSON.parse(await textBody(request, 4096));
        const result = await issuer.keyManagement(operation, input);
        response.statusCode = operation === "stage" ? 201 : 200;
        response.end(JSON.stringify(result));
      } catch (error) {
        sendError(
          response,
          error instanceof VerificationError
            ? error
            : new VerificationError(
                error instanceof SyntaxError
                  ? "ISSUER_KEY_BAD_REQUEST"
                  : "ISSUER_KEY_STATE_UNAVAILABLE",
                error instanceof SyntaxError ? 400 : 503,
              ),
        );
      }
      return;
    }
    if (
      issuer &&
      request.method === "POST" &&
      request.url === "/management/issuer/renewals"
    ) {
      try {
        if (
          request.headers["content-type"]?.split(";")[0] !== "application/json"
        )
          throw new VerificationError("ISSUER_RENEWAL_BAD_REQUEST", 415);
        const correlation = request.headers["idempotency-key"];
        const result = await issuer.createRenewal(
          JSON.parse(await textBody(request, 262144)),
          typeof correlation === "string" ? correlation : undefined,
        );
        response.statusCode = 201;
        response.end(JSON.stringify(result));
      } catch (error) {
        sendError(
          response,
          error instanceof VerificationError
            ? error
            : new VerificationError(
                error instanceof SyntaxError
                  ? "ISSUER_RENEWAL_BAD_REQUEST"
                  : "ISSUER_STATE_UNAVAILABLE",
                error instanceof SyntaxError ? 400 : 503,
              ),
        );
      }
      return;
    }
    const issuanceStatus =
      /^\/management\/issuer\/issuances\/([A-Za-z0-9_-]{22})\/status$/.exec(
        request.url ?? "",
      );
    if (
      issuer &&
      issuanceStatus &&
      ["GET", "POST"].includes(request.method ?? "")
    ) {
      try {
        let input: unknown;
        if (request.method === "POST") {
          if (
            request.headers["content-type"]?.split(";")[0] !==
            "application/json"
          )
            throw new VerificationError("ISSUER_STATUS_BAD_REQUEST", 415);
          input = JSON.parse(await textBody(request, 1024));
        }
        response.end(
          JSON.stringify(
            await issuer.issuanceStatus(issuanceStatus[1]!, input),
          ),
        );
      } catch (error) {
        sendError(
          response,
          error instanceof VerificationError
            ? error
            : new VerificationError(
                error instanceof SyntaxError
                  ? "ISSUER_STATUS_BAD_REQUEST"
                  : "ISSUER_STATE_UNAVAILABLE",
                error instanceof SyntaxError ? 400 : 503,
              ),
        );
      }
      return;
    }
    const linkedOffer =
      /^\/management\/sessions\/([A-Za-z0-9_-]{43})\/issuance-offer$/.exec(
        request.url ?? "",
      );
    if (
      issuer &&
      request.method === "POST" &&
      (request.url === "/management/issuer/offers" || (sessions && linkedOffer))
    ) {
      try {
        if (
          request.headers["content-type"]?.split(";")[0] !== "application/json"
        )
          throw new VerificationError("ISSUER_OFFER_BAD_REQUEST", 415);
        const input = JSON.parse(await textBody(request, 131072));
        const result = await issuer.createOffer(
          input,
          linkedOffer && sessions
            ? {
                sessions,
                id: linkedOffer[1]!,
                capability: request.headers["x-session-capability"],
              }
            : undefined,
        );
        response.statusCode = 201;
        response.end(JSON.stringify(result));
      } catch (error) {
        sendError(
          response,
          error instanceof VerificationError
            ? error
            : new VerificationError(
                error instanceof SyntaxError
                  ? "ISSUER_OFFER_BAD_REQUEST"
                  : "ISSUER_STATE_UNAVAILABLE",
                error instanceof SyntaxError ? 400 : 503,
              ),
        );
      }
      return;
    }
    if (
      sessions &&
      request.url?.startsWith("/management/") &&
      request.url !== "/management/sign"
    ) {
      try {
        const match =
          /^\/management\/sessions\/([A-Za-z0-9_-]{43})(\/result)?$/.exec(
            request.url,
          );
        let result: unknown;
        if (
          request.method === "POST" &&
          request.url === "/management/sessions"
        ) {
          result = sessions.create(await body(request));
          response.statusCode = 201;
        } else if (
          request.method === "POST" &&
          request.url === "/management/evidence/refresh"
        ) {
          const input = await body(request);
          if (!input || typeof input !== "object" || Object.keys(input).length)
            throw new VerificationError("SESSION_BAD_REQUEST");
          await cache!.refresh();
          result = { status: "refreshed" };
        } else if (match && request.method === "GET" && !match[2])
          result = sessions.status(
            match[1]!,
            request.headers["x-session-capability"],
          );
        else if (match && request.method === "POST" && match[2]) {
          const input = await body(request);
          if (!input || typeof input !== "object" || Object.keys(input).length)
            throw new VerificationError("SESSION_BAD_REQUEST");
          result = sessions.consume(
            match[1]!,
            request.headers["x-session-capability"],
          );
        } else throw new VerificationError("SESSION_NOT_FOUND", 404);
        response.end(JSON.stringify(result));
      } catch (error) {
        sendError(response, error);
      }
      return;
    }
    if (request.method !== "POST" || request.url !== "/management/sign") {
      response.statusCode = 404;
      response.end('{"error":"not_found"}');
      return;
    }
    try {
      const input = (await body(request)) as {
        nonce?: unknown;
        audience?: unknown;
      };
      if (
        !input ||
        typeof input !== "object" ||
        Array.isArray(input) ||
        Object.keys(input).some(
          (key) => key !== "nonce" && key !== "audience",
        ) ||
        typeof input.nonce !== "string" ||
        input.nonce.length < 8 ||
        input.nonce.length > 256
      )
        throw Error("invalid proof challenge");
      if (
        typeof input.audience !== "string" ||
        input.audience.length > 2048 ||
        new URL(input.audience).protocol !== "https:"
      )
        throw Error("invalid audience");
      const now = Math.floor(Date.now() / 1000);
      const jwt = signCompactJwsJson({
        keyId: identity.keyId,
        header: {
          alg: "ES256",
          typ: "partner-identity-proof+jwt",
          kid: identity.keyId,
        },
        payload: {
          iss: identity.did,
          aud: input.audience,
          nonce: input.nonce,
          iat: now,
          exp: now + 60,
        },
      });
      response.end(JSON.stringify({ jwt }));
    } catch {
      response.statusCode = 400;
      response.end('{"error":"invalid_request"}');
    }
  });
  for (const server of [publicServer, managementServer]) {
    server.requestTimeout = 5000;
    server.headersTimeout = 5000;
    server.timeout = 5000;
    server.maxHeadersCount = 32;
  }
  try {
    const publicAddress = await listen(
      publicServer,
      config.publicPort,
      "0.0.0.0",
    );
    const managementAddress = await listen(
      managementServer,
      config.managementPort,
      "127.0.0.1",
    );
    return {
      public: publicAddress,
      management: managementAddress,
      close: async () => {
        await Promise.all(
          [publicServer, managementServer].map(
            (server) =>
              new Promise<void>((resolve) => {
                server.close(() => resolve());
                server.closeAllConnections();
              }),
          ),
        );
        await issuer?.state.close();
      },
    };
  } catch (error) {
    publicServer.close();
    managementServer.close();
    await issuer?.state.close();
    throw error;
  }
}
