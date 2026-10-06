import {
  createServer,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { openAccounts } from "./accounts.js";
import { readFileSync } from "node:fs";
export type AppConfig = {
  origin: string;
  port: number;
  runtimeManagement: string;
  runtimeToken: string;
  issuer: string;
  verifierDid: string;
  institution: string;
  database: string;
  listenHost?: "127.0.0.1" | "0.0.0.0";
};
type Profile = "education_sign_in" | "education_eligibility";
type Interaction = {
  id: string;
  profile: Profile;
  sessionId: string;
  capability: string;
  expiresAt: number;
  phase: "pending" | "consuming" | "consumed";
};
type Browser = {
  creating: number;
  csrf: string;
  expiresAt: number;
  accountId?: string;
  retired?: boolean;
  interactions: Map<string, Interaction>;
};
class Refusal extends Error {
  constructor(
    readonly code: string,
    readonly status = 400,
  ) {
    super(code);
  }
}
const random = () => randomBytes(32).toString("base64url");
const paths = (profile: Profile) =>
  [
    "enrolled",
    "institution_id",
    ...(profile === "education_sign_in" ? ["student_id"] : []),
  ].map((field) => ["credentialSubject", field]);
function equal(a: string, b: string) {
  const x = Buffer.from(a),
    y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}
function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new Refusal("RESULT_INVALID");
  return value as Record<string, unknown>;
}
async function body(req: IncomingMessage) {
  if (req.headers["content-type"] !== "application/json")
    throw new Refusal("REQUEST_BAD_REQUEST", 415);
  let bytes = 0;
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    bytes += chunk.length;
    if (bytes > 4096) throw new Refusal("REQUEST_TOO_LARGE", 413);
    chunks.push(chunk);
  }
  try {
    return object(
      JSON.parse(
        new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks)),
      ),
    );
  } catch {
    throw new Refusal("REQUEST_BAD_REQUEST");
  }
}
export async function startApplication(
  config: AppConfig,
  dependencies: { now?: () => number } = {},
) {
  const origin = new URL(config.origin),
    management = new URL(config.runtimeManagement);
  if (
    origin.protocol !== "https:" ||
    origin.origin !== config.origin ||
    management.protocol !== "http:" ||
    management.hostname !== "127.0.0.1" ||
    management.origin !== config.runtimeManagement ||
    !config.runtimeToken ||
    !config.issuer ||
    !config.verifierDid ||
    !config.institution
  )
    throw Error("application configuration invalid");
  const now = dependencies.now ?? (() => Date.now() / 1000),
    store = await openAccounts(config.database),
    browsers = new Map<string, Browser>();
  const cookie = (id: string) =>
    `__Host-education=${id}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=1800`;
  const send = (
    res: ServerResponse,
    status: number,
    value: unknown,
    session?: string,
  ) => {
    res.writeHead(status, {
      "content-type": "application/json",
      "cache-control": "no-store",
      "referrer-policy": "no-referrer",
      "x-content-type-options": "nosniff",
      ...(session ? { "set-cookie": cookie(session) } : {}),
    });
    res.end(JSON.stringify(value));
  };
  function freshBrowser() {
    if (browsers.size >= 100) throw new Refusal("BROWSER_CAPACITY", 429);
    const id = random(),
      browser: Browser = {
        creating: 0,
        csrf: random(),
        expiresAt: now() + 1800,
        interactions: new Map(),
      };
    browsers.set(id, browser);
    return { id, browser };
  }
  function currentBrowser(browser: Browser) {
    if (now() >= browser.expiresAt) throw new Refusal("BROWSER_EXPIRED", 401);
    if (browser.retired) throw new Refusal("BROWSER_RETIRED", 409);
  }
  function currentInteraction(interaction: Interaction) {
    if (now() >= interaction.expiresAt)
      throw new Refusal("INTERACTION_EXPIRED", 410);
  }
  async function runtime(path: string, value: unknown, capability?: string) {
    const response = await fetch(config.runtimeManagement + path, {
      method: "POST",
      redirect: "error",
      signal: AbortSignal.timeout(5000),
      headers: {
        authorization: "Bearer " + config.runtimeToken,
        "content-type": "application/json",
        ...(capability ? { "x-session-capability": capability } : {}),
      },
      body: JSON.stringify(value),
    });
    let size = 0;
    const chunks: Uint8Array[] = [];
    if (!response.body) throw new Refusal("RUNTIME_UNAVAILABLE", 503);
    const reader = response.body.getReader();
    try {
      while (true) {
        const { done, value: chunk } = await reader.read();
        if (done) break;
        size += chunk.length;
        if (size > 16384) throw new Refusal("RUNTIME_UNAVAILABLE", 503);
        chunks.push(chunk);
      }
    } finally {
      await reader.cancel().catch(() => {});
      reader.releaseLock();
    }
    let result;
    try {
      result = object(JSON.parse(Buffer.concat(chunks).toString("utf8")));
    } catch {
      throw new Refusal("RUNTIME_UNAVAILABLE", 503);
    }
    return { status: response.status, body: result };
  }
  function validate(result: Record<string, unknown>, interaction: Interaction) {
    if (result.interaction_id !== interaction.id)
      throw new Refusal("RESULT_INVALID");
    if (result.status !== "verified")
      throw new Refusal("VERIFICATION_REFUSED", 403);
    const evidence = object(result.evidence),
      claims = object(result.claims);
    if (
      typeof evidence.expires_at !== "number" ||
      !Number.isFinite(evidence.expires_at) ||
      now() >= evidence.expires_at
    )
      throw new Refusal("EVIDENCE_STALE", 410);
    if (
      evidence.issuer_did !== config.issuer ||
      evidence.verifier_did !== config.verifierDid ||
      evidence.credential_type !== "UniversityEducationCredential" ||
      evidence.definition_id !== "urn:credworks:education" ||
      evidence.definition_version !== "1" ||
      evidence.profile !== interaction.profile ||
      JSON.stringify(evidence.claim_paths) !==
        JSON.stringify(paths(interaction.profile)) ||
      Object.keys(claims).sort().join() !==
        paths(interaction.profile)
          .map((path) => path[1])
          .sort()
          .join()
    )
      throw new Refusal("RESULT_INVALID");
    if (claims.enrolled !== true) throw new Refusal("ENROLMENT_REQUIRED", 403);
    if (claims.institution_id !== config.institution)
      throw new Refusal("INSTITUTION_NOT_ALLOWED", 403);
    if (
      interaction.profile === "education_sign_in" &&
      (typeof claims.student_id !== "string" ||
        claims.student_id.length < 1 ||
        claims.student_id.length > 128 ||
        claims.student_id.trim() !== claims.student_id ||
        /[\x00-\x1f\x7f]/.test(claims.student_id))
    )
      throw new Refusal("STUDENT_ID_INVALID", 403);
    return { claims, deadline: evidence.expires_at };
  }
  const assetFiles: Record<string, [string, string]> = {
    "/": ["index.html", "text/html; charset=utf-8"],
    "/openapi.json": ["openapi.json", "application/json"],
    "/app.js": ["app.js", "text/javascript; charset=utf-8"],
    "/app.css": ["app.css", "text/css; charset=utf-8"],
    "/spectral.ttf": ["spectral.ttf", "font/ttf"],
    "/mono.ttf": ["mono.ttf", "font/ttf"],
    "/fonts": ["fonts.md", "text/plain; charset=utf-8"],
    "/spectral-OFL.txt": ["spectral-OFL.txt", "text/plain; charset=utf-8"],
    "/mono-OFL.txt": ["mono-OFL.txt", "text/plain; charset=utf-8"],
  };
  const assets = new Map(
    Object.entries(assetFiles).map(([route, [file, type]]) => [
      route,
      {
        type,
        bytes: readFileSync(new URL("./public/" + file, import.meta.url)),
      },
    ]),
  );
  const server = createServer(async (req, res) => {
    try {
      for (const [id, browser] of browsers)
        if (now() >= browser.expiresAt) browsers.delete(id);
      const url = new URL(req.url ?? "/", config.origin);
      if (url.search) throw new Refusal("REQUEST_BAD_REQUEST");
      const asset = assets.get(url.pathname);
      if (req.method === "GET" && asset) {
        res.writeHead(200, {
          "content-type": asset.type,
          "cache-control": "no-store",
          "referrer-policy": "no-referrer",
          "x-content-type-options": "nosniff",
          "content-security-policy":
            "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
        });
        return res.end(asset.bytes);
      }
      const raw =
        req.headers.cookie
          ?.split(";")
          .map((part) => part.trim())
          .filter((part) => part.startsWith("__Host-education=")) ?? [];
      const id =
        raw.length === 1 ? raw[0]!.slice("__Host-education=".length) : "";
      let browser = browsers.get(id);
      if (req.method === "GET" && url.pathname === "/api/session") {
        if (!browser || browser.retired) {
          const created = freshBrowser();
          return send(
            res,
            200,
            { csrf: created.browser.csrf, status: "anonymous" },
            created.id,
          );
        }
        return send(res, 200, {
          csrf: browser.csrf,
          status: browser.accountId ? "signed_in" : "anonymous",
          ...(browser.accountId ? { account_id: browser.accountId } : {}),
        });
      }
      if (req.method !== "POST") throw new Refusal("ROUTE_NOT_FOUND", 404);
      if (!browser) throw new Refusal("BROWSER_REQUIRED", 401);
      if (
        req.headers.origin !== config.origin ||
        typeof req.headers["x-csrf-token"] !== "string" ||
        !equal(browser.csrf, req.headers["x-csrf-token"])
      )
        throw new Refusal("CSRF_REFUSED", 403);
      const input = await body(req);
      if (url.pathname === "/api/interactions") {
        if (browser.retired) throw new Refusal("BROWSER_REQUIRED", 401);
        if (
          Object.keys(input).join() !== "profile" ||
          !["education_sign_in", "education_eligibility"].includes(
            String(input.profile),
          )
        )
          throw new Refusal("REQUEST_BAD_REQUEST");
        if (browser.interactions.size + browser.creating >= 5)
          throw new Refusal("INTERACTION_CAPACITY", 429);
        const interactionId = random(),
          profile = input.profile as Profile;
        browser.creating++;
        let created;
        try {
          created = await runtime("/management/sessions", {
            profile,
            interaction_id: interactionId,
            purpose:
              profile === "education_sign_in"
                ? "Sign in to this application with Education"
                : "Check eligibility without creating an account",
          });
        } finally {
          browser.creating--;
        }
        currentBrowser(browser);
        if (created.status !== 201)
          throw new Refusal("RUNTIME_UNAVAILABLE", 503);
        const value = created.body;
        if (
          value.interaction_id !== interactionId ||
          typeof value.session_id !== "string" ||
          typeof value.correlation_capability !== "string" ||
          typeof value.expires_at !== "number" ||
          !Number.isFinite(value.expires_at) ||
          value.expires_at <= now() ||
          typeof value.activation_uri !== "string" ||
          typeof value.request_uri !== "string"
        )
          throw new Refusal("RUNTIME_UNAVAILABLE", 503);
        browser.interactions.set(interactionId, {
          id: interactionId,
          profile,
          sessionId: value.session_id,
          capability: value.correlation_capability,
          expiresAt: value.expires_at + 120,
          phase: "pending",
        });
        return send(res, 201, {
          id: interactionId,
          activation_uri: value.activation_uri,
          request_uri: value.request_uri,
          expires_at: value.expires_at,
          profile,
        });
      }
      const match = /^\/api\/interactions\/([A-Za-z0-9_-]{43})\/complete$/.exec(
        url.pathname,
      );
      if (!match) throw new Refusal("ROUTE_NOT_FOUND", 404);
      if (Object.keys(input).length) throw new Refusal("REQUEST_BAD_REQUEST");
      const interaction = browser.interactions.get(match[1]!);
      if (!interaction) throw new Refusal("INTERACTION_NOT_FOUND", 404);
      if (interaction.phase !== "pending")
        throw new Refusal("INTERACTION_CONSUMED", 409);
      if (now() >= interaction.expiresAt) {
        interaction.phase = "consumed";
        throw new Refusal("INTERACTION_EXPIRED", 410);
      }
      interaction.phase = "consuming";
      let outcome;
      try {
        outcome = await runtime(
          "/management/sessions/" +
            encodeURIComponent(interaction.sessionId) +
            "/result",
          {},
          interaction.capability,
        );
      } catch {
        interaction.phase = "consumed";
        throw new Refusal("RUNTIME_UNAVAILABLE", 503);
      }
      if (
        outcome.status === 409 &&
        object(outcome.body.error).code === "RESULT_PENDING"
      ) {
        interaction.phase = "pending";
        throw new Refusal("RESULT_PENDING", 409);
      }
      interaction.phase = "consumed";
      if (outcome.status !== 200) throw new Refusal("RESULT_UNAVAILABLE", 410);
      currentBrowser(browser);
      currentInteraction(interaction);
      const verified = validate(outcome.body, interaction);
      if (interaction.profile === "education_eligibility")
        return send(res, 200, { status: "eligible" });
      const accountId = await store.account(
        config.issuer,
        verified.claims.student_id as string,
      );
      currentBrowser(browser);
      currentInteraction(interaction);
      if (now() >= verified.deadline) throw new Refusal("EVIDENCE_STALE", 410);
      const replacement = freshBrowser();
      replacement.browser.accountId = accountId;
      browser.retired = true;
      for (const pending of browser.interactions.values())
        pending.phase = "consumed";
      browser.accountId = undefined;
      return send(
        res,
        200,
        { status: "signed_in", account_id: accountId },
        replacement.id,
      );
    } catch (error) {
      const refusal =
        error instanceof Refusal
          ? error
          : new Refusal("APPLICATION_UNAVAILABLE", 503);
      if (!res.headersSent)
        send(res, refusal.status, { error: { code: refusal.code } });
      else res.destroy();
    }
  });
  server.requestTimeout = 10000;
  server.headersTimeout = 10000;
  server.timeout = 10000;
  try {
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(config.port, config.listenHost ?? "127.0.0.1", resolve);
    });
  } catch (error) {
    await store.close();
    throw error;
  }
  return {
    url: `http://127.0.0.1:${config.port}`,
    async close() {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await store.close();
    },
  };
}
