import * as core from "@unsw-vc/identity-core-node";
import { eq } from "drizzle-orm";
import { isDeepStrictEqual } from "node:util";
import {
  closeSync,
  constants,
  existsSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  opendirSync,
  readSync,
} from "node:fs";
import { join } from "node:path";
import { issuerIdentity } from "./issuer-schema.js";
import type { IssuerState } from "./issuer-state.js";
import type { RuntimeIdentity } from "./runtime.js";
import { VerificationError } from "./evidence-cache.js";

export type CredentialKey = {
  keyId: string;
  publicJwk: core.PublicJwk | null;
  thumbprint: string | null;
  sealedHash: string | null;
  abandoned: boolean;
};
type StageRequest = {
  expected_revision: number;
  project_id: string;
  issuer_registration_id: string;
  expected_registry_revision: number;
  key_fragment: string;
};
export type CredentialKeyState = {
  version: 1;
  revision: number;
  selectedKeyId: string;
  keys: CredentialKey[];
  pending: {
    phase: "preparing" | "staged";
    keyId: string;
    request: StageRequest;
  } | null;
};
const uuid = (x: unknown) =>
  typeof x === "string" &&
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(
    x,
  );
const revision = (x: unknown): x is number =>
  Number.isInteger(x) && Number(x) >= 0 && Number(x) <= 2147483647;
export function exactKeyBody(
  x: unknown,
  fields: string,
): x is Record<string, unknown> {
  return (
    !!x &&
    typeof x === "object" &&
    !Array.isArray(x) &&
    Object.keys(x).sort().join() === fields
  );
}
function refusal(code = "ISSUER_KEY_STATE_UNAVAILABLE", status = 503): never {
  throw new VerificationError(code, status);
}
function stageRequest(x: unknown): x is StageRequest {
  return (
    exactKeyBody(
      x,
      "expected_registry_revision,expected_revision,issuer_registration_id,key_fragment,project_id",
    ) &&
    revision(x.expected_revision) &&
    revision(x.expected_registry_revision) &&
    uuid(x.project_id) &&
    uuid(x.issuer_registration_id) &&
    typeof x.key_fragment === "string" &&
    /^[A-Za-z0-9._-]{1,128}$/.test(x.key_fragment)
  );
}
export function validateCredentialKeyState(
  value: CredentialKeyState,
  identity: RuntimeIdentity,
) {
  if (
    !exactKeyBody(value, "keys,pending,revision,selectedKeyId,version") ||
    value.version !== 1 ||
    !revision(value.revision) ||
    !Array.isArray(value.keys) ||
    value.keys.length < 1 ||
    value.keys.length > 64
  )
    refusal();
  const ids = new Set();
  for (const key of value.keys) {
    if (
      !exactKeyBody(key, "abandoned,keyId,publicJwk,sealedHash,thumbprint") ||
      typeof key.keyId !== "string" ||
      !key.keyId.startsWith(identity.did + "#") ||
      !/^[A-Za-z0-9._-]{1,128}$/.test(
        key.keyId.slice(identity.did.length + 1),
      ) ||
      ids.has(key.keyId) ||
      typeof key.abandoned !== "boolean"
    )
      refusal();
    ids.add(key.keyId);
    if (key.publicJwk === null) {
      if (
        key.thumbprint !== null ||
        key.sealedHash !== null ||
        (!key.abandoned && value.pending?.keyId !== key.keyId)
      )
        refusal();
    } else {
      if (
        !key.publicJwk ||
        Object.keys(key.publicJwk).some(
          (k) => !["kty", "crv", "x", "y", "kid"].includes(k),
        ) ||
        (key.publicJwk.kid !== undefined && key.publicJwk.kid !== key.keyId) ||
        core.publicJwkSha256Thumbprint(key.publicJwk) !== key.thumbprint ||
        typeof key.sealedHash !== "string" ||
        !/^[A-Za-z0-9_-]{43}$/.test(key.sealedHash)
      )
        refusal();
    }
  }
  const bootstrap = value.keys.find((k) => k.keyId === identity.keyId),
    selected = value.keys.find((k) => k.keyId === value.selectedKeyId);
  if (
    !bootstrap ||
    bootstrap.abandoned ||
    !isDeepStrictEqual(bootstrap.publicJwk, identity.publicJwk) ||
    !selected?.publicJwk ||
    selected.abandoned
  )
    refusal();
  if (value.pending) {
    const pending = value.pending,
      key = value.keys.find((k) => k.keyId === pending.keyId);
    if (
      !exactKeyBody(pending, "keyId,phase,request") ||
      !stageRequest(pending.request) ||
      pending.keyId !== identity.did + "#" + pending.request.key_fragment ||
      !["preparing", "staged"].includes(pending.phase) ||
      !key ||
      key.abandoned ||
      key.keyId === selected.keyId ||
      (pending.phase === "staged") !== (key.publicJwk !== null)
    )
      refusal();
  }
  return value;
}
export function credentialPublicKey(
  value: CredentialKeyState | null,
  identity: RuntimeIdentity,
  keyId: string | null,
  thumbprint: string | null,
) {
  if (keyId === null || thumbprint === null) refusal();
  const key = value
    ? validateCredentialKeyState(value, identity).keys.find(
        (k) => k.keyId === keyId,
      )
    : keyId === identity.keyId
      ? {
          publicJwk: identity.publicJwk,
          thumbprint: core.publicJwkSha256Thumbprint(identity.publicJwk),
          abandoned: false,
        }
      : undefined;
  if (
    !key?.publicJwk ||
    key.abandoned ||
    thumbprint !== key.thumbprint
  )
    refusal();
  return key.publicJwk;
}
export function assertCredentialKeySelection(
  value: CredentialKeyState | null,
  identity: RuntimeIdentity,
  keyId: string | null,
  thumbprint: string | null,
) {
  const publicJwk = credentialPublicKey(value, identity, keyId, thumbprint);
  if (value?.pending) refusal("ISSUER_KEY_STAGING", 409);
  if ((keyId ?? identity.keyId) !== (value?.selectedKeyId ?? identity.keyId))
    refusal("ISSUER_KEY_SELECTION_CONFLICT", 409);
  return publicJwk;
}

export class IssuerKeys {
  constructor(
    readonly state: IssuerState,
    readonly identity: RuntimeIdentity,
    readonly directory: string,
    readonly unlockKey: string,
  ) {}
  private file(keyId: string) {
    return keyId === this.identity.keyId
      ? join(this.directory, "signing-key.sealed")
      : join(
          this.directory,
          "credential-keys",
          core.sha256B64Url(keyId) + ".sealed",
        );
  }
  private sealedHash(keyId: string) {
    const fd = openSync(
      this.file(keyId),
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    );
    try {
      const info = fstatSync(fd);
      if (
        !info.isFile() ||
        info.nlink !== 1 ||
        info.size !== 68 ||
        info.mode & 0o077 ||
        (process.getuid && info.uid !== process.getuid())
      )
        refusal();
      const bytes = Buffer.alloc(69);
      let count = 0;
      while (count < bytes.length) {
        const n = readSync(fd, bytes, count, bytes.length - count, null);
        if (!n) break;
        count += n;
      }
      if (count !== 68) refusal();
      return core.sha256B64Url(bytes.subarray(0, count));
    } finally {
      closeSync(fd);
    }
  }
  private initial(): CredentialKeyState {
    return {
      version: 1,
      revision: 0,
      selectedKeyId: this.identity.keyId,
      keys: [
        {
          keyId: this.identity.keyId,
          publicJwk: this.identity.publicJwk,
          thumbprint: core.publicJwkSha256Thumbprint(this.identity.publicJwk),
          sealedHash: this.sealedHash(this.identity.keyId),
          abandoned: false,
        },
      ],
      pending: null,
    };
  }
  private load(value: CredentialKeyState | null) {
    return validateCredentialKeyState(value ?? this.initial(), this.identity);
  }
  async snapshot() {
    const rows = await this.state.db.select().from(issuerIdentity);
    if (
      rows.length !== 1 ||
      rows[0]!.keyId !== this.identity.keyId ||
      rows[0]!.publicThumbprint !==
        core.publicJwkSha256Thumbprint(this.identity.publicJwk)
    )
      refusal();
    return this.load(rows[0]!.credentialKeys);
  }
  private async mutate<T>(action: (value: CredentialKeyState) => T) {
    return this.state.db.transaction(async (tx) => {
      const [row] = await tx
        .select()
        .from(issuerIdentity)
        .where(eq(issuerIdentity.singleton, 1))
        .for("update");
      if (
        !row ||
        row.keyId !== this.identity.keyId ||
        row.publicThumbprint !==
          core.publicJwkSha256Thumbprint(this.identity.publicJwk)
      )
        refusal();
      const value = this.load(row.credentialKeys);
      const result = action(value);
      validateCredentialKeyState(value, this.identity);
      await tx
        .update(issuerIdentity)
        .set({ credentialKeys: value })
        .where(eq(issuerIdentity.singleton, 1));
      return result;
    });
  }
  private advance(value: CredentialKeyState) {
    if (value.revision === 2147483647) refusal("ISSUER_KEY_LIMIT", 409);
    value.revision++;
  }
  private expect(value: CredentialKeyState, expected: unknown) {
    if (!revision(expected)) refusal("ISSUER_KEY_BAD_REQUEST", 400);
    if (value.revision !== expected)
      refusal("ISSUER_KEY_REVISION_CONFLICT", 409);
  }
  private material(key: CredentialKey) {
    if (!key.publicJwk || key.sealedHash !== this.sealedHash(key.keyId))
      refusal();
    let publicJwk;
    try {
      publicJwk = core.publicJwk(key.keyId);
    } catch {
      publicJwk = core.persistentSigningKey({
        path: this.file(key.keyId),
        unlockKey: this.unlockKey,
        keyId: key.keyId,
        create: false,
      });
    }
    if (!isDeepStrictEqual(publicJwk, key.publicJwk)) refusal();
  }
  async ready() {
    try {
      const value = await this.snapshot();
      for (const key of value.keys) if (key.publicJwk) this.material(key);
      const directory = join(this.directory, "credential-keys");
      if (existsSync(directory)) {
        const info = lstatSync(directory);
        if (
          !info.isDirectory() ||
          info.mode & 0o077 ||
          (process.getuid && info.uid !== process.getuid())
        )
          refusal();
        const allowed = new Set(
          value.keys
            .filter((k) => k.keyId !== this.identity.keyId)
            .map((k) => core.sha256B64Url(k.keyId) + ".sealed"),
        );
        // ponytail: inventory is bounded to 64 immutable IDs; use a separate key service only if this profile grows.
        const entries = opendirSync(directory);
        try {
          let count = 0;
          for (let e = entries.readSync(); e; e = entries.readSync())
            if (++count > 64 || !allowed.has(e.name)) refusal();
        } finally {
          entries.closeSync();
        }
      }
      return value;
    } catch {
      refusal();
    }
  }
  view(value: CredentialKeyState) {
    return {
      revision: value.revision,
      selected_key_id: value.selectedKeyId,
      credential_keys: value.keys.map((k) => ({
        key_id: k.keyId,
        public_jwk: k.publicJwk,
        public_jwk_sha256_thumbprint: k.thumbprint,
        abandoned: k.abandoned,
      })),
      pending: value.pending
        ? {
            phase: value.pending.phase,
            key_id: value.pending.keyId,
            ...value.pending.request,
          }
        : null,
    };
  }
  async inspect() {
    return this.view(await this.ready());
  }
  async stage(input: unknown) {
    if (!stageRequest(input)) refusal("ISSUER_KEY_BAD_REQUEST", 400);
    const keyId = this.identity.did + "#" + input.key_fragment;
    const fresh = await this.mutate((value) => {
      if (value.pending && isDeepStrictEqual(value.pending.request, input))
        return false;
      this.expect(value, input.expected_revision);
      if (value.pending || value.keys.some((k) => k.keyId === keyId))
        refusal("ISSUER_KEY_CONFLICT", 409);
      if (value.keys.length >= 64) refusal("ISSUER_KEY_LIMIT", 409);
      this.advance(value);
      value.keys.push({
        keyId,
        publicJwk: null,
        thumbprint: null,
        sealedHash: null,
        abandoned: false,
      });
      value.pending = { phase: "preparing", keyId, request: input };
      return true;
    });
    try {
      const pending = await this.snapshot();
      if (
        pending.pending?.keyId !== keyId ||
        !isDeepStrictEqual(pending.pending.request, input)
      )
        refusal("ISSUER_KEY_REVISION_CONFLICT", 409);
      if (pending.pending.phase === "staged")
        return this.view(await this.ready());
      const directory = join(this.directory, "credential-keys");
      if (fresh) {
        if (!existsSync(directory)) mkdirSync(directory, { mode: 0o700 });
        const info = lstatSync(directory);
        if (!info.isDirectory() || info.mode & 0o077) refusal();
      }
      let publicJwk: core.PublicJwk;
      if (fresh)
        publicJwk = core.persistentSigningKey({
          path: this.file(keyId),
          unlockKey: this.unlockKey,
          keyId,
          create: true,
        });
      else {
        this.sealedHash(keyId);
        try {
          publicJwk = core.publicJwk(keyId);
        } catch {
          publicJwk = core.persistentSigningKey({
            path: this.file(keyId),
            unlockKey: this.unlockKey,
            keyId,
            create: false,
          });
        }
      }
      const hash = this.sealedHash(keyId),
        fd = openSync(directory, constants.O_RDONLY | constants.O_NOFOLLOW);
      try {
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
      await this.mutate((value) => {
        if (
          value.pending?.keyId !== keyId ||
          !isDeepStrictEqual(value.pending.request, input)
        )
          refusal("ISSUER_KEY_REVISION_CONFLICT", 409);
        const key = value.keys.find((k) => k.keyId === keyId)!;
        if (
          key.publicJwk &&
          (!isDeepStrictEqual(key.publicJwk, publicJwk) ||
            key.sealedHash !== hash)
        )
          refusal();
        if (!key.publicJwk) {
          this.advance(value);
          key.publicJwk = publicJwk;
          key.thumbprint = core.publicJwkSha256Thumbprint(publicJwk);
          key.sealedHash = hash;
          value.pending.phase = "staged";
        }
      });
      return this.view(await this.ready());
    } catch (error) {
      if (error instanceof VerificationError) throw error;
      refusal();
    }
  }
  async proof(input: unknown, registryOrigin: string, clock: () => number) {
    if (!exactKeyBody(input, "challenge,expected_revision"))
      refusal("ISSUER_KEY_BAD_REQUEST", 400);
    const value = await this.ready();
    this.expect(value, input.expected_revision);
    const now = clock();
    const p = value.pending,
      c = input.challenge;
    if (
      !p ||
      p.phase !== "staged" ||
      !exactKeyBody(
        c,
        "audience,challenge_id,expected_revision,expires_at,issuer_registration_id,key_id,nonce,operation,proof_key_id",
      ) ||
      c.operation !== "rotate" ||
      c.issuer_registration_id !== p.request.issuer_registration_id ||
      c.expected_revision !== p.request.expected_registry_revision ||
      c.key_id !== p.keyId ||
      c.proof_key_id !== p.keyId ||
      !uuid(c.challenge_id) ||
      typeof c.nonce !== "string" ||
      !/^[A-Za-z0-9_-]{43}$/.test(c.nonce) ||
      c.audience !==
        registryOrigin +
          `/api/projects/${p.request.project_id}/issuers/${p.request.issuer_registration_id}/key-challenges/${c.challenge_id}/complete` ||
      typeof c.expires_at !== "string"
    )
      refusal("ISSUER_KEY_PROOF_REFUSED", 403);
    const expires = Date.parse(c.expires_at) / 1000;
    // Registry deadlines include milliseconds; this clock and JWT claims use integer seconds.
    if (
      !Number.isFinite(expires) ||
      expires <= now ||
      expires >= now + 121 ||
      new Date(expires * 1000).toISOString() !== c.expires_at
    )
      refusal("ISSUER_KEY_PROOF_REFUSED", 403);
    const exp = Math.min(now + 60, Math.floor(expires));
    if (exp <= now) refusal("ISSUER_KEY_PROOF_REFUSED", 403);
    const jwt = core.signCompactJwsJson({
      keyId: p.keyId,
      header: { alg: "ES256", typ: "partner-identity-proof+jwt", kid: p.keyId },
      payload: {
        iss: this.identity.did,
        aud: c.audience,
        nonce: c.nonce,
        iat: now,
        exp,
      },
    });
    return { jwt };
  }
  async candidate(input: unknown) {
    if (!exactKeyBody(input, "expected_revision,key_id"))
      refusal("ISSUER_KEY_BAD_REQUEST", 400);
    const value = await this.ready();
    this.expect(value, input.expected_revision);
    if (
      !value.pending ||
      value.pending.phase !== "staged" ||
      value.pending.keyId !== input.key_id
    )
      refusal("ISSUER_KEY_CONFLICT", 409);
    return value.keys.find((k) => k.keyId === input.key_id)!;
  }
  async activate(input: unknown, validate: (key: CredentialKey) => void) {
    await this.candidate(input);
    const body = input as Record<string, unknown>;
    await this.mutate((value) => {
      this.expect(value, body.expected_revision);
      const key = value.keys.find((k) => k.keyId === body.key_id);
      if (
        !key?.publicJwk ||
        value.pending?.phase !== "staged" ||
        value.pending.keyId !== key.keyId
      )
        refusal("ISSUER_KEY_CONFLICT", 409);
      this.material(key);
      validate(key);
      this.advance(value);
      value.selectedKeyId = key.keyId;
      value.pending = null;
      validate(key);
    });
    return this.inspect();
  }
  async abandon(input: unknown) {
    if (!exactKeyBody(input, "expected_revision,key_id"))
      refusal("ISSUER_KEY_BAD_REQUEST", 400);
    await this.mutate((value) => {
      this.expect(value, input.expected_revision);
      if (!value.pending || value.pending.keyId !== input.key_id)
        refusal("ISSUER_KEY_CONFLICT", 409);
      value.keys.find((k) => k.keyId === input.key_id)!.abandoned = true;
      value.pending = null;
      this.advance(value);
    });
    return this.inspect();
  }
}
