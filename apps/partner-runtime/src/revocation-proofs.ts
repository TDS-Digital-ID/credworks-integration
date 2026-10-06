import * as core from "@unsw-vc/identity-core-node";
import {
  closeSync,
  constants,
  existsSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  opendirSync,
  openSync,
  readSync,
  renameSync,
  rmdirSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import type { RuntimeIdentity } from "./runtime.js";
import { VerificationError, type VerifierConfig, type CredentialPin } from "./evidence-cache.js";

const MAX_RECORDS = 10000;
const MAX_PROOF_BYTES = 262144;
const MAX_TOTAL_BYTES = 64 * 1024 * 1024;
const MAX_INVENTORY_BYTES = 16 * 1024 * 1024;
const INVENTORY_TYPE = "credworks-revocation-inventory+jwt";
type Tuple = {
  issuerDid: string;
  issuerKeyId: string | null;
  issuerThumbprint: string;
  statusThumbprint: string;
  statusKeyId: string | null;
  url: string;
  index: string;
};
type Entry = {
  id: string;
  tuple: Tuple;
  observedAt: number;
  proofHash: string;
  proofBytes: number;
};
type Inventory = { version: number; runtimeDid: string; entries: Entry[] };

export function statusSourceKeyId(
  config: VerifierConfig,
  source: VerifierConfig["statusSources"][number],
): string | undefined {
  return config.scalar &&
    core.publicJwkSha256Thumbprint(config.issuerJwk) ===
      core.publicJwkSha256Thumbprint(source.publicJwk)
    ? config.scalar.issuerKeyId
    : source.publicJwk.kid;
}

function unavailable(): never {
  throw new VerificationError("EVIDENCE_UNAVAILABLE", 503);
}
function privateDirectory(path: string) {
  const info = lstatSync(path);
  if (
    !info.isDirectory() ||
    info.mode & 0o077 ||
    (process.getuid && info.uid !== process.getuid())
  )
    unavailable();
}
export function readPrivate(path: string, limit: number): string {
  const fd = openSync(
    path,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  try {
    const info = fstatSync(fd);
    if (
      !info.isFile() ||
      info.nlink !== 1 ||
      info.mode & 0o077 ||
      (process.getuid && info.uid !== process.getuid()) ||
      info.size > limit
    )
      unavailable();
    const bytes = Buffer.alloc(info.size + 1);
    let size = 0;
    while (size < bytes.length) {
      const count = readSync(fd, bytes, size, bytes.length - size, null);
      if (count === 0) break;
      size += count;
    }
    if (size !== info.size) unavailable();
    return new TextDecoder("utf-8", { fatal: true }).decode(
      bytes.subarray(0, size),
    );
  } finally {
    closeSync(fd);
  }
}
function syncDirectory(path: string) {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}
function atomicWrite(path: string, text: string) {
  const pending = path + ".pending";
  const fd = openSync(
    pending,
    constants.O_WRONLY |
      constants.O_CREAT |
      constants.O_EXCL |
      constants.O_NOFOLLOW,
    0o600,
  );
  try {
    writeFileSync(fd, text, "utf8");
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(pending, path);
  syncDirectory(dirname(path));
}
function entryStatus(tuple: Tuple): core.CredentialStatus {
  return {
    id: tuple.url + "#" + tuple.index,
    type: "BitstringStatusListEntry",
    statusPurpose: "revocation",
    statusListIndex: tuple.index,
    statusListCredential: tuple.url,
  };
}
function idFor(tuple: Tuple) {
  return core.sha256B64Url(
    JSON.stringify([
      "credworks-revocation-proof-v1",
      tuple.issuerDid,
      tuple.issuerKeyId,
      tuple.issuerThumbprint,
      tuple.statusThumbprint,
      tuple.statusKeyId,
      tuple.url,
      tuple.index,
    ]),
  );
}

// Only public signed negative evidence lives here. Positive snapshots remain in memory.
export class RevocationProofs {
  private readonly directory: string;
  private readonly lock: string;
  private readonly manifest: string;
  constructor(
    private readonly stateDir: string,
    private readonly identity: RuntimeIdentity,
    private readonly config: VerifierConfig,
    private readonly now: () => number,
  ) {
    this.directory = join(stateDir, "revocation-proofs");
    this.lock = join(stateDir, "revocation-proofs.lock");
    this.manifest = join(stateDir, "identity.json");
    this.locked((mutation) => {
      const manifest = JSON.parse(readPrivate(this.manifest, 65536));
      if (
        manifest.version !== 1 ||
        core.didWebFromHost(new URL(manifest.origin).host) !== identity.did ||
        core.publicJwkSha256Thumbprint(manifest.publicJwk) !==
          core.publicJwkSha256Thumbprint(identity.publicJwk)
      )
        unavailable();
      if (manifest.revocationProofStoreVersion === undefined) {
        // An interrupted or unexpected store is never silently initialized empty.
        if (existsSync(this.directory)) unavailable();
        mutation();
        mkdirSync(this.directory, { mode: 0o700 });
        this.writeInventory([]);
        atomicWrite(
          this.manifest,
          JSON.stringify({ ...manifest, revocationProofStoreVersion: 1 }) +
            "\n",
        );
      } else if (manifest.revocationProofStoreVersion !== 1) unavailable();
      this.load();
    });
  }
  private tuple(
    source: VerifierConfig["statusSources"][number],
    index: string,
    credential?: CredentialPin,
  ): Tuple {
    const issuerThumbprint = core.publicJwkSha256Thumbprint(
      this.config.issuerJwk,
    );
    const statusThumbprint = core.publicJwkSha256Thumbprint(source.publicJwk);
    return {
      issuerDid: this.config.issuerDid,
      issuerKeyId: credential?.keyId ?? this.config.scalar?.issuerKeyId ?? null,
      issuerThumbprint: credential?.thumbprint ?? issuerThumbprint,
      statusThumbprint,
      statusKeyId: statusSourceKeyId(this.config, source) ?? null,
      url: source.url,
      index,
    };
  }
  private validate(entry: Entry): string {
    if (
      !entry ||
      Object.keys(entry).sort().join() !==
        "id,observedAt,proofBytes,proofHash,tuple" ||
      !entry.tuple ||
      !Number.isSafeInteger(entry.observedAt) ||
      entry.observedAt > this.now() ||
      !Number.isSafeInteger(entry.proofBytes) ||
      entry.proofBytes < 1 ||
      entry.proofBytes > MAX_PROOF_BYTES ||
      typeof entry.proofHash !== "string" ||
      !/^[A-Za-z0-9_-]{43}$/.test(entry.proofHash) ||
      typeof entry.id !== "string" ||
      !/^[A-Za-z0-9_-]{43}$/.test(entry.id)
    )
      unavailable();
    const source = this.config.statusSources.find(
      (value) =>
        value.url === entry.tuple.url && value.purpose === "revocation",
    );
    if (
      !source ||
      typeof entry.tuple.index !== "string" ||
      !/^(0|[1-9][0-9]*)$/.test(entry.tuple.index) ||
      Object.keys(entry.tuple).sort().join() !== "index,issuerDid,issuerKeyId,issuerThumbprint,statusKeyId,statusThumbprint,url" ||
      entry.tuple.issuerDid !== this.config.issuerDid ||
      typeof entry.tuple.issuerThumbprint !== "string" || !/^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(entry.tuple.issuerThumbprint) ||
      (this.config.scalar ? entry.tuple.issuerKeyId === null :
        entry.tuple.issuerKeyId !== null || entry.tuple.issuerThumbprint !== core.publicJwkSha256Thumbprint(this.config.issuerJwk)) ||
      (entry.tuple.issuerKeyId !== null && (typeof entry.tuple.issuerKeyId !== "string" ||
        !entry.tuple.issuerKeyId.startsWith(this.config.issuerDid + "#") ||
        !/^[A-Za-z0-9._-]{1,128}$/.test(entry.tuple.issuerKeyId.slice(this.config.issuerDid.length + 1)))) ||
      entry.tuple.statusThumbprint !== core.publicJwkSha256Thumbprint(source.publicJwk) ||
      entry.tuple.statusKeyId !== (statusSourceKeyId(this.config, source) ?? null) ||
      entry.id !== idFor(entry.tuple)
    )
      unavailable();
    const compact = readPrivate(
      join(this.directory, entry.id + ".jwt"),
      MAX_PROOF_BYTES,
    );
    if (
      Buffer.byteLength(compact) !== entry.proofBytes ||
      core.sha256B64Url(compact) !== entry.proofHash
    )
      unavailable();
    this.authenticate(entry.tuple, compact, entry.observedAt, source);
    return compact;
  }
  private authenticate(
    tuple: Tuple,
    compact: string,
    observedAt: number,
    source: VerifierConfig["statusSources"][number],
  ) {
    const [header, list] = core.verifyBitstringStatusListCredentialAt({
      compactJws: compact,
      statusListJwk: source.publicJwk,
      nowUnixSeconds: observedAt,
    });
    if (
      list.issuer !== tuple.issuerDid ||
      list.credentialSubject.id !== source.url + "#list" ||
      list.credentialSubject.statusPurpose !== "revocation" ||
      !list.validUntil ||
      (tuple.statusKeyId !== null && header.kid !== tuple.statusKeyId)
    )
      unavailable();
    if (
      core.resolveCredentialStatusAt({
        status: entryStatus(tuple),
        resolverResponses: { [source.url]: compact },
        statusListJwk: source.publicJwk,
        nowUnixSeconds: observedAt,
      }).revoked !== true
    )
      unavailable();
  }
  private load(): Entry[] {
    const manifest = JSON.parse(readPrivate(this.manifest, 65536));
    if (manifest.revocationProofStoreVersion !== 1) unavailable();
    privateDirectory(this.directory);
    const verified = core.verifyCompactJwsJson({
      compactJws: readPrivate(
        join(this.directory, "inventory.jwt"),
        MAX_INVENTORY_BYTES,
      ),
      publicJwk: this.identity.publicJwk,
    });
    const value = verified.payload as Inventory;
    if (
      verified.header.typ !== INVENTORY_TYPE ||
      verified.header.kid !== this.identity.keyId ||
      !value ||
      Object.keys(value).sort().join() !== "entries,runtimeDid,version" ||
      value.version !== 1 ||
      value.runtimeDid !== this.identity.did ||
      !Array.isArray(value.entries) ||
      value.entries.length > MAX_RECORDS
    )
      unavailable();
    const expected = new Set(["inventory.jwt"]);
    let bytes = 0;
    // ponytail: scan at most 10,000 retained proofs; use a batched core status-read path if this ceiling grows.
    for (const entry of value.entries) {
      this.validate(entry);
      if (expected.has(entry.id + ".jwt")) unavailable();
      expected.add(entry.id + ".jwt");
      bytes += entry.proofBytes;
      if (bytes > MAX_TOTAL_BYTES) unavailable();
    }
    const files = opendirSync(this.directory);
    let count = 0;
    try {
      for (let file = files.readSync(); file; file = files.readSync()) {
        if (++count > expected.size || !expected.has(file.name)) unavailable();
      }
      if (count !== expected.size) unavailable();
    } finally {
      files.closeSync();
    }
    return value.entries;
  }
  private signedInventory(entries: Entry[]): string {
    const payload = { version: 1, runtimeDid: this.identity.did, entries };
    if (Buffer.byteLength(JSON.stringify(payload)) > 12 * 1024 * 1024)
      unavailable();
    const compact = core.signCompactJwsJson({
      keyId: this.identity.keyId,
      header: { alg: "ES256", typ: INVENTORY_TYPE, kid: this.identity.keyId },
      payload,
    });
    if (Buffer.byteLength(compact) > MAX_INVENTORY_BYTES) unavailable();
    return compact;
  }
  private writeInventory(entries: Entry[]) {
    atomicWrite(
      join(this.directory, "inventory.jwt"),
      this.signedInventory(entries),
    );
  }
  private locked<T>(action: (mutation: () => void) => T): T {
    let acquired = false,
      mutated = false,
      succeeded = false;
    try {
      privateDirectory(this.stateDir);
      const deadline = performance.now() + 250;
      const pause = new Int32Array(new SharedArrayBuffer(4));
      for (;;) {
        try {
          mkdirSync(this.lock, { mode: 0o700 });
          acquired = true;
          break;
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
          privateDirectory(this.lock);
          if (performance.now() >= deadline) unavailable();
          // No awaited work holds this lock. A crashed writer requires explicit recovery.
          Atomics.wait(pause, 0, 0, 5);
        }
      }
      syncDirectory(this.stateDir);
      const result = action(() => {
        mutated = true;
      });
      succeeded = true;
      return result;
    } catch {
      return unavailable();
    } finally {
      if (acquired && (!mutated || succeeded)) {
        try {
          rmdirSync(this.lock);
          syncDirectory(this.stateDir);
        } catch {
          unavailable();
        }
      }
    }
  }
  check(
    status: core.CredentialStatus,
    compact: string,
    freshUntil: number,
    credential?: CredentialPin,
  ): boolean {
    const source = this.config.statusSources.find(
      (source) =>
        source.url === status.statusListCredential &&
        source.purpose === status.statusPurpose,
    );
    if (!source) unavailable();
    let statusError: unknown;
    const refused = this.locked((mutation) => {
      const entries = this.load();
      // New negative resolution begins only after the lock has been fsynced.
      // If storage cannot establish that barrier, no new bit is observed here.
      const observedAt = this.now();
      let resolution: core.CredentialStatusResolution;
      try {
        if (observedAt >= freshUntil)
          throw new VerificationError("EVIDENCE_STALE", 503);
        resolution = core.resolveCredentialStatusAt({
          status,
          resolverResponses: { [source.url]: compact },
          statusListJwk: source.publicJwk,
          nowUnixSeconds: observedAt,
        });
      } catch (error) {
        // Propagate only this ordinary status decision after safe lock cleanup.
        // Loading, authentication and persistence failures still refuse storage.
        statusError = error;
        return false;
      }
      if (source.purpose !== "revocation") return resolution.revoked;
      const tuple = this.tuple(source, String(resolution.status_list_index), credential);
      const id = idFor(tuple);
      if (entries.some((entry) => entry.id === id)) return true;
      if (resolution.revoked !== true) return false;
      const bytes = Buffer.byteLength(compact);
      const entry = {
        id,
        tuple,
        observedAt,
        proofHash: core.sha256B64Url(compact),
        proofBytes: bytes,
      };
      // Authenticate before any mutation; the caller's boolean is not a persisted trust source.
      this.authenticate(tuple, compact, observedAt, source);
      // Once authenticated revocation is observed, every failed persistence path
      // retains the fsynced lock. An older active list cannot revive an omitted tuple.
      mutation();
      if (
        entries.length >= MAX_RECORDS ||
        bytes > MAX_PROOF_BYTES ||
        entries.reduce((sum, entry) => sum + entry.proofBytes, 0) + bytes >
          MAX_TOTAL_BYTES
      )
        unavailable();
      const inventory = this.signedInventory([...entries, entry]);
      atomicWrite(join(this.directory, id + ".jwt"), compact);
      atomicWrite(join(this.directory, "inventory.jwt"), inventory);
      return true;
    });
    if (statusError !== undefined) throw statusError;
    return refused;
  }
}
