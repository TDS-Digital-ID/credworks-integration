import * as core from "@unsw-vc/identity-core-node";
import {
  readFileSync,
  writeFileSync,
  openSync,
  closeSync,
  fsyncSync,
  renameSync,
  lstatSync,
  mkdirSync,
  rmdirSync,
} from "node:fs";
import { dirname, resolve } from "node:path";
import { isDeepStrictEqual } from "node:util";
import { httpClient } from "./http-client.mjs";

const recovery = {
  REGISTRATION_BUSY:
    "Another registration may be running. After confirming it has stopped, remove only the adjacent .lock directory and retry with the same files.",
  REGISTRATION_PROJECT_OUTCOME_UNKNOWN:
    "Project creation was not confirmed locally. Preserve state and any .pending file; ask the registry operator to reconcile the original attempt. The API cannot recover a lost once-issued credential. Do not create another project.",
  REGISTRATION_CHALLENGE_OUTCOME_UNKNOWN:
    "The ownership challenge response was lost. Preserve the project credential and ask the registry operator to resolve the outstanding challenge before retrying.",
  REGISTRATION_COMPLETION_OUTCOME_UNKNOWN:
    "Ownership completion may have succeeded. Preserve state and retry the same command to read the original registration through authenticated HTTP. If it remains unavailable, ask the registry operator to reconcile the saved challenge; do not register a replacement.",
  REGISTRATION_STATE_REFUSED:
    "Preserve both files. Restore the original origins, trust configuration and runtime identity; legacy or damaged state needs operator-assisted recovery, not deletion.",
  REGISTRATION_STORAGE_REFUSED:
    "Use a private directory (mode 0700) and regular state file (mode 0600) owned by this user. Preserve state and any .pending file; resolve interrupted writes with the operator using authenticated remote state before retrying.",
};
const uuid = (value: unknown) =>
  typeof value === "string" &&
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(
    value,
  );
const protectedPath = (path: string, directory: boolean) => {
  const info = lstatSync(path);
  if (
    (directory ? !info.isDirectory() : !info.isFile()) ||
    info.mode & (directory ? 0o077 : 0o177) ||
    info.uid !== process.getuid?.()
  )
    throw Error("REGISTRATION_STORAGE_REFUSED");
};

// The output doubles as a journal: persist capabilities before any further HTTP work.
export const registerVerifier = (config: any, output: string) => registerRuntime(config, output, "verifier");
export const registerCustomVerifier = (config: any, output: string) => registerRuntime(config, output, "verifier", false);
export const registerIssuer = (config: any, output: string) => registerRuntime(config, output, "issuer");
async function registerRuntime(config: any, output: string, role: "verifier" | "issuer", education = true) {
  const path = resolve(output);
  protectedPath(dirname(path), true);
  try {
    mkdirSync(path + ".lock", { mode: 0o700 });
  } catch {
    throw Error("REGISTRATION_BUSY");
  }
  try {
    try {
      lstatSync(path + ".pending");
      throw Error("REGISTRATION_STORAGE_REFUSED");
    } catch (error: any) {
      if (error.code !== "ENOENT") throw Error("REGISTRATION_STORAGE_REFUSED");
    }
    let state: any;
    try {
      protectedPath(path, false);
      state = JSON.parse(readFileSync(path, "utf8"));
      if (!state || typeof state !== "object" || Array.isArray(state))
        throw Error("REGISTRATION_STATE_REFUSED");
    } catch (error: any) {
      if (error.code !== "ENOENT") throw Error("REGISTRATION_STATE_REFUSED");
    }
    const save = () => {
      try {
        const temporary = path + ".pending";
        const fd = openSync(temporary, "wx", 0o600);
        try {
          writeFileSync(fd, JSON.stringify(state, null, 2) + "\n");
          fsyncSync(fd);
        } finally {
          closeSync(fd);
        }
        renameSync(temporary, path);
        const directory = openSync(dirname(path), "r");
        try {
          fsyncSync(directory);
        } finally {
          closeSync(directory);
        }
      } catch {
        throw Error("REGISTRATION_STORAGE_REFUSED");
      }
    };
    try {
      return await resumeRegistration(config, role, education, state, (next: any) => {
        state = next;
        save();
      });
    } catch (error) {
      if (error instanceof Error && error.message in recovery) throw error;
      const uncertain = {
        "creating-project": "PROJECT",
        "requesting-challenge": "CHALLENGE",
        completing: "COMPLETION",
      }[state?.phase as string];
      if (uncertain)
        throw Error("REGISTRATION_" + uncertain + "_OUTCOME_UNKNOWN");
      throw error;
    }
  } finally {
    rmdirSync(path + ".lock");
  }
}

async function resumeRegistration(
  config: any,
  role: "verifier" | "issuer",
  education: boolean,
  state: any,
  save: (state: any) => void,
) {
  const management = new URL(config.managementOrigin);
  if (
    management.protocol !== "http:" ||
    management.hostname !== "127.0.0.1" ||
    management.origin !== config.managementOrigin
  )
    throw Error("MANAGEMENT_LOCATION_REFUSED");
  for (const origin of [config.registryOrigin, config.runtimeOrigin]) {
    const url = new URL(origin);
    if (
      url.protocol !== "https:" ||
      url.origin !== origin ||
      url.username ||
      url.password
    )
      throw Error("HTTP_ORIGIN_REFUSED");
  }
  if (
    config.registryDid !==
    core.didWebFromHost(new URL(config.registryOrigin).host)
  )
    throw Error("REGISTRY_IDENTITY_REFUSED");
  const binding = {
    registryOrigin: config.registryOrigin,
    registryDid: config.registryDid,
    anchor: core.publicJwkSha256Thumbprint(config.trustAnchorJwk),
    ...(role === "verifier" && education ? { educationIssuerDid: config.educationIssuerDid } : { role: role === "verifier" ? "custom-verifier" : role }),
    runtimeOrigin: config.runtimeOrigin,
    managementOrigin: config.managementOrigin,
  };
  if (
    state &&
    (state.version !== 1 || !isDeepStrictEqual(state.binding, binding))
  )
    throw Error("REGISTRATION_STATE_REFUSED");
  const call = httpClient({}, config.managementOrigin);
  const json = async (
    location: string,
    expected: number,
    body?: unknown,
    bearer?: string,
  ) => {
    const origin = new URL(location).origin;
    if (
      ![
        config.registryOrigin,
        config.runtimeOrigin,
        config.managementOrigin,
      ].includes(origin)
    )
      throw Error("HTTP_ORIGIN_REFUSED");
    const response = await call(location, {
      method: body ? "POST" : "GET",
      headers: {
        ...(body ? { "content-type": "application/json" } : {}),
        ...(bearer ? { authorization: "Bearer " + bearer } : {}),
      },
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
    if (response.status !== expected)
      throw Error("HTTP_STATUS_REFUSED_" + response.status);
    return response.json();
  };
  const document = await json(
    config.runtimeOrigin + "/.well-known/did.json",
    200,
  );
  const did = core.didWebFromHost(new URL(config.runtimeOrigin).host);
  if (document.id !== did || document.verificationMethod?.length !== 1)
    throw Error("RUNTIME_IDENTITY_REFUSED");
  const key = document.verificationMethod[0];
  core.resolveDidWebKey({
    issuerDid: did,
    kid: key.id,
    resolverResponses: {
      [core.didWebToHttpsUrl(did)]: JSON.stringify(document),
    },
  });
  const didField = role + "Did", jwkField = role + "PublicJwk";
  const registrationIdField = role === "issuer" ? "issuer_registration_id" : "registration_id";
  if (
    state &&
    (state[didField] !== did ||
      state.keyId !== key.id ||
      !isDeepStrictEqual(state[jwkField], key.publicKeyJwk))
  )
    throw Error("REGISTRATION_STATE_REFUSED");
  if (!state) {
    state = {
      version: 1,
      binding,
      startedAt: new Date().toISOString(),
      [didField]: did,
      keyId: key.id,
      [jwkField]: key.publicKeyJwk,
      phase: "creating-project",
    };
    save(state);
    const owner = await json(config.registryOrigin + "/api/projects", 201, {});
    state.project = owner.project;
    state.management_credential = owner.management_credential;
    state.phase = "project-created";
    save(state);
  }
  if (state.phase === "creating-project")
    throw Error("REGISTRATION_PROJECT_OUTCOME_UNKNOWN");
  if (
    !uuid(state.project?.project_id) ||
    !/^cw_project_[A-Za-z0-9_-]{43}$/.test(state.management_credential)
  )
    throw Error("REGISTRATION_STATE_REFUSED");
  const projectUrl =
    config.registryOrigin + "/api/projects/" + state.project.project_id;
  const owner = await json(
    projectUrl,
    200,
    undefined,
    state.management_credential,
  );
  if (owner.project?.project_id !== state.project.project_id)
    throw Error("REGISTRATION_STATE_REFUSED");
  if (state.phase === "requesting-challenge")
    throw Error("REGISTRATION_CHALLENGE_OUTCOME_UNKNOWN");
  const challengePath = projectUrl + "/" + role + "s/challenges";
  if (
    state.phase === "project-created" ||
    (state.phase === "challenge-ready" &&
      Date.parse(state.challenge?.expires_at) <= Date.now())
  ) {
    state.phase = "requesting-challenge";
    save(state);
    state.challenge = await json(
      challengePath,
      201,
      {
        origin: config.runtimeOrigin,
        did,
        key_id: key.id,
        public_jwk: key.publicKeyJwk,
      },
      state.management_credential,
    );
    state.phase = "challenge-ready";
    save(state);
  }
  if (state.phase === "challenge-ready") {
    const challenge = state.challenge;
    if (
      !uuid(challenge?.challenge_id) ||
      challenge.audience !==
        challengePath + "/" + challenge.challenge_id + "/complete" ||
      typeof challenge.nonce !== "string" ||
      !Number.isFinite(Date.parse(challenge.expires_at))
    )
      throw Error("REGISTRATION_STATE_REFUSED");
    const proof = await json(
      config.managementOrigin + "/management/sign",
      200,
      { nonce: challenge.nonce, audience: challenge.audience },
      config.managementToken,
    );
    state.phase = "completing";
    save(state);
    let registration;
    try {
      registration = await json(
        challenge.audience,
        201,
        { jwt: proof.jwt },
        state.management_credential,
      );
    } catch {
      // A lost response is reconciled below using the registry's challenge-derived ID.
    }
    if (registration) {
      state.registration = registration;
      state.phase = "registered";
      save(state);
    }
  }
  const recovering = state.phase === "completing";
  const registrationId = recovering
    ? state.challenge?.challenge_id
    : state.registration?.[registrationIdField];
  if (
    !["completing", "registered", "complete"].includes(state.phase) ||
    !uuid(registrationId)
  )
    throw Error("REGISTRATION_STATE_REFUSED");
  const registration = await json(
    projectUrl + "/" + role + "s/" + registrationId,
    200,
    undefined,
    state.management_credential,
  );
  if (
    registration[registrationIdField] !== registrationId ||
    registration.project_id !== state.project.project_id ||
    registration[role + "_did"] !== did ||
    registration[role + "_origin"] !== config.runtimeOrigin ||
    registration.key_id !== key.id ||
    !isDeepStrictEqual(registration.public_jwk, key.publicKeyJwk) ||
    (role === "verifier" && registration.withdrawn_at !== null) ||
    registration.revision !== (recovering ? 0 : (state.registration.revision ?? (role === "issuer" ? 0 : undefined)))
  )
    throw Error("REGISTRATION_STATE_REFUSED");
  if (recovering) {
    state.registration = registration;
    state.phase = "registered";
    save(state);
  }
  if (role === "issuer" || !education) { state.phase = "complete"; save(state); return state; }
  const permissionUrl =
    config.registryOrigin +
    "/scoped-verifier-permissions.jwt?verifier_did=" +
    encodeURIComponent(did);
  const response = await call(permissionUrl);
  if (response.status !== 200) throw Error("PERMISSION_UNAVAILABLE");
  const signed = core.verifyCompactJwsJson({
    compactJws: response.text,
    publicJwk: config.trustAnchorJwk,
  }).payload as any;
  if (signed.issuer !== config.registryDid || signed.id !== permissionUrl)
    throw Error("REGISTRY_IDENTITY_REFUSED");
  for (const profile of ["education_eligibility", "education_sign_in"]) {
    core.verifyScopedVerifierPermission({
      compactJws: response.text,
      trustAnchorJwk: config.trustAnchorJwk,
      request: {
        credential_issuer_did: config.educationIssuerDid,
        definition_id: "urn:credworks:education",
        definition_version: "1",
        credential_type: "UniversityEducationCredential",
        verifier_did: did,
        verifier_origin: config.runtimeOrigin,
        verifier_public_jwk: key.publicKeyJwk,
        profile_name: profile,
        claim_paths: [
          "enrolled",
          "institution_id",
          ...(profile === "education_sign_in" ? ["student_id"] : []),
        ].map((field) => ["credentialSubject", field]),
      },
      nowUnixSeconds: Math.floor(Date.now() / 1000),
    });
  }
  state.permissionsUrl = permissionUrl;
  state.phase = "complete";
  save(state);
  return state;
}
if (process.argv[1]?.endsWith("register-verifier.ts")) {
  try {
    protectedPath(process.argv[2]!, false);
    await registerVerifier(
      JSON.parse(readFileSync(process.argv[2]!, "utf8")),
      process.argv[3]!,
    );
    console.log("VERIFIER_REGISTERED_PROTECTED_OUTPUT_WRITTEN");
  } catch (error) {
    const code = error instanceof Error ? error.message : "";
    const instruction = recovery[code as keyof typeof recovery];
    console.error(
      instruction
        ? code + ": " + instruction
        : "VERIFIER_REGISTRATION_FAILED: Preserve the configuration and state files, fix connectivity or signed permissions, then retry the same command. No replacement identity was created.",
    );
    process.exitCode = 1;
  }
}
