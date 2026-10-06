import * as core from "@unsw-vc/identity-core-node";
import { readFileSync, writeFileSync } from "node:fs";
import { httpClient } from "./http-client.mjs";

// Configuration is operator-held; the output contains a management capability.
// Neither configuration nor output belongs in source control or process logs.
export async function registerVerifier(config: any) {
  const management = new URL(config.managementOrigin);
  if (
    management.protocol !== "http:" ||
    management.hostname !== "127.0.0.1" ||
    management.origin !== config.managementOrigin
  )
    throw Error("MANAGEMENT_LOCATION_REFUSED");
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
  if (document.id !== did || document.verificationMethod.length !== 1)
    throw Error("VERIFIER_IDENTITY_REFUSED");
  const key = document.verificationMethod[0];
  const owner = await json(config.registryOrigin + "/api/projects", 201, {});
  const path =
    config.registryOrigin +
    `/api/projects/${owner.project.project_id}/verifiers/challenges`;
  const challenge = await json(
    path,
    201,
    {
      origin: config.runtimeOrigin,
      did,
      key_id: key.id,
      public_jwk: key.publicKeyJwk,
    },
    owner.management_credential,
  );
  const proof = await json(
    config.managementOrigin + "/management/sign",
    200,
    { nonce: challenge.nonce, audience: challenge.audience },
    config.managementToken,
  );
  await json(
    path + "/" + challenge.challenge_id + "/complete",
    201,
    { jwt: proof.jwt },
    owner.management_credential,
  );
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
  return {
    project: owner.project,
    management_credential: owner.management_credential,
    verifierDid: did,
    verifierPublicJwk: key.publicKeyJwk,
    permissionsUrl: permissionUrl,
  };
}
if (process.argv[1]?.endsWith("register-verifier.ts")) {
  try {
    const result = await registerVerifier(
      JSON.parse(readFileSync(process.argv[2]!, "utf8")),
    );
    writeFileSync(process.argv[3]!, JSON.stringify(result, null, 2) + "\n", {
      mode: 0o600,
      flag: "wx",
    });
    console.log("VERIFIER_REGISTERED_PROTECTED_OUTPUT_WRITTEN");
  } catch {
    console.error("VERIFIER_REGISTRATION_FAILED");
    process.exitCode = 1;
  }
}
