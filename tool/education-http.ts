/** Public-HTTP sandbox acceptance; all key operations stay inside the Rust addon. */
import * as core from "@unsw-vc/identity-core-node";
import assert from "node:assert/strict";
import { mkdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { httpClient } from "./http-client.mjs";

type Config = {
  registryOrigin: string;
  registryDid: string;
  trustAnchorJwk: core.PublicJwk;
  portalOrigin: string;
  providerOrigin: string;
  applicationOrigin: string;
  runtimeOrigin: string;
  governmentIssuerDid: string;
  educationIssuerDid: string;
  stateDir: string;
};
const now = () => Math.floor(Date.now() / 1000);
const formType = "application/x-www-form-urlencoded";
const paths = (profile: string) => [
  ["credentialSubject", "enrolled"],
  ["credentialSubject", "institution_id"],
  ...(profile === "education_sign_in"
    ? [["credentialSubject", "student_id"]]
    : []),
];
export async function runEducation(config: Config, fetch = httpClient()) {
  const allowed = new Set([
    config.registryOrigin,
    config.portalOrigin,
    config.providerOrigin,
    config.applicationOrigin,
    config.runtimeOrigin,
    new URL(core.didWebToHttpsUrl(config.governmentIssuerDid)).origin,
    new URL(core.didWebToHttpsUrl(config.educationIssuerDid)).origin,
  ]);
  const call = async (
    url: string,
    method = "GET",
    body?: unknown,
    headers = {},
  ) => {
    if (!allowed.has(new URL(url).origin)) throw Error("HTTP_ORIGIN_REFUSED");
    return fetch(url, {
      method,
      headers: {
        ...(body ? { "content-type": "application/json" } : {}),
        ...headers,
      },
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
  };
  const json = async (
    url: string,
    method = "GET",
    body?: unknown,
    headers = {},
    status = 200,
  ) => {
    const response = await call(url, method, body, headers);
    if (response.status !== status)
      throw Error("HTTP_STATUS_REFUSED_" + response.status);
    return response.json();
  };
  const text = async (url: string) => {
    const response = await call(url);
    if (response.status !== 200)
      throw Error("HTTP_STATUS_REFUSED_" + response.status);
    return response.text;
  };
  const postForm = async (
    url: string,
    body: Record<string, string>,
    deadline?: number,
  ) => {
    if (!allowed.has(new URL(url).origin)) throw Error("HTTP_ORIGIN_REFUSED");
    const response = await fetch(url, {
      method: "POST",
      headers: { "content-type": formType },
      body: new URLSearchParams(body).toString(),
      ...(deadline !== undefined ? { deadline } : {}),
    });
    if (response.status !== 200)
      throw Error("HTTP_STATUS_REFUSED_" + response.status);
    return response.json();
  };
  mkdirSync(config.stateDir, { recursive: true, mode: 0o700 });
  const holderKeyId = "holder:kit:" + core.randomUrlSafe(16);
  const holder = core.persistentSigningKey({
    path: join(config.stateDir, randomUUID() + ".key"),
    unlockKey: core.randomUrlSafe(32),
    keyId: holderKeyId,
    create: true,
  });
  const owner = await json(
    config.registryOrigin + "/api/projects",
    "POST",
    {},
    {},
    201,
  );
  const auth = { authorization: "Bearer " + owner.management_credential };
  const person = await json(
    config.portalOrigin +
      `/api/sandbox/projects/${owner.project.project_id}/education/people`,
    "POST",
    { allocation_id: randomUUID() },
    auth,
    201,
  );
  const setups =
    config.portalOrigin +
    `/api/sandbox/projects/${owner.project.project_id}/education/people/${person.person_id}/setups`;
  const setupInput = { request_id: randomUUID(), scenario: "valid" };
  const setup = await json(setups, "POST", setupInput, auth, 201);
  const metadata = await json(
    config.portalOrigin + "/.well-known/openid-credential-issuer",
  );
  const oauth = await json(
    metadata.authorization_servers[0] +
      "/.well-known/oauth-authorization-server",
  );
  const receive = async (offerUri: string, issuerDid: string) => {
    const offer = await json(offerUri);
    const grant =
      offer.grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"];
    const token = await postForm(oauth.token_endpoint, {
      grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
      "pre-authorized_code": grant["pre-authorized_code"],
    });
    const nonce = await json(metadata.nonce_endpoint, "POST");
    const wia = await json(
      config.providerOrigin + "/wallet-instance-attestations",
      "POST",
      {
        credential_issuer: metadata.credential_issuer,
        holder_public_jwk: holder,
        attestation_evidence: {
          evidence_type: "mock_platform_attestation",
          platform: "headless-sandbox",
          device_id: randomUUID(),
          challenge: core.publicJwkSha256Thumbprint(holder),
        },
      },
      {},
      201,
    );
    const response = await json(
      metadata.credential_endpoint,
      "POST",
      {
        credential_configuration_id: offer.credential_configuration_ids[0],
        holder_public_jwk: holder,
        wallet_instance_attestation: wia.wallet_instance_attestation,
        proofs: {
          jwt: [
            core.createKeyProof({
              audience: metadata.credential_issuer,
              nonce: nonce.c_nonce,
              iat: now(),
              keyId: holderKeyId,
              publicJwk: holder,
            }),
          ],
        },
      },
      { authorization: "Bearer " + token.access_token },
    );
    const compact = response.credentials[0].credential;
    const document = JSON.parse(await text(core.didWebToHttpsUrl(issuerDid)));
    const issuerJwk = document.verificationMethod.find(
      (method: any) =>
        method.id ===
        JSON.parse(Buffer.from(compact.split(".")[0], "base64url").toString())
          .kid,
    )?.publicKeyJwk;
    const receipt = core.verifySdJwtCredential({
      compactSdJwt: compact,
      issuerJwk,
      options: {
        now_unix_seconds: now(),
        format: "w3c_vc_data_model",
        required_claims: [],
      },
    });
    assert.equal((receipt.processed_payload as any).iss, issuerDid);
    return compact;
  };
  const government = await receive(
    setup.government_identity_offer_uri,
    config.governmentIssuerDid,
  );
  await presentEnrolment(
    config,
    setup.enrolment.requestUri,
    government,
    holderKeyId,
    text,
    postForm,
  );
  const continued = await json(setups, "POST", setupInput, auth, 201);
  const education = await receive(
    continued.education_offer_uri,
    config.educationIssuerDid,
  );
  return { education, holderKeyId, holder, owner, call, json, text, postForm };
}

export async function presentEnrolment(
  config: Pick<Config, "registryOrigin" | "trustAnchorJwk">,
  requestUri: string,
  government: string,
  holderKeyId: string,
  text: (url: string) => Promise<string>,
  postForm: (
    url: string,
    body: Record<string, string>,
    deadline?: number,
  ) => Promise<unknown>,
  clock = now,
  sign = core.presentSdJwt,
) {
  const compact = await text(requestUri);
  const hint = JSON.parse(
    Buffer.from(compact.split(".")[1] ?? "", "base64url").toString(),
  );
  if (
    typeof hint.client_id !== "string" ||
    !hint.client_id.startsWith("decentralized_identifier:")
  )
    throw Error("REQUEST_LOCATION_REFUSED");
  const didUrl = core.didWebToHttpsUrl(
    hint.client_id.slice("decentralized_identifier:".length),
  );
  const [document, trust] = await Promise.all([
    text(didUrl),
    text(config.registryOrigin + "/trust-list.jwt"),
  ]);
  // All HTTP evidence is fetched before the independent verification clock is sampled.
  const verified = core.verifyOid4vpRequestObject({
    compactJws: compact,
    resolverResponses: { [didUrl]: document },
    nowUnixSeconds: clock(),
  });
  const request = verified.payload as any;
  const claims = ["family_name", "given_name", "date_of_birth"].map((field) => [
    "credentialSubject",
    field,
  ]);
  const query = request.dcql_query.credentials;
  if (
    query.length !== 1 ||
    query[0].id !== "enrolment_government_identity" ||
    query[0].format !== "vc+sd-jwt" ||
    JSON.stringify(query[0].claims.map((claim: any) => claim.path)) !==
      JSON.stringify(claims) ||
    JSON.stringify(query[0].meta?.type_values) !==
      JSON.stringify([
        [
          "https://www.w3.org/2018/credentials#VerifiableCredential",
          "GovernmentIdentityCredential",
        ],
      ])
  )
    throw Error("REQUEST_SCOPE_NOT_PERMITTED");
  const location = new URL(requestUri),
    response = new URL(request.response_uri),
    authenticatedOrigin = new URL(didUrl).origin;
  if (
    location.protocol !== "https:" ||
    location.origin !== authenticatedOrigin ||
    location.hash ||
    location.username ||
    location.password ||
    response.protocol !== "https:" ||
    response.origin !== authenticatedOrigin ||
    response.hash ||
    response.username ||
    response.password
  )
    throw Error("REQUEST_LOCATION_REFUSED");
  core.verifyVerifierTrustListAccreditation({
    compactJws: trust,
    trustAnchorJwk: config.trustAnchorJwk,
    verifierDid: verified.verifier_did,
    credentialType: "GovernmentIdentityCredential",
    profileName: "enrolment_government_identity",
    requestedClaimPaths: claims,
    nowUnixSeconds: clock(),
  });
  const trustPayload = core.verifyCompactJwsJson({
    compactJws: trust,
    publicJwk: config.trustAnchorJwk,
  }).payload as any;
  const deadline = Math.min(request.exp, trustPayload.exp);
  if (clock() >= deadline) throw Error("FRESHNESS_CHECK_FAILED");
  const presentation = sign({
    compactSdJwt: government,
    profile: { name: "enrolment_government_identity", claim_paths: claims },
    holderKeyId,
    audience: request.client_id,
    nonce: request.nonce,
    iat: clock(),
  }).presentation;
  return postForm(
    request.response_uri,
    {
      state: request.state,
      vp_token: JSON.stringify({
        enrolment_government_identity: [presentation],
      }),
    },
    deadline,
  );
}

export async function registeredCeremonies(
  config: Config,
  flow: Awaited<ReturnType<typeof runEducation>>,
) {
  const { call, text, postForm, education, holderKeyId } = flow;
  const documentUrl = config.runtimeOrigin + "/.well-known/did.json";
  const document = JSON.parse(await text(documentUrl));
  const verifierDid = core.didWebFromHost(new URL(config.runtimeOrigin).host);
  assert.equal(document.id, verifierDid);
  assert.equal(document.verificationMethod.length, 1);
  const key = document.verificationMethod[0];
  const permissionUrl =
    config.registryOrigin +
    "/scoped-verifier-permissions.jwt?verifier_did=" +
    encodeURIComponent(verifierDid);
  const permissions = await text(permissionUrl);
  const authenticated = core.verifyCompactJwsJson({
    compactJws: permissions,
    publicJwk: config.trustAnchorJwk,
  }).payload as any;
  assert.equal(authenticated.issuer, config.registryDid);
  assert.equal(authenticated.id, permissionUrl);
  const browser = async () => {
    let cookie = "";
    let csrf = "";
    return {
      async request(path: string, method = "GET", body?: unknown) {
        const response = await call(
          config.applicationOrigin + path,
          method,
          body,
          {
            ...(cookie ? { cookie } : {}),
            ...(method === "POST"
              ? { origin: config.applicationOrigin, "x-csrf-token": csrf }
              : {}),
          },
        );
        const set = response.headers["set-cookie"];
        if (set) cookie = set[0].split(";")[0];
        const value = response.json();
        if (typeof value.csrf === "string") csrf = value.csrf;
        return { status: response.status, value };
      },
    };
  };
  const a = await browser(),
    b = await browser();
  assert.equal((await a.request("/api/session")).status, 200);
  assert.equal((await b.request("/api/session")).status, 200);
  let accountId: string | undefined;
  for (const profile of [
    "education_sign_in",
    "education_sign_in",
    "education_eligibility",
  ]) {
    const created = await a.request("/api/interactions", "POST", { profile });
    assert.equal(created.status, 201);
    const interaction = created.value;
    const stolen = await b.request(
      "/api/interactions/" + interaction.id + "/complete",
      "POST",
      {},
    );
    assert.equal(stolen.status, 404);
    assert.equal(stolen.value.error.code, "INTERACTION_NOT_FOUND");
    const compactJws = await text(interaction.request_uri);
    const verified = core.verifyOid4vpRequestObject({
      compactJws,
      resolverResponses: { [documentUrl]: JSON.stringify(document) },
      nowUnixSeconds: now(),
    });
    const request = verified.payload as any;
    assert.equal(verified.verifier_did, verifierDid);
    assert.equal(new URL(interaction.request_uri).origin, config.runtimeOrigin);
    const response = new URL(request.response_uri);
    assert.equal(response.origin, config.runtimeOrigin);
    assert.equal(response.protocol, "https:");
    assert.equal(response.hash, "");
    assert.equal(request.dcql_query.credentials.length, 1);
    assert.equal(verified.header.kid, key.id);
    const query = request.dcql_query.credentials[0];
    assert.equal(query.id, profile);
    if (
      query.format !== "vc+sd-jwt" ||
      JSON.stringify(query.meta?.type_values) !==
        JSON.stringify([
          [
            "https://www.w3.org/2018/credentials#VerifiableCredential",
            "UniversityEducationCredential",
          ],
        ])
    )
      throw Error("REQUEST_SCOPE_NOT_PERMITTED");
    assert.deepEqual(
      query.claims.map((claim: any) => claim.path),
      paths(profile),
    );
    core.verifyScopedVerifierPermission({
      compactJws: permissions,
      trustAnchorJwk: config.trustAnchorJwk,
      request: {
        credential_issuer_did: config.educationIssuerDid,
        definition_id: "urn:credworks:education",
        definition_version: "1",
        credential_type: "UniversityEducationCredential",
        verifier_did: verifierDid,
        verifier_origin: config.runtimeOrigin,
        verifier_public_jwk: key.publicKeyJwk,
        profile_name: profile,
        claim_paths: paths(profile),
      },
      nowUnixSeconds: now(),
    });
    const vp = core.presentSdJwt({
      compactSdJwt: education,
      profile: { name: profile, claim_paths: paths(profile) },
      holderKeyId,
      audience: request.client_id,
      nonce: request.nonce,
      iat: now(),
    }).presentation;
    const accepted = await postForm(
      request.response_uri,
      {
        state: request.state,
        vp_token: JSON.stringify({ [profile]: [vp] }),
      },
      Math.min(request.exp, authenticated.exp),
    );
    assert.deepEqual(accepted, { status: "accepted" }); // Delivery is not verification.
    const result = await a.request(
      "/api/interactions/" + interaction.id + "/complete",
      "POST",
      {},
    );
    assert.equal(result.status, 200);
    if (profile === "education_sign_in") {
      assert.equal(result.value.status, "signed_in");
      if (accountId) assert.equal(result.value.account_id, accountId);
      accountId = result.value.account_id;
      await a.request("/api/session");
    } else {
      assert.deepEqual(result.value, { status: "eligible" });
      assert.equal(JSON.stringify(query.claims).includes("student_id"), false);
      const replay = await a.request(
        "/api/interactions/" + interaction.id + "/complete",
        "POST",
        {},
      );
      assert.equal(replay.status, 409);
      assert.equal(replay.value.error.code, "INTERACTION_CONSUMED");
    }
  }
  return {
    status: "passed",
    attestation: "self-asserted mock_platform_attestation; NOT physical",
    cases: [
      "government-enrolment-education",
      "browser-correlation",
      "sign-in-account-continuity",
      "identifier-free-eligibility",
      "one-time-completion",
    ],
  };
}

if (process.argv[1]?.endsWith("education-http.ts")) {
  try {
    const config = JSON.parse(readFileSync(process.argv[2]!, "utf8"));
    const flow = await runEducation(config);
    console.log(JSON.stringify(await registeredCeremonies(config, flow)));
  } catch {
    // No activation URI, presentation, claims, code, bearer or raw exception is logged.
    console.error("EDUCATION_HTTP_ACCEPTANCE_FAILED");
    process.exitCode = 1;
  }
}
