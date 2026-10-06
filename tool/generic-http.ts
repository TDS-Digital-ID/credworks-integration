/** Portable software holder. Native signing and verification use the shared Rust core. */
import * as core from '@unsw-vc/identity-core-node';
import assert from 'node:assert/strict';
import { isDeepStrictEqual } from 'node:util';
import { mkdirSync, readdirSync, lstatSync, readFileSync, writeFileSync, renameSync, openSync, fsyncSync, closeSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { httpClient } from './http-client.mjs';
export type GenericConfig = {
    registryOrigin: string;
    registryDid: string;
    trustAnchorJwk: core.PublicJwk;
    providerOrigin: string;
    providerDid: string;
    providerJwk: core.PublicJwk;
    issuerOrigin: string;
    issuerManagementOrigin: string;
    issuerManagementToken: string;
    verifierOrigin: string;
    verifierManagementOrigin: string;
    verifierManagementToken: string;
    stateDir: string;
    configurationId: string;
    verifierConfigurationId?: string;
    definitionId: string;
    definitionVersion: string;
    credentialType: string;
    profileName: string;
    claimPaths: string[][];
    authorizationPath: string;
    permissionPath: string;
    statusKeyId: string;
    statusPublicJwk: core.PublicJwk;
    projectId?: string;
    ownerCredential?: string;
    issuerRegistrationId?: string;
};
export type Receipt = {
    issuanceId: string;
    compact: string;
    payload: any;
    issuerKeyId: string;
    issuerJwk: core.PublicJwk;
    authorization: string;
    observedAt: number;
    deadline: number;
    response: any;
};
const seconds = () => Math.floor(Date.now() / 1000);
const hint = (compact: string, part: number) => JSON.parse(Buffer.from(compact.split('.')[part]!, 'base64url').toString('utf8'));
const check = (condition: unknown, code: string): void => {
    if (!condition)
        throw Error(code);
};
const deadline = (value: number, clock: () => number) => check(Number.isFinite(value) && clock() < value, 'FRESHNESS_CHECK_FAILED');
function requireSupportedQuery(dcql: unknown): void {
    const exact = (value: any, keys: string[]) => value !== null && typeof value === 'object' && !Array.isArray(value) && isDeepStrictEqual(Object.keys(value).sort(), keys.sort());
    const query = (dcql as any)?.credentials?.[0];
    check(exact(dcql, ['credentials']) && Array.isArray((dcql as any).credentials) && (dcql as any).credentials.length === 1 && exact(query, ['id', 'format', 'meta', 'claims']) && exact(query.meta, ['type_values']) && Array.isArray(query.claims) && query.claims.length >= 1 && query.claims.length <= 64 && query.claims.every((claim: any) => exact(claim, ['path']) && Array.isArray(claim.path) && claim.path.length >= 2 && claim.path.length <= 16 && claim.path.every((part: any) => typeof part === 'string')), 'REQUEST_SCOPE_NOT_PERMITTED');
}
export function openGeneric(config: GenericConfig, client?: ReturnType<typeof httpClient>, clock = seconds) {
    for (const origin of [config.registryOrigin, config.providerOrigin, config.issuerOrigin, config.verifierOrigin]) {
        const url = new URL(origin);
        check(url.protocol === 'https:' && url.origin === origin && !url.username && !url.password, 'HTTP_ORIGIN_REFUSED');
    }
    for (const origin of [config.issuerManagementOrigin, config.verifierManagementOrigin]) {
        const url = new URL(origin);
        check(url.protocol === 'http:' && url.hostname === '127.0.0.1' && url.origin === origin, 'MANAGEMENT_LOCATION_REFUSED');
    }
    for (const path of [config.authorizationPath, config.permissionPath])
        check(/^\/(issuer-authorizations|scoped-verifier-permissions)\/[0-9a-f-]{36}\.jwt$/.test(path), 'REGISTRY_LOCATION_REFUSED');
    mkdirSync(config.stateDir, {
        recursive: true,
        mode: 0o700
    });
    const directory = lstatSync(config.stateDir);
    check(directory.isDirectory() && (directory.mode & 0o777) === 0o700, 'PRIVATE_STATE_REFUSED');
    const save = (name: string, value: unknown) => {
        check(/^[A-Za-z0-9_-]+$/.test(name), 'PRIVATE_STATE_REFUSED');
        const tmp = join(config.stateDir, '.' + randomUUID());
        writeFileSync(tmp, JSON.stringify(value) + '\n', {
            mode: 0o600,
            flag: 'wx'
        });
        const fd = openSync(tmp, 'r');
        try {
            fsyncSync(fd);
        }
        finally {
            closeSync(fd);
        }
        renameSync(tmp, join(config.stateDir, name + '.json'));
        const dirfd = openSync(config.stateDir, 'r');
        try {
            fsyncSync(dirfd);
        }
        finally {
            closeSync(dirfd);
        }
    };
    const load = (name: string): any => {
        check(/^[A-Za-z0-9_-]+$/.test(name), 'PRIVATE_STATE_REFUSED');
        const path = join(config.stateDir, name + '.json');
        const st = lstatSync(path);
        check(st.isFile() && (st.mode & 0o777) === 0o600 && st.size <= 2097152, 'PRIVATE_STATE_REFUSED');
        return JSON.parse(readFileSync(path, 'utf8'));
    };
    let secret;
    let newHolder = false;
    try {
        secret = load('holder');
    }
    catch (error: any) {
        if (error.code !== 'ENOENT')
            throw error;
        check(readdirSync(config.stateDir).length === 0, 'PRIVATE_STATE_REFUSED');
        newHolder = true;
        secret = {
            keyId: 'holder:kit:' + core.randomUrlSafe(16),
            unlock: core.randomUrlSafe(32)
        };
        writeFileSync(join(config.stateDir, 'holder.json'), JSON.stringify(secret), {
            mode: 0o600,
            flag: 'wx'
        });
    }
    const hasKey = existsReceiptKey();
    check(newHolder ? !hasKey : hasKey, 'PRIVATE_STATE_REFUSED');
    const holder = core.persistentSigningKey({
        path: join(config.stateDir, 'holder.key'),
        unlockKey: secret.unlock,
        keyId: secret.keyId,
        create: newHolder
    });
    function existsReceiptKey() {
        try {
            const s = lstatSync(join(config.stateDir, 'holder.key'));
            check(s.isFile() && (s.mode & 0o777) === 0o600, 'PRIVATE_STATE_REFUSED');
            return true;
        }
        catch (error: any) {
            if (error.code === 'ENOENT')
                return false;
            throw error;
        }
    }
    const issuerDid = core.didWebFromHost(new URL(config.issuerOrigin).host);
    const verifierDid = core.didWebFromHost(new URL(config.verifierOrigin).host);
    const allowed = new Set([config.registryOrigin, config.providerOrigin, config.issuerOrigin, config.verifierOrigin, config.issuerManagementOrigin, config.verifierManagementOrigin]);
    const publicClient = client ?? httpClient();
    const issuerClient = client ?? httpClient({}, config.issuerManagementOrigin);
    const verifierClient = client ?? httpClient({}, config.verifierManagementOrigin);
    const request = async (url: string, method = 'GET', body?: unknown, headers: Record<string, string> = {}, expected = 200, limit = 131072, expires?: number, form = false) => {
        const parsed = new URL(url);
        check(allowed.has(parsed.origin), 'HTTP_ORIGIN_REFUSED');
        const transport = parsed.origin === config.issuerManagementOrigin ? issuerClient : parsed.origin === config.verifierManagementOrigin ? verifierClient : publicClient;
        if (expires !== undefined)
            deadline(expires, clock);
        const response = await transport(url, {
            method,
            headers: {
                ...(body !== undefined ? { 'content-type': form ? 'application/x-www-form-urlencoded' : 'application/json' } : {}),
                ...headers
            },
            ...(body !== undefined ? { body: form ? new URLSearchParams(body as Record<string, string>).toString() : JSON.stringify(body) } : {}),
            responseLimit: limit,
            requestLimit: parsed.origin === config.registryOrigin && /^\/api\/projects\/[0-9a-f-]{36}\/issuers\/[0-9a-f-]{36}\/(?:definitions|adoptions\/[0-9a-f-]{36}\/verifier-grants)$/.test(parsed.pathname) ? 262144 : 131072,
            ...(expires !== undefined ? { deadline: expires } : {})
        });
        if (response.status !== expected) {
            let code;
            try {
                const value = response.json();
                code = typeof value.error === 'string' ? value.error : value.error?.code;
            }
            catch { }
            throw Error(typeof code === 'string' && /^[A-Za-z0-9_]+$/.test(code) ? code : 'HTTP_STATUS_REFUSED_' + response.status);
        }
        if (expires !== undefined)
            deadline(expires, clock);
        return response;
    };
    const json = async (...args: Parameters<typeof request>) => (await request(...args)).json();
    const text = async (url: string, limit = 131072) => (await request(url, 'GET', undefined, {}, 200, limit)).text;
    const management = (role: 'issuer' | 'verifier', path: string, body?: unknown, expected = 200, headers = {}) => json((role === 'issuer' ? config.issuerManagementOrigin : config.verifierManagementOrigin) + path, body === undefined ? 'GET' : 'POST', body, {
        authorization: 'Bearer ' + (role === 'issuer' ? config.issuerManagementToken : config.verifierManagementToken),
        ...headers
    }, expected);
    const registryPayload = (compact: string, path: string) => {
        const value = core.verifyCompactJwsJson({
            compactJws: compact,
            publicJwk: config.trustAnchorJwk
        }).payload as any;
        check(value.issuer === config.registryDid && value.id === config.registryOrigin + path, 'TRUST_CHECK_FAILED');
        return value;
    };
    const authority = (compact: string, keyId: string, jwk: core.PublicJwk, purpose: 'issuance' | 'verification', at = clock()) => {
        const grant = core.verifyIssuerAuthorization({
            compactJws: compact,
            trustAnchorJwk: config.trustAnchorJwk,
            request: {
                registry_did: config.registryDid,
                credential_issuer_did: issuerDid,
                credential_issuer_key_id: keyId,
                credential_issuer_public_jwk: jwk,
                definition_id: config.definitionId,
                definition_version: config.definitionVersion,
                credential_type: config.credentialType,
                purpose
            },
            nowUnixSeconds: at
        });
        check((grant.status_authority?.key_id ?? keyId) === config.statusKeyId && (grant.status_authority?.public_jwk_sha256_thumbprint ?? core.publicJwkSha256Thumbprint(jwk)) === core.publicJwkSha256Thumbprint(config.statusPublicJwk), 'STATUS_CHECK_FAILED');
        return grant;
    };
    const authenticatedReceipt = (receipt: Receipt, auth: string, at = clock()) => {
        authority(auth, receipt.issuerKeyId, receipt.issuerJwk, 'verification', at);
        const verified = core.verifyScalarCredentialAuthorization({
            compactSdJwt: receipt.compact,
            issuerJwk: receipt.issuerJwk,
            compactAuthorization: auth,
            trustAnchorJwk: config.trustAnchorJwk,
            registryDid: config.registryDid,
            nowUnixSeconds: at,
            mode: 'complete'
        });
        return receiptBinding(receipt, verified);
    };
    const receiptBinding = (receipt: Receipt, verified: core.VerifiedSdJwtCredential) => {
        const payload = verified.processed_payload as any;
        check(verified.issuer_header.kid === receipt.issuerKeyId && payload.iss === issuerDid && payload.credentialDefinition?.id === config.definitionId && payload.credentialDefinition?.version === config.definitionVersion, 'TRUST_CHECK_FAILED');
        check(core.publicJwkSha256Thumbprint(payload.cnf.jwk) === core.publicJwkSha256Thumbprint(holder), 'BINDING_CHECK_FAILED');
        return payload;
    };
    const status = async (receipt: Receipt) => {
        const payload = authenticatedReceipt(receipt, receipt.authorization, receipt.observedAt);
        const reference = payload.credentialStatus as core.CredentialStatus;
        check(reference.statusListCredential === config.issuerOrigin + '/oid4vci/status/revocation.jwt' && reference.statusPurpose === 'revocation', 'STATUS_CHECK_FAILED');
        const name = 'negative-' + receipt.issuanceId;
        try {
            const negative = load(name);
            check(negative.credentialId === payload.id && negative.keyId === receipt.issuerKeyId && negative.credentialPin === core.publicJwkSha256Thumbprint(receipt.issuerJwk) && negative.statusKeyId === config.statusKeyId && negative.statusPin === core.publicJwkSha256Thumbprint(config.statusPublicJwk), 'STATUS_CHECK_FAILED');
            const resolved = core.resolveCredentialStatusAt({
                status: reference,
                resolverResponses: { [reference.statusListCredential]: negative.signed },
                statusListJwk: config.statusPublicJwk,
                nowUnixSeconds: negative.observedAt
            });
            check(resolved.revoked, 'STATUS_CHECK_FAILED');
            return {
                revoked: true,
                deadline: negative.deadline,
                original: true
            };
        }
        catch (error: any) {
            if (error.code !== 'ENOENT')
                throw error;
        }
        const signed = await text(reference.statusListCredential), at = clock();
        const [statusHeader, verified] = core.verifyBitstringStatusListCredentialAt({
            compactJws: signed,
            statusListJwk: config.statusPublicJwk,
            nowUnixSeconds: at
        });
        check(statusHeader.kid === config.statusKeyId && verified.issuer === issuerDid, 'STATUS_CHECK_FAILED');
        const resolved = core.resolveCredentialStatusAt({
            status: reference,
            resolverResponses: { [reference.statusListCredential]: signed },
            statusListJwk: config.statusPublicJwk,
            nowUnixSeconds: at
        });
        const expiry = Date.parse(verified.validUntil!) / 1000;
        deadline(expiry, clock);
        if (resolved.revoked)
            save(name, {
                credentialId: payload.id,
                keyId: receipt.issuerKeyId,
                credentialPin: core.publicJwkSha256Thumbprint(receipt.issuerJwk),
                statusKeyId: config.statusKeyId,
                statusPin: core.publicJwkSha256Thumbprint(config.statusPublicJwk),
                signed,
                observedAt: at,
                deadline: expiry
            });
        return {
            revoked: resolved.revoked,
            deadline: expiry,
            original: false
        };
    };
    const fresh = async (receipt: Receipt, expires?: number) => {
        const auth = await text(config.registryOrigin + config.authorizationPath, 262144);
        registryPayload(auth, config.authorizationPath);
        authority(auth, receipt.issuerKeyId, receipt.issuerJwk, 'verification');
        authenticatedReceipt(receipt, auth);
        const observed = await status(receipt);
        check(!observed.revoked, 'STATUS_CHECK_FAILED');
        if (expires !== undefined)
            deadline(expires, clock);
        return {
            auth,
            deadline: Math.min(registryPayload(auth, config.authorizationPath).exp, observed.deadline, receipt.payload.exp)
        };
    };
    const createOffer = (input: any) => management('issuer', '/management/issuer/offers', {
        configuration_id: config.configurationId,
        ...input,
        recipient_jwk_thumbprint: core.publicJwkSha256Thumbprint(holder)
    }, 201);
    const receive = async (offered: any, operationName?: string) => {
        const uri = typeof offered === 'string' ? offered : offered.credential_offer_uri;
        check(new URL(uri).origin === config.issuerOrigin, 'HTTP_ORIGIN_REFUSED');
        const name = operationName ?? 'receive-' + new URL(uri).pathname.split('/').at(-1);
        let operation: any;
        try {
            operation = load(name);
            check(operation.offerUri === uri, 'BINDING_CHECK_FAILED');
        }
        catch (error: any) {
            if (error.code !== 'ENOENT')
                throw error;
            operation = { offerUri: uri };
            save(name, operation);
        }
        if (operation.receipt) {
            authenticatedReceipt(operation.receipt, operation.receipt.authorization, operation.receipt.observedAt);
            return operation.receipt as Receipt;
        }
        const [metadata, oauth, offer, document, auth] = await Promise.all([json(config.issuerOrigin + '/.well-known/openid-credential-issuer'), json(config.issuerOrigin + '/.well-known/oauth-authorization-server'), operation.offer ?? (operation.token ? undefined : json(uri)), text(core.didWebToHttpsUrl(issuerDid), 262144), text(config.registryOrigin + config.authorizationPath, 262144)]);
        check(metadata.credential_issuer === config.issuerOrigin && (!offer || offer.credential_issuer === config.issuerOrigin), 'TRUST_CHECK_FAILED');
        if (offer) {
            check(isDeepStrictEqual(offer.credential_configuration_ids, [config.configurationId]), 'DEFINITION_NOT_ACCEPTED');
            operation.offer = offer;
            save(name, operation);
        }
        const supported = metadata.credential_configurations_supported[config.configurationId];
        check(supported?.format === 'vc+sd-jwt' && supported.credworks_issuer_authorization?.path === config.authorizationPath && isDeepStrictEqual(supported.credentialDefinition, {
            id: config.definitionId,
            version: config.definitionVersion
        }), 'TRUST_CHECK_FAILED');
        for (const endpoint of [oauth.token_endpoint, metadata.nonce_endpoint, metadata.credential_endpoint])
            check(new URL(endpoint).origin === config.issuerOrigin, 'HTTP_ORIGIN_REFUSED');
        const publication = registryPayload(auth, config.authorizationPath);
        // Signed grants select current issuance authority; DID members are hints until the core authenticates them.
        const candidates = publication.authorizations.filter((g: any) => g.credential_issuer_did === issuerDid && g.definition.id === config.definitionId && g.definition.version === config.definitionVersion && (g.key_state ?? 'current') === 'current' && g.status === 'active');
        check(candidates.length === 1, 'TRUST_CHECK_FAILED');
        const selected = operation.review?.selected ?? candidates[0];
        const issuerJwk = operation.review?.issuerJwk ?? core.resolveDidWebKey({
            issuerDid,
            kid: selected.credential_issuer_key_id,
            resolverResponses: { [core.didWebToHttpsUrl(issuerDid)]: document }
        });
        const grant = authority(auth, selected.credential_issuer_key_id, issuerJwk, operation.body ? 'verification' : 'issuance');
        if (operation.review)
            check(isDeepStrictEqual(grant.definition, operation.review.definition), 'TRUST_CHECK_FAILED');
        else {
            operation.review = {
                selected,
                issuerJwk,
                definition: grant.definition,
                authorization: auth,
                observedAt: clock()
            };
            save(name, operation);
        }
        const statusAuthority = grant.status_authority;
        check((statusAuthority?.key_id ?? selected.credential_issuer_key_id) === config.statusKeyId && (statusAuthority?.public_jwk_sha256_thumbprint ?? core.publicJwkSha256Thumbprint(issuerJwk)) === core.publicJwkSha256Thumbprint(config.statusPublicJwk), 'STATUS_CHECK_FAILED');
        operation.deadline = Math.min(operation.deadline ?? Infinity, publication.exp, offered.expires_at ?? Infinity);
        deadline(operation.deadline, clock);
        save(name, operation);
        if (!operation.token) {
            check(!operation.tokenAttempted, 'TOKEN_DELIVERY_UNCERTAIN');
            operation.tokenAttempted = true;
            save(name, operation);
            operation.tokenObservedAt = clock();
            operation.token = await json(oauth.token_endpoint, 'POST', {
                grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
                'pre-authorized_code': offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']['pre-authorized_code']
            }, {}, 200, 131072, operation.deadline, true);
            save(name, operation);
        }
        if (!operation.body) {
            const nonceObservedAt = clock();
            const nonce = await json(metadata.nonce_endpoint, 'POST');
            const wia = await json(config.providerOrigin + '/wallet-instance-attestations', 'POST', {
                credential_issuer: config.issuerOrigin,
                holder_public_jwk: holder,
                attestation_evidence: {
                    evidence_type: 'mock_platform_attestation',
                    platform: 'headless-sandbox',
                    device_id: randomUUID(),
                    challenge: core.publicJwkSha256Thumbprint(holder)
                }
            }, {}, 201);
            const attestation = core.verifyCompactJwsJson({
                compactJws: wia.wallet_instance_attestation,
                publicJwk: config.providerJwk
            }).payload as any;
            check(attestation.iss === config.providerDid && attestation.aud === config.issuerOrigin && core.publicJwkSha256Thumbprint(attestation.cnf.jwk) === core.publicJwkSha256Thumbprint(holder), 'BINDING_CHECK_FAILED');
            check(attestation.iat <= clock() && typeof attestation.exp === 'number' && attestation.exp > clock(), 'FRESHNESS_CHECK_FAILED');
            operation.deadline = Math.min(operation.deadline, attestation.exp, operation.tokenObservedAt + operation.token.expires_in, nonceObservedAt + nonce.c_nonce_expires_in);
            deadline(operation.deadline, clock);
            operation.body = {
                credential_configuration_id: config.configurationId,
                holder_public_jwk: holder,
                wallet_instance_attestation: wia.wallet_instance_attestation,
                proofs: { jwt: [core.createKeyProof({
                            audience: config.issuerOrigin,
                            nonce: nonce.c_nonce,
                            iat: clock(),
                            keyId: secret.keyId,
                            publicJwk: holder
                        })] }
            };
            save(name, operation);
        }
        const response = await json(metadata.credential_endpoint, 'POST', operation.body, { authorization: 'Bearer ' + operation.token.access_token }, 200, 131072, operation.deadline);
        const compact = response.credentials?.[0]?.credential;
        check(typeof compact === 'string', 'CREDENTIAL_RESPONSE_INVALID');
        const receipt: Receipt = {
            issuanceId: new URL(uri).pathname.split('/').at(-1)!,
            compact,
            payload: null,
            issuerKeyId: selected.credential_issuer_key_id,
            issuerJwk,
            authorization: auth,
            observedAt: clock(),
            deadline: operation.deadline,
            response
        };
        receipt.payload = authenticatedReceipt(receipt, auth);
        check(hint(compact, 0).kid === receipt.issuerKeyId, 'TRUST_CHECK_FAILED');
        const observed = await status(receipt);
        check(!observed.revoked, 'STATUS_CHECK_FAILED');
        receipt.deadline = Math.min(receipt.deadline, observed.deadline, receipt.payload.exp);
        deadline(receipt.deadline, clock);
        operation.receipt = receipt;
        save(name, operation);
        save('receipt-' + receipt.issuanceId, receipt);
        return receipt;
    };
    const createSession = async (interactionId: string, purpose = 'Present selected credential') => {
        const session = await management('verifier', '/management/sessions', {
            configuration_id: config.verifierConfigurationId ?? config.configurationId,
            profile: config.profileName,
            interaction_id: interactionId,
            purpose
        }, 201);
        save('session-' + session.session_id, session);
        return session;
    };
    const present = async (session: any, receipt: Receipt) => {
        check(new URL(session.request_uri).origin === config.verifierOrigin, 'HTTP_ORIGIN_REFUSED');
        const [compact, document, auth, permission] = await Promise.all([text(session.request_uri, 262144), text(core.didWebToHttpsUrl(verifierDid)), text(config.registryOrigin + config.authorizationPath, 262144), text(config.registryOrigin + config.permissionPath, 262144)]);
        const verified = core.verifyOid4vpRequestObject({
            compactJws: compact,
            resolverResponses: { [core.didWebToHttpsUrl(verifierDid)]: document },
            nowUnixSeconds: clock()
        });
        const request = verified.payload as any;
        check(verified.verifier_did === verifierDid && request.client_id === 'decentralized_identifier:' + verifierDid && new URL(request.response_uri).origin === config.verifierOrigin, 'TRUST_CHECK_FAILED');
        const context = request.credworks_scalar;
        check(context && isDeepStrictEqual(Object.keys(context).sort(), ['credential_issuer_did', context.credential_issuer_keys ? 'credential_issuer_keys' : 'credential_issuer_key_id', 'definition_id', 'definition_version', 'authorization_path', 'permission_path', 'profile_name'].sort()), 'REQUEST_SCOPE_NOT_PERMITTED');
        check(context.credential_issuer_did === issuerDid && context.definition_id === config.definitionId && context.definition_version === config.definitionVersion && context.authorization_path === config.authorizationPath && context.permission_path === config.permissionPath && context.profile_name === config.profileName, 'REQUEST_SCOPE_NOT_PERMITTED');
        requireSupportedQuery(request.dcql_query);
        const query = request.dcql_query?.credentials;
        check(query?.length === 1 && query[0].id === config.profileName && query[0].format === 'vc+sd-jwt' && isDeepStrictEqual(query[0].claims.map((claim: any) => claim.path), config.claimPaths) && isDeepStrictEqual(query[0].meta?.type_values, [['https://www.w3.org/2018/credentials#VerifiableCredential', config.credentialType]]), 'REQUEST_SCOPE_NOT_PERMITTED');
        const grant = authority(auth, receipt.issuerKeyId, receipt.issuerJwk, 'verification');
        check(isDeepStrictEqual(grant.definition.profiles.find(p => p.name === config.profileName)?.claim_paths, config.claimPaths), 'REQUEST_SCOPE_NOT_PERMITTED');
        if (context.credential_issuer_keys) {
            const members = context.credential_issuer_keys;
            check(Array.isArray(members) && members.length >= 1 && members.length <= 64 && new Set(members.map((m: any) => m.key_id)).size === members.length, 'TRUST_CHECK_FAILED');
            for (const member of members)
                check(isDeepStrictEqual(Object.keys(member).sort(), ['key_id', 'public_jwk_sha256_thumbprint']) && typeof member.key_id === 'string' && member.key_id.startsWith(issuerDid + '#') && /^[A-Za-z0-9._-]{1,128}$/.test(member.key_id.slice(issuerDid.length + 1)) && /^[A-Za-z0-9_-]{43}$/.test(member.public_jwk_sha256_thumbprint), 'TRUST_CHECK_FAILED');
            const issuerDocument = await text(core.didWebToHttpsUrl(issuerDid), 262144);
            for (const member of members) {
                const jwk = core.resolveDidWebKey({
                    issuerDid,
                    kid: member.key_id,
                    resolverResponses: { [core.didWebToHttpsUrl(issuerDid)]: issuerDocument }
                });
                check(core.publicJwkSha256Thumbprint(jwk) === member.public_jwk_sha256_thumbprint, 'TRUST_CHECK_FAILED');
                const advertised = authority(auth, member.key_id, jwk, 'verification');
                check(isDeepStrictEqual(advertised.definition, grant.definition) && isDeepStrictEqual(advertised.status_authority, grant.status_authority), 'TRUST_CHECK_FAILED');
            }
            check(members.some((m: any) => m.key_id === receipt.issuerKeyId && m.public_jwk_sha256_thumbprint === core.publicJwkSha256Thumbprint(receipt.issuerJwk)), 'TRUST_CHECK_FAILED');
        }
        else
            check(context.credential_issuer_key_id === receipt.issuerKeyId, 'TRUST_CHECK_FAILED');
        const key = core.resolveDidWebKey({
            issuerDid: verifierDid,
            kid: verified.header.kid!,
            resolverResponses: { [core.didWebToHttpsUrl(verifierDid)]: document }
        });
        const permissionRequest = {
            credential_issuer_did: issuerDid,
            definition_id: config.definitionId,
            definition_version: config.definitionVersion,
            credential_type: config.credentialType,
            verifier_did: verifierDid,
            verifier_origin: config.verifierOrigin,
            verifier_public_jwk: key,
            profile_name: config.profileName,
            claim_paths: config.claimPaths
        };
        core.verifyScopedVerifierPermission({ compactJws: permission, trustAnchorJwk: config.trustAnchorJwk, request: permissionRequest, nowUnixSeconds: clock() });
        const permissionPayload = registryPayload(permission, config.permissionPath), authorizationPayload = registryPayload(auth, config.authorizationPath);
        authenticatedReceipt(receipt, auth);
        const observed = await status(receipt);
        check(!observed.revoked, 'STATUS_CHECK_FAILED');
        const name = 'presentation-' + session.session_id;
        let original: any;
        try {
            original = load(name);
            check(original.compact === compact && original.credentialId === receipt.payload.id, 'BINDING_CHECK_FAILED');
        }
        catch (error: any) {
            if (error.code !== 'ENOENT')
                throw error;
            original = {
                compact,
                credentialId: receipt.payload.id,
                permission,
                authorization: auth
            };
        }
        original.deadline = Math.min(original.deadline ?? Infinity, request.exp, session.expires_at, permissionPayload.exp, authorizationPayload.exp, observed.deadline, receipt.payload.exp);
        deadline(original.deadline, clock);
        save(name, original);
        const presentation = core.presentSdJwt({
            compactSdJwt: receipt.compact,
            profile: {
                name: config.profileName,
                claim_paths: config.claimPaths
            },
            holderKeyId: secret.keyId,
            audience: request.client_id,
            nonce: request.nonce,
            iat: clock()
        }).presentation;
        original.deadline = Math.min(original.deadline, (await fresh(receipt, original.deadline)).deadline);
        deadline(original.deadline, clock);
        save(name, original);
        const [currentPermission, currentDocument] = await Promise.all([
            text(config.registryOrigin + config.permissionPath, 262144),
            text(core.didWebToHttpsUrl(verifierDid)),
        ]);
        const currentRequest = core.verifyOid4vpRequestObject({
            compactJws: compact,
            resolverResponses: { [core.didWebToHttpsUrl(verifierDid)]: currentDocument },
            nowUnixSeconds: clock(),
        });
        const currentKey = core.resolveDidWebKey({ issuerDid: verifierDid, kid: currentRequest.header.kid!, resolverResponses: { [core.didWebToHttpsUrl(verifierDid)]: currentDocument } });
        check(core.publicJwkSha256Thumbprint(currentKey) === core.publicJwkSha256Thumbprint(key), 'TRUST_CHECK_FAILED');
        core.verifyScopedVerifierPermission({ compactJws: currentPermission, trustAnchorJwk: config.trustAnchorJwk, request: permissionRequest, nowUnixSeconds: clock() });
        original.deadline = Math.min(original.deadline, registryPayload(currentPermission, config.permissionPath).exp);
        deadline(original.deadline, clock);
        save(name, original);
        const acknowledged = await json(request.response_uri, 'POST', {
            state: request.state,
            vp_token: JSON.stringify({ [config.profileName]: [presentation] })
        }, {}, 200, 131072, original.deadline, true);
        assert.deepEqual(acknowledged, { status: 'accepted' });
        return acknowledged;
    };
    const result = async (session: any) => {
        const value = await management('verifier', `/management/sessions/${session.session_id}/result`, {}, 200, { 'x-session-capability': session.correlation_capability });
        check(value.interaction_id === session.interaction_id, 'BINDING_CHECK_FAILED');
        save('result-' + session.session_id, value);
        return value;
    };
    const continuation = async (session: any, input: any, operationName = 'continue-' + session.session_id) => {
        let operation: any;
        try {
            operation = load(operationName);
            check(isDeepStrictEqual(operation.input, input), 'BINDING_CHECK_FAILED');
        }
        catch (error: any) {
            if (error.code !== 'ENOENT')
                throw error;
            operation = {
                input,
                idempotencyKey: core.randomUrlSafe(32)
            };
            save(operationName, operation);
        }
        const offer = await management('verifier', `/management/sessions/${session.session_id}/issuance-offer`, {
            configuration_id: config.configurationId,
            ...input,
            interaction_id: session.interaction_id
        }, 201, {
            'x-session-capability': session.correlation_capability,
            'idempotency-key': operation.idempotencyKey
        });
        operation.offer = offer;
        save(operationName, operation);
        return offer;
    };
    const createRenewal = async (receipt: Receipt, input: any, operationName: string) => {
        let operation: any;
        try {
            operation = load(operationName);
            check(operation.predecessor.payload.id === receipt.payload.id && isDeepStrictEqual(operation.input, input), 'BINDING_CHECK_FAILED');
        }
        catch (error: any) {
            if (error.code !== 'ENOENT')
                throw error;
            operation = {
                predecessor: receipt,
                input,
                idempotencyKey: core.randomUrlSafe(32)
            };
            save(operationName, operation);
        }
        operation.created = await management('issuer', '/management/issuer/renewals', {
            version: 1,
            predecessor_issuance_id: receipt.issuanceId,
            configuration_id: config.configurationId,
            ...input
        }, 201, { 'idempotency-key': operation.idempotencyKey });
        save(operationName, operation);
        return operation;
    };
    const holderProof = async (audience: string, expires?: number, capture?: (bound: number) => void) => {
        check(new URL(audience).origin === config.issuerOrigin, 'HTTP_ORIGIN_REFUSED');
        const nonceObservedAt = clock();
        const nonce = await json(config.issuerOrigin + '/oid4vci/nonce', 'POST');
        const bound = Math.min(expires ?? Infinity, nonceObservedAt + nonce.c_nonce_expires_in);
        deadline(bound, clock);
        capture?.(bound);
        const proof = {
            proof_type: 'jwt',
            jwt: core.createKeyProof({
                audience,
                nonce: nonce.c_nonce,
                iat: clock(),
                keyId: secret.keyId,
                publicJwk: holder
            })
        };
        deadline(bound, clock);
        return proof;
    };
    const renewalPayload = (receipt: Receipt, auth: string) => {
        const verified = core.verifyScalarRenewalPredecessor({
            compactSdJwt: receipt.compact,
            issuerJwk: receipt.issuerJwk,
            compactAuthorization: auth,
            trustAnchorJwk: config.trustAnchorJwk,
            registryDid: config.registryDid,
            nowUnixSeconds: clock()
        });
        const payload = receiptBinding(receipt, verified);
        check(isDeepStrictEqual(payload, receipt.payload), 'BINDING_CHECK_FAILED');
        return payload;
    };
    const retainedPredecessor = async (receipt: Receipt) => {
        const auth = await text(config.registryOrigin + config.authorizationPath, 262144);
        const current = authority(auth, receipt.issuerKeyId, receipt.issuerJwk, 'verification');
        const payload = renewalPayload(receipt, auth);
        const original = authority(receipt.authorization, receipt.issuerKeyId, receipt.issuerJwk, 'verification', receipt.observedAt);
        check(isDeepStrictEqual(current.definition, original.definition), 'TRUST_CHECK_FAILED');
        // Original receipt/status evidence retains its own authenticated observation;
        // it never supplies the positive renewal credential time.
        const observed = await status(receipt);
        check(!observed.revoked, 'STATUS_CHECK_FAILED');
        return { payload, deadline: Math.min(registryPayload(auth, config.authorizationPath).exp, observed.deadline) };
    };
    const renew = async (operationName: string) => {
        const operation = load(operationName);
        const uri = operation.created.renewal_request_uri;
        check(new URL(uri).origin === config.issuerOrigin, 'HTTP_ORIGIN_REFUSED');
        if (!operation.authorized) {
            const proposal = await json(uri);
            const prior = operation.predecessor as Receipt;
            const authenticatedPrior = await retainedPredecessor(prior);
            check(proposal.credential_issuer === config.issuerOrigin && proposal.configuration_id === config.configurationId && isDeepStrictEqual(proposal.definition, {
                id: config.definitionId,
                version: config.definitionVersion,
                credential_type: config.credentialType
            }) && proposal.predecessor.credential_id === authenticatedPrior.payload.id && proposal.predecessor.status_list_credential === authenticatedPrior.payload.credentialStatus.statusListCredential && proposal.predecessor.status_list_index === authenticatedPrior.payload.credentialStatus.statusListIndex && isDeepStrictEqual(proposal.claims, operation.input.claims) && proposal.valid_from === operation.input.valid_from && proposal.valid_until === operation.input.valid_until, 'BINDING_CHECK_FAILED');
            operation.deadline = Math.min(operation.deadline ?? Infinity, proposal.expires_at, operation.created.expires_at, authenticatedPrior.deadline);
            deadline(operation.deadline, clock);
            operation.proposal = proposal;
            operation.predecessorBinding = authenticatedPrior.payload;
            save(operationName, operation);
            const body = {
                version: 1,
                capability: new URL(uri).searchParams.get('capability'),
                proof: await holderProof(proposal.authorize_uri, operation.deadline, bound => { operation.deadline = bound; })
            };
            const rechecked = await retainedPredecessor(prior);
            check(isDeepStrictEqual(rechecked.payload, operation.predecessorBinding), 'BINDING_CHECK_FAILED');
            operation.deadline = Math.min(operation.deadline, rechecked.deadline);
            deadline(operation.deadline, clock);
            operation.lastAuthorization = body;
            save(operationName, operation);
            operation.authorized = await json(proposal.authorize_uri, 'POST', body, {}, 200, 131072, operation.deadline);
            save(operationName, operation);
        }
        if (!operation.predecessorBinding) {
            const auth = await text(config.registryOrigin + config.authorizationPath, 262144);
            authority(auth, operation.predecessor.issuerKeyId, operation.predecessor.issuerJwk, 'verification');
            operation.predecessorBinding = renewalPayload(operation.predecessor, auth);
            save(operationName, operation);
        }
        operation.successor = await receive(operation.authorized, operationName + '-delivery');
        const receipt = operation.successor.response.x_credworks_renewal;
        const canonical = config.issuerOrigin + '/partner-renewals/' + operation.created.renewal_id;
        check(receipt?.version === 1 && receipt.renewal_id === operation.created.renewal_id && receipt.predecessor_credential_id === operation.predecessorBinding.id && receipt.successor_credential_id === operation.successor.payload.id && receipt.confirm_uri === canonical + '/receipts/' + receipt.receipt_id + '/successors/' + operation.successor.issuanceId + '/confirm' && receipt.status_uri === canonical + '/status' && receipt.cancel_uri === canonical + '/cancel', 'BINDING_CHECK_FAILED');
        operation.receipt = receipt;
        save(operationName, operation);
        return operation.successor as Receipt;
    };
    const renewalOperation = async (operationName: string, action: 'status' | 'cancel' | 'confirm') => {
        const operation = load(operationName);
        const url = action === 'confirm' ? operation.receipt?.confirm_uri : config.issuerOrigin + '/partner-renewals/' + operation.created.renewal_id + '/' + action;
        check(typeof url === 'string', 'RECEIPT_REQUIRED');
        if (action === 'confirm') {
            check(operation.successor && operation.receipt, 'RECEIPT_REQUIRED');
            operation.deadline = Math.min(operation.deadline, (await fresh(operation.successor)).deadline);
            deadline(operation.deadline, clock);
            save(operationName, operation);
        }
        const body = {
            version: 1,
            ...(action === 'confirm' ? { event: 'credential_accepted' } : {}),
            proof: await holderProof(url, action === 'confirm' ? operation.deadline : undefined, bound => { operation.writeDeadline = bound; })
        };
        operation.lastOperation = {
            action,
            url,
            body
        };
        save(operationName, operation);
        if (action === 'confirm') {
            operation.deadline = Math.min(operation.deadline, (await fresh(operation.successor)).deadline);
            deadline(operation.deadline, clock);
            save(operationName, operation);
        }
        const value = await json(url, 'POST', body, {}, 200, 131072, Math.min(operation.writeDeadline, action === 'confirm' ? operation.deadline : Infinity));
        check(value.renewal_id === operation.created.renewal_id, 'BINDING_CHECK_FAILED');
        operation.lastResult = value;
        save(operationName, operation);
        return value;
    };
    const ownerPath = () => { check(config.projectId && config.issuerRegistrationId && config.ownerCredential, 'OWNER_CONFIGURATION_REQUIRED'); return config.registryOrigin + `/api/projects/${config.projectId}/issuers/${config.issuerRegistrationId}`; };
    const ownerCall = (url: string, body?: unknown, expected = 200) => json(url, body === undefined ? 'GET' : 'POST', body, { authorization: 'Bearer ' + config.ownerCredential }, expected);
    const rotate = async (fragment: string, operationName = 'rotation-' + fragment) => {
        check(/^[A-Za-z0-9._-]{1,128}$/.test(fragment), 'OWNER_CONFIGURATION_REQUIRED');
        const path = ownerPath(), keyId = issuerDid + '#' + fragment;
        let operation: any;
        try {
            operation = load(operationName);
            check(operation.keyId === keyId, 'BINDING_CHECK_FAILED');
        }
        catch (error: any) {
            if (error.code !== 'ENOENT')
                throw error;
            operation = { keyId };
            save(operationName, operation);
        }
        let local = await management('issuer', '/management/issuer/keys');
        let owner = await ownerCall(path);
        const alreadySelected = local.credential_keys.find((key: any) => key.key_id === keyId);
        if (local.selected_key_id === keyId && !local.pending) {
            check(alreadySelected?.public_jwk, 'TRUST_CHECK_FAILED');
            authority(await text(config.registryOrigin + config.authorizationPath, 262144), keyId, alreadySelected.public_jwk, 'issuance');
            operation.completed = local;
            save(operationName, operation);
            return local;
        }
        if (!operation.stageRequest) {
            operation.stageRequest = { expected_revision: local.revision, project_id: config.projectId, issuer_registration_id: config.issuerRegistrationId, expected_registry_revision: owner.revision, key_fragment: fragment };
            save(operationName, operation);
        }
        if (!operation.staged) {
            operation.staged = await management('issuer', '/management/issuer/keys/stage', operation.stageRequest, 201);
            save(operationName, operation);
        }
        const staged = operation.staged;
        const key = staged.credential_keys.find((value: any) => value.key_id === keyId);
        check(key?.public_jwk && !key.abandoned, 'TRUST_CHECK_FAILED');
        const published = owner.credential_keys.find((value: any) => value.key_id === keyId && value.key_state === 'current');
        if (published) {
            check(core.publicJwkSha256Thumbprint(published.public_jwk) === core.publicJwkSha256Thumbprint(key.public_jwk), 'TRUST_CHECK_FAILED');
        }
        else {
            if (!operation.challenge) {
                operation.challenge = await ownerCall(path + '/key-challenges', { operation: 'rotate', expected_revision: operation.stageRequest.expected_registry_revision, key_id: keyId, public_jwk: key.public_jwk }, 201);
                save(operationName, operation);
            }
            const proof = await management('issuer', '/management/issuer/keys/proof', { expected_revision: staged.revision, challenge: operation.challenge });
            operation.proof = proof;
            save(operationName, operation);
            operation.registryResult = await ownerCall(path + `/key-challenges/${operation.challenge.challenge_id}/complete`, proof, 201);
            save(operationName, operation);
        }
        // Activation authenticates every configured signed grant in the production runtime.
        operation.completed = await management('issuer', '/management/issuer/keys/activate', { expected_revision: staged.revision, key_id: keyId });
        save(operationName, operation);
        return operation.completed;
    };
    const withdraw = async (keyId: string) => {
        const path = ownerPath(), owner = await ownerCall(path);
        const challenge = await ownerCall(path + '/key-challenges', {
            operation: 'withdraw',
            expected_revision: owner.revision,
            key_id: keyId
        }, 201);
        const proof = await management('issuer', '/management/sign', {
            nonce: challenge.nonce,
            audience: challenge.audience
        });
        return ownerCall(path + `/key-challenges/${challenge.challenge_id}/complete`, proof, 201);
    };
    const register = async (role: 'issuer' | 'verifier', project?: any) => {
        const origin = role === 'issuer' ? config.issuerOrigin : config.verifierOrigin;
        const did = core.didWebFromHost(new URL(origin).host), url = core.didWebToHttpsUrl(did);
        const document = core.resolveDidWebDocument({
            did,
            resolverResponses: { [url]: await text(url, role === 'issuer' ? 262144 : 131072) }
        });
        check(document.verificationMethod.length === 1, 'REGISTRATION_IDENTITY_REFUSED');
        const key = document.verificationMethod[0]!;
        const owner = project ?? await json(config.registryOrigin + '/api/projects', 'POST', {}, {}, 201);
        const path = config.registryOrigin + `/api/projects/${owner.project.project_id}/${role === 'issuer' ? 'issuers' : 'verifiers'}/challenges`;
        const challenge = await json(path, 'POST', {
            origin,
            did,
            key_id: key.id,
            public_jwk: key.publicKeyJwk
        }, { authorization: 'Bearer ' + owner.management_credential }, 201);
        const proof = await management(role, '/management/sign', {
            nonce: challenge.nonce,
            audience: challenge.audience
        });
        const registration = await json(path + `/${challenge.challenge_id}/complete`, 'POST', proof, { authorization: 'Bearer ' + owner.management_credential }, 201);
        const output = {
            ...owner,
            registration
        };
        save('registration-' + role, output);
        return output;
    };
    return {
        holder,
        holderKeyId: secret.keyId,
        save,
        load,
        request,
        json,
        text,
        management,
        register,
        createOffer,
        receive,
        status,
        fresh,
        createSession,
        present,
        result,
        continue: continuation,
        createRenewal,
        renew,
        renewalStatus: (name: string) => renewalOperation(name, 'status'),
        cancel: (name: string) => renewalOperation(name, 'cancel'),
        confirm: (name: string) => renewalOperation(name, 'confirm'),
        rotate,
        withdraw,
        revoke: (id: string) => management('issuer', `/management/issuer/issuances/${id}/status`, { state: 'revoked' }),
        verifyRestored: async (receipt: Receipt) => {
            const observed = await status(receipt);
            if (observed.revoked)
                return observed;
            await fresh(receipt);
            return observed;
        }
    };
}
if (process.argv[1]?.endsWith('generic-http.ts')) {
    try {
        const config = JSON.parse(readFileSync(process.argv[2]!, 'utf8'));
        const operation = process.argv[3]!;
        const input = process.argv[4] ? JSON.parse(readFileSync(process.argv[4], 'utf8')) : {};
        const flow = openGeneric(config);
        check(['register', 'createOffer', 'receive', 'createSession', 'present', 'result', 'continue', 'createRenewal', 'renew', 'renewalStatus', 'cancel', 'confirm', 'rotate', 'withdraw', 'revoke', 'status', 'verifyRestored'].includes(operation), 'OPERATION_REFUSED');
        const result = await (flow as any)[operation](...(input.args ?? []));
        flow.save('output', result);
        console.log('GENERIC_OPERATION_COMPLETED_PROTECTED_OUTPUT_WRITTEN');
    }
    catch {
        console.error('GENERIC_OPERATION_FAILED');
        process.exitCode = 1;
    }
}
