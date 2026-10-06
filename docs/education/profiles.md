# Profiles and application policy

The only credential definition is `urn:credworks:education` version `1`, after authenticated issuer/type verification of `UniversityEducationCredential`. A type-name match alone gives no authority. Both profiles require an active signed grant for the runtime's exact DID, HTTPS origin, actual request signing key, accepted issuer and every full path.

| Profile | Complete disclosure paths | Application use |
| --- | --- | --- |
| education_eligibility | credentialSubject.enrolled; credentialSubject.institution_id | Check eligibility without account continuity |
| education_sign_in | credentialSubject.enrolled; credentialSubject.institution_id; credentialSubject.student_id | Check policy and map returning account |

No name, date of birth, programme, photo or holder identifier is requested. Arbitrary additional paths, issuers, formats or definitions refuse. The wallet independently resolves its provisioned registry origin/DID/public anchor; a partner hostname or unsigned field cannot choose that trust. Request retrieval, consent, holder signing and transmission obey the minimum request/grant deadline, including a final check after Android authorization. Equality is expired. Cancellation and overbroad requests release no credential bytes.

## Delivery, verification and access

1. Public `{"status":"accepted"}` acknowledges admitted delivery only. It carries no verification verdict, claims or login decision.
2. Protected one-time result retrieval returns verified typed claims and evidence, or a claim-free refusal. The initiating application keeps the management bearer and correlation capability server-side. Public state and request capabilities cannot retrieve results.
3. The application checks policy explicitly. The reference app requires the configured issuer/verifier, exact type/definition/version/profile/paths, original interaction, fresh evidence, `enrolled === true` and the exact configured institution. A verified `enrolled=false` is valid cryptography and refuses access.

Sign-in additionally requires a bounded nonblank student ID. The app maps the exact authenticated `(issuer, student_id)` pair to a random application UUID. The UUID does not remove the stable student ID correlation risk at the receiving service: two services given that identifier can correlate visits. Eligibility returns `eligible`, creates no account and does not sign in. Use it whenever continuity is unnecessary. Synthetic student IDs are stable and never reassigned.

## Browser correlation

The browser app creates a 30-minute Secure/HttpOnly/SameSite=Strict `__Host-education` cookie. JSON POSTs require exact Origin and synchronizer `X-CSRF-Token`. Runtime session ID, interaction ID and correlation capability remain server-side. Another browser cannot complete the interaction; one admitted completion claims it before upstream I/O. Uncertain delivery fails closed. Replay and concurrent consumption cannot create a second login. Successful sign-in rotates cookie/CSRF and retires pending interactions; refusal preserves an existing login.

The app rechecks browser, result-retention and immutable evidence deadlines after network/account I/O. Refresh cannot extend old results. See [API examples](api.md) and [operations](operations.md).
