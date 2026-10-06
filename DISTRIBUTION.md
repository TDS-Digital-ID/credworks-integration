# Distribution status

The operator delegated selection of reuse terms and public destination on 2026-10-06.
Project-owned source is licensed under Apache-2.0; dependency and font licences remain unchanged.
The planned distribution repository is `TDS-Digital-ID/credworks-integration`. The existing
`universityvc-integration` and `university-vc-monorepo` repositories remain private.
No public availability is claimed by this preparation commit.

Release A is the frozen Education kit36dcc1b plus explicit distribution metadata changes,
original ed5b8bea images and the established-signer Education9130db0 APK. Release B is the
frozen generic kit083253f plus explicit distribution metadata changes, original dcef4b7 images
and established-signer generic17c6d60 APK. A distribution manifest must identify all source
revisions, transforms and checksums; do not label historical images as rebuilt from this commit.
The source archives retain their embedded source/build provenance.

The operator explicitly deferred remaining physical-phone tests. Existing observations and
failures remain preserved; unperformed checks stay NOT RUN. Software-holder tests use mock
platform attestation and do not establish hardware acceptance. The intermittent startup issue
#442 remains unresolved. The frozen generic APK does not include the later #445 expired-receipt
diagnostic correction. Clean-device installation and published-only clean setup are not accepted.
These are preview limitations, not a claim of completed release acceptance.

Before public distribution, attach matching dependency/font notices and the reviewed finite
source, images, signed APK, provenance and checksums. Exclude Git history, operator state,
credentials, tunnel material, backups and private host evidence. Preserve installed wallet
identity/data; do not uninstall or reset keys to force an update. Publish Release A before B.
Keep #329/#338/#348 open while their remaining release criteria are unmet.

The project licence text is the unchanged official Apache License, Version2.0 from
https://www.apache.org/licenses/LICENSE-2.0.txt. Existing copyright, attribution and third-party
licence notices are retained. No third-party work is relicensed by this project licence.
