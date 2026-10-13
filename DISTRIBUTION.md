# Distribution status

Project-owned source is licensed under Apache-2.0. Dependency and font licences
remain unchanged. Public experimental releases live in
[TDS-Digital-ID/credworks-integration](https://github.com/TDS-Digital-ID/credworks-integration/releases).
Both producer repositories remain private.

## Published previews

The Education preview was published before the generic preview. Their manifests
record the exact source, signed APKs, image archives, notices and checksums. The
[later generic physical preview](https://github.com/TDS-Digital-ID/credworks-integration/releases/tag/release-b-physical-preview-20261012)
updates the signed wallet to source `2d97ba0`, including the expired-receipt diagnostic
correction. Its runtime images and kit source remain unchanged.

That preview records receipt, disclosure, revocation, signing-key and renewal checks
on one Pixel. Fresh public-source services were also checked with that phone; the
published Education APK's eligibility and sign-in checks passed separately. These
are experimental sandbox observations. They do not establish a second-device
matrix, vendor platform attestation, independent-wallet interoperability or production
assurance. Original failures and scope decisions remain in the release evidence.

## Student onboarding preview

The guided commands target [student-onboarding-preview-20261013](https://github.com/TDS-Digital-ID/credworks-integration/releases/tag/student-onboarding-preview-20261013),
with the exact ARM64/AMD64 archives in this source. If the release is unavailable,
it is still awaiting publication approval. Earlier previews do not include these commands. The [candidate manifest](config/setup-candidate.json) records the
unchanged source revision and exact image/archive identities. A newer documentation
commit does not change an image's source label.

Local software-holder checks use labelled mock platform attestation. Public Education
setup, eligibility, sign-in, custom lifecycle and restart checks passed on macOS ARM64
and in an Ubuntu ARM64 VM using supplied public-only artifacts. The VM run required
operator DNS cache refreshes and documented same-state recovery. The Android guide passed receipt,
authorization cancellation and app-confirmed eligibility on one Pixel 7 with Android 17.
Native Linux AMD64 and Windows/WSL2 remain unverified. See [platform evidence](docs/setup/guide.md#platform-evidence).
Older release results are not evidence that the new instructions work everywhere.

Before a new release, attach the matching finite source, images, signed APK when
applicable, notices, corresponding source and checksum inventory. Exclude operator
state, credentials, tunnel material, backups and private host evidence. Preserve
installed wallet data and hardware identity. Compare signing certificates before an
update; do not uninstall or replace keys to bypass an incompatibility.

The project licence is the unchanged official
[Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0.txt).
Existing copyright, attribution and third-party licence notices are retained.
