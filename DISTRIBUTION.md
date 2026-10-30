# Distribution status

Project-owned source is licensed under Apache-2.0. Dependency and font licences
remain unchanged. Public artifacts live in
[TDS-Digital-ID/credworks-integration](https://github.com/TDS-Digital-ID/credworks-integration/releases).
Both producer repositories remain private.

## Team starter

Course teams receive a private starter containing the kit, their own tunnel
assignment and `START-HERE.txt`. Extract it, start Docker and run `./setup`.
The [getting-started guide](docs/education/getting-started.md) covers confirmation,
eligibility and the team's app. The package contains a tunnel credential and must
be delivered only to its assigned team through a private channel.

## Runtime and client

The [setup manifest](config/setup-candidate.json) records the exact ARM64 and AMD64
runtime/app archives, image identities and checksums. Setup downloads and verifies
the archive for the Docker engine's architecture. Both images use source
`4be274ebc92a8653f56f83661d035150d1497770`.

Ordinary verification results support bounded authenticated retries. Each verified
read checks current authorization, credential status and the original evidence
deadline. Results remain in memory; restarts require a new verification. The
Education client permits another unavailable runtime read before application
effects begin and never repeats its application callback.

Packaged checks passed on ARM64 in a Docker Linux VM and on AMD64 under emulation.
A fresh source extraction and image import also passed `./setup prepare` on macOS
ARM64. These checks do not establish each team's public setup or phone behaviour.
See [platform evidence](docs/setup/operations.md#platform-evidence).

## Wallet and licensing

The Android wallet is a separate signed artifact. Follow the exact download,
checksum and signing-certificate checks in the [Android guide](docs/guides/android-wallet.md).
Software-holder checks use labelled mock platform attestation. The kit does not
claim production assurance, vendor platform attestation or broad wallet compatibility.

Public releases include source inventories, checksums, third-party notices and
corresponding-source attachments. Operator credentials, state and private team
assignments are excluded from public artifacts.

The project licence is the official
[Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0.txt).
Copyright, attribution and third-party licence notices are retained.
