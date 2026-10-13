# Try the Android wallet

Complete [Getting started](../education/getting-started.md) first. Now use a real Android phone to review an eligibility request and authorize sharing. Your app must confirm eligibility after the wallet delivers the details. This is separate from the software-holder check.

The new onboarding guide has not yet been verified on a phone. Earlier wallet preview results do not qualify this path.

You need an Android 11 or newer phone, a screen lock, working internet and the [inspected wallet candidate](#wallet-candidate). iPhone: Coming soon.

## 1. Prepare the phone

Keep any existing wallet data and hardware keys. Record its credential types and counts privately before an update. Compare the installed package, version and signing certificate with the candidate below. Use a compatible update only; if the certificate differs or Android refuses it, stop and ask the maintainer. Never uninstall, clear storage or replace keys to make a test pass.

On the phone, open your team's app HTTPS origin. Expect the Education page with no certificate warning. A page that works on your laptop may still be unreachable from the phone. Fix Wi-Fi, DNS or the tunnel before continuing; do not bypass certificate checks.

The commands below can open the wallet over USB using optional [Android Platform-Tools](https://developer.android.com/tools/releases/platform-tools). Put `adb` on your shell's PATH. Enable [USB debugging](https://developer.android.com/tools/adb#Enabling), connect the phone and approve the computer's authorization prompt on the unlocked phone. Keep only the intended device connected and select its intended Android user yourself. No host Node.js or Rust installation is needed.

Download `release-b-physical-preview-20261012.tar.gz` from [the wallet release](https://github.com/TDS-Digital-ID/credworks-integration/releases/tag/release-b-physical-preview-20261012). Its SHA256 must be `4e903ebd69df819316d29d74e9656ad2cfdc3e60c1433e0a6083913bc87ae161`. From the download directory, extract only the APK into a new directory:

```sh
mkdir credworks-wallet
tar -xzf release-b-physical-preview-20261012.tar.gz -C credworks-wallet release-b/wallet-buildprod-release.apk
cd credworks-wallet/release-b
```

Check the extracted APK against [the package, version, checksum and signing certificate below](#wallet-candidate). For an existing wallet, confirm its signing identity and that this version is a compatible update before continuing. Then, with only the intended phone connected:

```sh
adb install -r wallet-buildprod-release.apk
```

This installs the app or updates a compatible installation while retaining its data. Android shares an installed package version across users; it does not copy their separate wallet data. Expect `Success`, then open the wallet on the phone. Confirm the previously recorded credential types and counts remain. If installation fails or asks for an incompatible downgrade, stop; do not uninstall, clear data or add bypass flags. Return to the kit directory for the next commands.

## 2. Receive your phone's synthetic credentials

The software holder's credential and key are not on your phone. From the kit root, prepare a separate phone attempt using your existing setup directory:

```sh
./setup android-offer --state "$HOME/.local/share/credworks-team"
./setup android-open --state "$HOME/.local/share/credworks-team" --stage government
```

The first command prints a protected local HTML file path. It contains private activation links, not the project bearer or a holder key. Keep it local; do not upload it or paste links into an online QR generator. The second command opens the Government offer in the wallet. `ANDROID_ACTIVATION_OPENED` means only that Android accepted the launch request.

Review the synthetic Government offer from `issuer-portal.credworks.xyz`, then authorize adding it with Android. Expect "Credential held". This creates the phone's own holder binding through the normal wallet flow.

Next open enrolment:

```sh
./setup android-open --state "$HOME/.local/share/credworks-team" --stage enrolment
```

Select the Government credential you just received. Review the UNSW issuer portal request for given name, family name and date of birth. Authorize sharing on the phone. Expect the browser's "Identity shared" page. These synthetic identity details go to the issuer for enrolment, not to your team's eligibility app.

Refresh the same attempt, then receive its Education offer:

```sh
./setup android-offer --state "$HOME/.local/share/credworks-team"
./setup android-open --state "$HOME/.local/share/credworks-team" --stage education
```

Review the separate Education offer and authorize adding it. Expect "Credential held". `ANDROID_STAGE_NOT_READY` means enrolment has not produced that offer yet; finish the matching identity-sharing step before retrying. Each receipt and disclosure still requires your review and Android authorization.

## 3. Check cancellation

Immediately before creating the phone request, refresh signed verifier evidence from the kit directory with the same setup state:

```sh
./setup doctor --state "$HOME/.local/share/credworks-team"
```

Continue only after `SETUP_READY`. This checks the running services and refreshes signed trust, permission and status evidence through protected management. Evidence can expire while you complete receipt or enrolment on the phone.

Return to your team's app in the same phone browser. Tap "Check eligibility only", then "Open CredWorks wallet on Android".

Confirm the recipient is your team's registered verifier origin, the purpose is eligibility without an account, and only enrolment and institution are requested. Select the new synthetic Education credential. Student ID must be withheld.

Review the request, tap the share button, then cancel Android's authorization dialog. Confirm that the dialog really appeared and the wallet says nothing was sent. The app must not grant eligibility from a pending request. Return to the app and start a fresh eligibility request when ready.

If the request expires before Android's dialog appears, record expiry, not cancellation. Start a fresh request and repeat this check.

## 4. Complete eligibility

Refresh again immediately before creating the successful attempt:

```sh
./setup doctor --state "$HOME/.local/share/credworks-team"
```

After `SETUP_READY`, repeat the review with a fresh request. Share only enrolment and institution and successfully authorize Android. After "Details delivered", promptly return to the same app browser and tap "Check completion".

Expect "Eligibility confirmed". This is the app backend's authenticated, policy-checked result. Wallet delivery alone is not success. Eligibility does not sign you in or create an app account.

If you see `RESULT_PENDING`, check again before expiry. If it expires, or the app restarts, start a fresh request in the app. Do not repeat credential issuance to recover an expired eligibility request.

A request or app interaction can return HTTP 503 when signed evidence is stale. If the app reports `RUNTIME_UNAVAILABLE` after a delay, run `doctor` again and, once it succeeds, create a fresh eligibility request using the same held Education credential. Protected diagnostics may identify `EVIDENCE_STALE`; do not expose management endpoints or tokens to inspect it. A failed refresh is a refusal, not approval. Refresh does not extend an old request or result deadline, reset a credential or replace your identity.

## Recover an expired issuance attempt

Retrying `android-offer` keeps the same person and attempt; it does not renew deadlines. If Government receipt or enrolment has expired, explicitly choose the next attempt number:

```sh
./setup android-offer --state "$HOME/.local/share/credworks-team" --attempt 2
```

Repeat with that same number after a connection failure. It reuses the same request rather than duplicating work. Prior attempt files remain intact. Repeat the receipt/enrolment steps for the new attempt and keep existing wallet records. Never delete setup state or reset a credential to hide a failure.

For `ANDROID_DEVICE_REQUIRED`, reconnect one phone. For `ANDROID_USB_AUTHORIZATION_REQUIRED`, approve debugging on the phone. For `ANDROID_ONE_DEVICE_REQUIRED`, disconnect other devices or emulators. `ANDROID_OPEN_FAILED` needs the correct installed wallet and an unlocked, manually selected Android user. The helper never unlocks, changes users or approves consent for you.

## Record your check

Keep PASS, FAIL or NOT RUN for receipt, cancellation, successful authorization and the app result. Record the kit revision, APK checksum/certificate/version, service image/configuration revisions, phone model, Android version and ABI. Preserve original failures and note what changed before a retry. Exclude PINs, activation links, credentials and disclosed values from shared evidence. If a phone or human authorization is unavailable, physical acceptance remains NOT RUN.

## Wallet candidate

Use the wallet inside [the generic physical preview](https://github.com/TDS-Digital-ID/credworks-integration/releases/tag/release-b-physical-preview-20261012). It also supports Education. Verify the extracted APK before installation; historical acceptance of that wallet does not validate your new team deployment.

| Item | Expected value |
| --- | --- |
| File | `wallet-buildprod-release.apk` |
| Package | `au.edu.unsw.vc.unsw_wallet` |
| Version | `1.0.0`, code `1` |
| APK SHA256 | `cf80d80b03ebf6a69fd73c3b8776320a85a2a4a2ef0b88e149f480cdd2d9cac5` |
| Signing certificate SHA256 | `6f34aeeb67c9e2f4f9d7611e25241f9277513d6787e49f883e54987817f8bf07` |
| Wallet source | `2d97ba0bec5d125c05bbd366c03a2d7c69d1f1ce` |

Use `shasum -a 256 wallet-buildprod-release.apk` on macOS or `sha256sum wallet-buildprod-release.apk` on Linux. Android SDK Build-Tools' `apksigner verify --print-certs` checks the signature and certificate. A matching filename alone proves nothing. Ask the maintainer to compare the installed signing identity if you cannot inspect it; do not work around an incompatible update.
