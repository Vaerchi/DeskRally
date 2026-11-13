# DeskRally Technician (Android)

An installable Android app a technician uses to sign in to the DeskRally console and control remote
Windows machines. It is **not** a guest/agent: no screen capture of the phone, no
AccessibilityService.

## What it is: a Trusted Web Activity, not a WebView

The app is a thin launcher (`com.google.androidbrowserhelper` `LauncherActivity`, the Bubblewrap
pattern). It opens the real console in **Chrome**, full screen, with no URL bar once Digital Asset
Links verify. Where no TWA-capable browser exists it falls back to a Custom Tab.

Why not a WebView: the console uses SSO (client SSO / OIDC) and Google and Microsoft block sign-in
inside embedded WebViews. The phone typing bar was tuned against Chrome's Gboard behaviour, and
Chrome gives the full WebRTC stack. Everything the console already does on phones and the Galaxy Z
Fold 7 (responsive CSS, touch gestures, typing bar) is reused unchanged; there is no app-side UI.

`DeskRallyLauncherActivity` adds one thing: the activity is exported, so any app could send it an
explicit intent with an arbitrary URL. `LaunchUrlPolicy` replaces anything that is not `https://`
on the configured console host with the console start page (unit-tested).

## Layout

| Path | Purpose |
|---|---|
| `app/build.gradle.kts` | applicationId `com.deskrally.technician`, minSdk 24, compile/target SDK 37, signing, the console host |
| `gradle.properties` | `deskrally.consoleHost`, the ONE place the host is set |
| `app/src/main/AndroidManifest.xml` | TWA meta-data, autoVerify https intent-filter, splash FileProvider |
| `app/src/main/res/` | adaptive icon, splash, colours (mirror the console's `--bg`), themes |
| `tools/serve-local-console.mjs` | local HTTPS server for verifying the TWA without production |
| `../web/viewer/public/manifest.webmanifest`, `.well-known/assetlinks.json` | the web half (see below) |

## Build

Prerequisites: a **JDK 17 or 21** (JDK 25 is too new for AGP 9.4), and the Android SDK with
`platforms;android-37.0` and `build-tools;36.0.0`. Point at them with `JAVA_HOME` and either
`ANDROID_HOME` or an untracked `android/local.properties` containing `sdk.dir=...`.

```
cd android
./gradlew assembleDebug assembleRelease testDebugUnitTest lint
```

Outputs: `app/build/outputs/apk/{debug,release}/`. Set `JAVA_HOME` to your JDK 21
and `ANDROID_HOME` to your Android SDK.

### Pointing a build at another console (tenant / self-hosted)

Change `deskrally.consoleHost` in `gradle.properties`, or pass it per build:

```
./gradlew assembleRelease -Pdeskrally.consoleHost=console.example.com
```

It must be a bare hostname. That single value feeds the launch URL, the https intent-filter, the
app's asset statement and `BuildConfig.CONSOLE_HOST`. A tenant build ALSO needs that host's
`/.well-known/assetlinks.json` to list the key the build is signed with (below), and for the web
side to serve it (the Caddy handler in `deploy/Caddyfile` does this for any `SITE_ADDRESS`).

## Sign

`keystore.properties` (gitignored, in this directory) points at the keystore:

```
storeFile=C:/Users/<you>/.secrets/deskrally-android/deskrally-dev-upload.jks
storePassword=...
keyAlias=deskrally-dev
keyPassword=...
```

Without it the release build is produced **unsigned**. Debug builds use the same key on purpose, so
a debug install verifies against the same fingerprint as release.

Keep the keystore and its password outside the repo (e.g. `%USERPROFILE%\.secrets\deskrally-android\`)
and must never be committed (`*.jks`, `*.keystore`, `keystore.properties` are gitignored).

**This is a DEV/upload key.** It is not the production key. See "Still manual".

## Getting the fingerprint into assetlinks.json

Chrome only drops the URL bar if `https://<host>/.well-known/assetlinks.json` lists the package AND
the SHA-256 of the cert that signed the installed APK.

```
keytool -list -v -keystore <keystore.jks> -alias <alias> | findstr SHA256
```

Paste the value (colon-separated, upper-case) into `sha256_cert_fingerprints` in
`web/viewer/public/.well-known/assetlinks.json`. The array can hold several; keep every key that
may sign a build you distribute. `web/viewer/src/pwa_assets.test.ts` checks the shape, that the
package matches `applicationId`, and that Caddy serves it as JSON ahead of the SPA fallback.

Current content: the Play App Signing key `FF:0F:94:5F:35:46:A1:E1:B0:CD:94:58:A3:88:F1:12:CB:D3:E7:9B:BE:EA:D8:AE:A1:B2:A1:21:9C:CA:22:95`
(signs every install from Google Play), and the DEV/upload key
`84:DF:D4:6C:18:48:55:72:11:64:75:92:FD:10:13:EF:11:C0:9B:7A:AD:39:5D:1B:22:5C:D5:83:F2:98:FD:42` (signs the sideload APK).

### How production serves it, and what a deploy needs

Production is Caddy (`deploy/Caddyfile`) serving the viewer build from `/srv/viewer`. The file ships
from `web/viewer/public/` through `vite build` into `dist/`, and an exact-path `@assetlinks` handler
serves it as `application/json` with `Cache-Control: public, max-age=300`, ahead of the SPA
catch-all. A deploy therefore needs: (1) the new viewer `dist/` in `VIEWER_DIST`, and (2) the new
Caddyfile loaded (`caddy validate`, then reload). Until both are live, Chrome gets the SPA's HTML
for that URL, verification fails and the app shows a Custom Tab with a URL bar. Nothing here has
been deployed.

## Verify on an emulator without production

Verification is a real network fetch by Chrome, so it can be tested locally:

1. `cd web/viewer && npm run build`, then `node android/tools/serve-local-console.mjs`
   (add `--spa-assetlinks` for the negative control).
2. Boot a `google_apis` (userdebug) x86_64 image. Chrome reads flags from a file on debuggable
   devices: `adb root`, then write `/data/local/tmp/chrome-command-line` containing
   `_ --no-first-run --disable-fre --host-resolver-rules="MAP main.deskrally.com 10.0.2.2:8443" --ignore-certificate-errors-spki-list=<base64 sha256 of the local cert's public key>`,
   `chmod 755` it, and `adb shell am force-stop com.android.chrome`. Use the SPKI-list flag, NOT
   `--ignore-certificate-errors`: the latter leaves the page marked "not secure", and Chrome
   shows the URL bar for an insecure page even when Digital Asset Links verify. (Git Bash on
   Windows: set `MSYS_NO_PATHCONV=1` or adb mangles `/data/...` paths.)
3. Clear Chrome's first-run state and install the debug APK; launch it. With the positive server
   there is no URL bar; with `--spa-assetlinks` there is one.

## Still manual

* **Play Console**: no account, listing or release exists. Nothing is published.
* **Production signing key**: if the app is enrolled in Play App Signing, Google re-signs it with
  its own key. Copy that key's SHA-256 from Play Console (Setup, App signing) and **ADD** it to
  `sha256_cert_fingerprints` next to the upload key. Without it the Play-installed app shows a URL
  bar even though sideloaded dev builds verify.
* **Tenant hostnames** beyond `main.deskrally.com`: each needs its own build and its own
  assetlinks entry.
* **Brand**: name and icon are the console's logo on a light plate, not a designed Play listing icon.
* **Version**: bump `versionCode` and `versionName` in `app/build.gradle.kts` for every upload.
