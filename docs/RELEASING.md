# Releasing nazar

A release is two zips attached to the GitHub release `vX.Y.Z` of `atas/nazar`, and two casks in
`atas/homebrew-tap` that point at them:

| Zip | Holds | Cask |
|---|---|---|
| `nazar-X.Y.Z.zip` | `nazar-agent.app`, with the `nazar` CLI inside it | `nazar` (links the CLI, runs `nazar install`) |
| `nazar-ui-X.Y.Z.zip` | `Nazar UI.app` | `nazar-ui` (into `/Applications`) |

Both bundles are signed with a Developer ID Application certificate (hardened runtime, secure
timestamp, no entitlements), notarized, and stapled. The casks are rendered from
`packaging/homebrew/*.rb.in`; never edit the tap's copies.

**Zip, not dmg.** A cask stages a zip as it is, so the `binary` stanzas can link the CLI from
inside `nazar-agent.app` and the agent stays in the Caskroom; a dmg would add a disk image to
sign, notarize and staple and a mount step, for nothing a cask uses. `ditto` keeps the signature
and the stapled ticket, and a zip is what `notarytool` takes. A zip cannot carry a ticket itself,
so the ticket is stapled to each bundle before it is zipped.

[release.yml](../.github/workflows/release.yml) releases weekly when `main` has new
commits, or when you run it (Actions → Release → Run workflow; optional version). It picks the
next patch version, builds, signs, notarizes, publishes and updates the tap. Its secrets live in
the `release` environment only (`scripts/release_test.sh` checks).

## Once

1. **You.** Join the [Apple Developer Program](https://developer.apple.com/programs/enroll/)
   (paid). Only a paid team can create Developer ID certificates; an "Apple Development"
   certificate cannot be notarized.
2. **You.** Create a Developer ID Application certificate: Xcode → Settings → Accounts → the
   team → Manage Certificates → + → Developer ID Application (the team's Account Holder only),
   or on [Certificates](https://developer.apple.com/account/resources/certificates/list) with a
   CSR from Keychain Access. It and its private key land in the login keychain. Check:

   ```bash
   security find-identity -v -p codesigning   # lists "Developer ID Application: NAME (TEAMID)"
   ```

   Export it with its private key (`.p12`) to an offline backup: a lost key means a new
   certificate.
3. **You.** Store the notary credentials in the login keychain under a profile name
   (`nazar-notary` here), with either an app-specific password or an App Store Connect API key
   ([notarization docs](https://developer.apple.com/documentation/security/customizing-the-notarization-workflow)):

   ```bash
   # app-specific password: https://account.apple.com → Sign-In and Security → App-Specific Passwords
   xcrun notarytool store-credentials nazar-notary --apple-id APPLE_ID --team-id TEAMID   # asks for it

   # or an API key: https://appstoreconnect.apple.com/access/integrations/api → Team Keys (role: Developer)
   xcrun notarytool store-credentials nazar-notary --key AuthKey_KEYID.p8 --key-id KEYID --issuer ISSUER_ID

   xcrun notarytool history --keychain-profile nazar-notary   # the credentials work
   ```

   An API key's `.p8` downloads once; keep it offline.
4. **You.** The `release` environment
   ([Settings → Environments](https://github.com/atas/nazar/settings/environments)): you as
   deployments from `main` only, and its secrets and variables:

   ```bash
   base64 -i developerID_application.p12 | gh secret set DEVELOPER_ID_P12_BASE64 --env release
   gh secret set DEVELOPER_ID_P12_PASSWORD --env release            # asks for the .p12's password
   gh secret set NOTARY_API_KEY --env release < AuthKey_KEYID.p8
   gh secret set TAP_DEPLOY_KEY --env release < tap_deploy_key       # a write deploy key of atas/homebrew-tap
   gh variable set NAZAR_SIGN_ID --env release --body 'Developer ID Application: NAME (TEAMID)'
   gh variable set NOTARY_KEY_ID --env release --body KEYID
   gh variable set NOTARY_ISSUER_ID --env release --body ISSUER_ID
   ```
5. **You.** The repo must be public: Homebrew downloads the zips without credentials, so it
   cannot install from a private repo's releases. Turn on private vulnerability reporting, which
   `SECURITY.md` sends reports to (it can't be turned on while the repo is private):
   [Code security](https://github.com/atas/nazar/settings/security_analysis) → Private
   vulnerability reporting → Enable.

Keys do not move between builds with different signatures: keys made with an ad-hoc or Apple
Development build stay with that build. After the first Homebrew install, create keys again
with the released CLI (spec 12).

## Each release

1. Nothing: the weekly run releases what is on `main`. To release now, or a minor or major
   version: [Run workflow](https://github.com/atas/nazar/actions/workflows/release.yml), with
   the version or empty for the next patch. The run sets the version in both bundles on a
   release commit only its tag points to.
2. **Dry run** before a risky change (any Mac, no certificate): `NAZAR_SIGN_ID=- DRY_RUN=1 make release`.
3. **Without CI**, from your Mac: set the version in both `macos/Resources/{Agent,UI}/Info.plist`,
   commit, `git tag -a vX.Y.Z -m vX.Y.Z`, then
   `NAZAR_SIGN_ID='Developer ID Application: NAME (TEAMID)' NAZAR_NOTARY_PROFILE=nazar-notary make release`,
   `gh release create` and `make release-tap TAP=../homebrew-tap`.
4. **You.** Smoke test on a clean macOS user account (System Settings → Users & Groups):

   ```bash
   brew update
   brew install --cask atas/tap/nazar
   nazar version                    # nazar X.Y.Z
   nazar status                     # the agent answers
   spctl -a -vv -t exec "$(brew --prefix)/Caskroom/nazar/X.Y.Z/nazar-agent.app"   # source=Notarized Developer ID
   brew install --cask atas/tap/nazar-ui && open -a "Nazar UI"
   ```

   Upgrade, on an account with the previous release and a key: `brew upgrade --cask nazar`, then
   `nazar ssh-key list` still lists the key and `ssh -T git@github.com` signs with it. Uninstall:
   `brew uninstall --cask nazar` stops the agent and keeps `~/.nazar`.

## Rollback

**You**, in this order:

1. Revert the tap, so new installs and upgrades get the previous version:

   ```bash
   git -C ../homebrew-tap revert --no-edit HEAD && git -C ../homebrew-tap push
   ```

   Anyone who already upgraded goes back with `brew update && brew reinstall --cask nazar`; the
   previous release has the same signature, so the keys stay.
2. Hide or remove the release: `gh release edit vX.Y.Z --draft` (assets no longer downloadable)
   or `gh release delete vX.Y.Z --cleanup-tag`.
3. Fix forward as `X.Y.Z+1`. Never upload different zips under a published tag: the cask's
   sha256 pins them, and installs would fail or, worse, differ.

For the first release there is nothing to go back to: the revert restores the pre-release casks,
and step 2 leaves them nothing to download.

A leaked certificate key: ask [Apple Developer Support](https://developer.apple.com/contact/) to
revoke the Developer ID certificate (what it signed may then stop passing Gatekeeper), create a
new one and release again.
