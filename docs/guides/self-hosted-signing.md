# Sign self-hosted DeskRally releases with Azure Artifact Signing

Self-hosted operators publish their Windows installers and executables under their own
verified signing identity. Use your own Azure Artifact Signing account and Public Trust
certificate profile. DeskRally's signing account and publisher identity are reserved for
releases distributed by the DeskRally maintainers.

Azure Artifact Signing was previously named Trusted Signing. Microsoft manages the private
signing keys. Your organization authorizes signing through Azure permissions.

## Cost and eligibility

Checked November 17, 2026. Microsoft lists Basic at USD $9.99 per account per month,
including 5,000 signatures, with additional signatures at $0.005 each. An EXE and an MSI
each consume signing operations. Confirm current subscription pricing, currency and taxes
before provisioning. [Microsoft tier details](https://learn.microsoft.com/en-us/azure/artifact-signing/how-to-change-sku)

Public Trust requires successful identity validation and is available only in Microsoft's
supported countries. Individual validation currently supports the US and Canada. Check the
current eligibility list before buying. Allow time for validation and any requested documents.
[Microsoft setup and eligibility](https://learn.microsoft.com/en-us/azure/artifact-signing/quickstart)

## 1. Create your signing identity

1. Sign in to the Azure portal with your own subscription and Microsoft Entra tenant.
2. Register the `Microsoft.CodeSigning` resource provider under the subscription's
   **Resource providers** settings.
3. Create an **Artifact Signing account**, select Basic and a supported region, and record
   the account name and regional signing endpoint shown by Azure.
4. Complete **Public** identity validation in the portal using your legal organization or
   eligible individual identity. The verified identity supplies the publisher information.
5. Create a **Public Trust** certificate profile linked to that identity validation.
6. Grant the release operator **Artifact Signing Certificate Profile Signer** on that profile.
   Identity validation requires the **Artifact Signing Identity Verifier** role. Subscription
   administration permissions alone do not necessarily permit signing.

Use a profile controlled by the operator responsible for the self-hosted deployment. Grant
signing access only to trusted release operators. Microsoft documents the permissions and
portal steps in its [setup guide](https://learn.microsoft.com/en-us/azure/artifact-signing/quickstart)
and [role guide](https://learn.microsoft.com/en-us/azure/artifact-signing/tutorial-assign-roles).

## 2. Prepare the Windows signing workstation

Install Azure CLI, a current Windows SDK SignTool and Microsoft's Artifact Signing client tools.
The client tools include the signing integration and its runtime dependencies.

```powershell
winget install -e --id Microsoft.AzureCLI
winget install -e --id Microsoft.Azure.ArtifactSigningClientTools
az login --tenant '<your-tenant-id>'
az account set --subscription '<your-subscription-id>'
```

Locate the installed `signtool.exe` and `Azure.CodeSigning.Dlib.dll` using the installed
package and SDK directories. Use matching architectures, such as x64 for both. Record their
absolute paths. The DeskRally helper requires explicit paths and reuses your Azure CLI login.
[Microsoft tool installation](https://learn.microsoft.com/en-us/azure/artifact-signing/how-to-signing-integrations)

## 3. Build for your own server

Follow the [server deployment guide](server-deployment.md) and
[client deployment guide](client-deployment.md). The attended support tool, technician desktop
app, installed agent and setup bootstrap are separate artifacts. Select your own server domain
and deployment settings in their respective build instructions before signing.

The hosted-service support tool and installer bundle target the maintainers' service.
Changing a destination after signing can invalidate a signature or leave deployment settings
outside its protection. Keep enrollment tokens in the protected provisioning workflow described
in the client guide. Public release artifacts must contain no enrollment tokens or private keys.

For example, build the technician desktop app for your organization DNS suffix from the
repository root, using the existing build prerequisites. Replace `example.com` with the suffix
your deployment actually uses.

```powershell
pwsh -NoProfile -File clients/windows/build-client.ps1 `
  -TenantZone 'example.com' -OutDir 'C:\Release\desktop'
```

This command builds the technician app. It does not build the support tool or agent.
Source builds leave automatic updates disabled unless you explicitly configure an update
identity. For a self-hosted update channel, use your own update host and publisher.

## 4. Sign the final artifacts

From the repository root, set values from your Azure account and installed tools.
The endpoint below is an East US example. Use the endpoint for your account's region.

```powershell
$signing = @{
    Endpoint = 'https://eus.codesigning.azure.net'
    AccountName = '<your-account-name>'
    CertificateProfileName = '<your-public-trust-profile>'
    SignToolPath = 'C:\Path\To\x64\signtool.exe'
    DlibPath = 'C:\Path\To\x64\Azure.CodeSigning.Dlib.dll'
}

& .\scripts\sign-artifact-release.ps1 `
  -Path 'C:\Release\desktop\DeskRallyClient.exe' @signing
```

The helper signs in place, requests SHA-256 and an RFC3161 timestamp, and verifies the result.
A failure leaves the artifact unshippable until signing and verification succeed. Signing
requests consume Azure quota and can incur charges.

Repeat for each executable you distribute, including the support tool, agent executable and
setup bootstrap. Sign executable payloads before building an installer that contains them,
then sign the final MSI. Generate checksums and update manifests only after final signing.
Rebuilding or modifying an artifact requires signing and verification again.

The existing `scripts/build-release.ps1` can automate signing of the support tool and final
MSI with `-Sign -SigningProvider AzureArtifact` and explicit account/profile/tool parameters.
That path does not sign every payload. See the existing helper guide, `docs/azure-artifact-signing.md` in the source repository,
for its exact coverage and command.

## 5. Verify before distribution

```powershell
$artifact = 'C:\Release\desktop\DeskRallyClient.exe'
& $signing.SignToolPath verify /pa /all /tw $artifact
if ($LASTEXITCODE -ne 0) { throw 'Signature verification failed' }
$signature = Get-AuthenticodeSignature -LiteralPath $artifact
$signature | Format-List Status, StatusMessage, SignerCertificate, TimeStamperCertificate
if ($signature.Status -ne 'Valid' -or !$signature.TimeStamperCertificate) {
    throw 'A valid timestamped signature is required'
}
$signature.SignerCertificate.Subject
Get-FileHash -LiteralPath $artifact -Algorithm SHA256
```

Confirm the publisher subject matches your verified identity. Test installation and connection
on a clean Windows machine against your own server. Verify the displayed destination and
consent prompts, uninstall behavior, and each artifact's signature. Keep final hashes with the
release. Windows reputation and enterprise controls can still produce warnings or blocks for
new signed releases. [Microsoft SmartScreen guidance](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation)

## 6. Configure updates under your own identity

Use your verified certificate subject as the expected publisher. Azure rotates short-lived
leaf certificates, so a fixed leaf thumbprint is unsuitable for long-term update trust.
DeskRally's agent also needs its own Ed25519 update manifest key. That is separate from Azure
Authenticode signing and the server's enrollment/grant keys.

For the desktop app, pair `-UpdateHost` with `-UpdatePublisher` at build time. For the agent,
configure `DESKRALLY_UPDATE_FEED`, `DESKRALLY_UPDATE_PUBKEY_FILE` and
`DESKRALLY_UPDATE_PUBLISHER` together. Follow the
update release operations guide (`docs/automatic-update-release.md` in the source repository) for feed preparation, signatures,
versioning and canary verification.

## Troubleshooting

| Problem | Check |
| --- | --- |
| Azure rejects signing with 403 | Correct tenant, approved identity, Public Trust profile and profile signer role. Allow role propagation time. |
| DLL or runtime cannot load | Matching SignTool/dlib architectures and the client tool runtime prerequisites. |
| Signature succeeds but publisher is wrong | Selected Azure account/profile and verified legal identity. |
| Installer works but automatic updates fail | Your feed origin, publisher subject, manifest key and actual signed artifact version. |
| New release triggers SmartScreen | Signature and timestamp verification, download reputation and local app-control policy. |

Keep Azure identity and certificate-profile validation current. Review signing access and
history, and restrict release signing to reviewed builds. If your identity cannot obtain Azure
Public Trust, use another publicly trusted code-signing provider under your own identity and
the repository's local-certificate signing path.
