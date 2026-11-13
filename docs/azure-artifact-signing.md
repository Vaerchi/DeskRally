# Opt-in Azure Artifact Signing

`scripts/build-release.ps1` keeps its unsigned default and existing local-certificate
`-Sign -CertThumbprint ...` path. Azure signing requires explicit `-Sign`, provider,
account/profile, regional endpoint, and installed tool paths. No login, account provisioning,
tool installation, or certificate-store change is performed. Invoking signing requests remote
signatures and may incur Azure charges; ordinary builds and tests do not invoke it.

Use your own Azure signing account and certificate profile. An operator must already have an
authorized Azure CLI login for that account/profile.
The helper excludes other credential sources, including interactive browser authentication.
Use matching SDK SignTool and ArtifactSigning.Client dlib architectures. Credentials are not
stored in the generated temporary metadata file; cleanup is attempted after success or failure.

```powershell
pwsh -NoProfile -File scripts/build-release.ps1 -RequireFreshAgent `
  -ControlPlaneUrl 'https://support.example.com/cp' -Sign -SigningProvider AzureArtifact `
  -ArtifactSigningEndpoint 'https://eus.codesigning.azure.net' `
  -ArtifactSigningAccountName '<account>' -ArtifactSigningProfileName '<profile>' `
  -ArtifactSignToolPath '<SDK>/x64/signtool.exe' `
  -ArtifactSigningDlibPath '<ArtifactSigning.Client>/bin/x64/Azure.CodeSigning.Dlib.dll'
```

The support client is signed after its manifest and resource checks. Its SHA-256 sidecar is
computed again after signing. When WiX is available, the MSI is signed after package-content
verification and before the top-level manifest records it. A missing WiX installation retains
the existing warning and produces no new MSI. This path does not sign every agent/server binary
or publish/install artifacts.

For an existing single EXE, DLL, MSI, or PS1, invoke `scripts/sign-artifact-release.ps1` with
`-Path`, `-Endpoint`, `-AccountName`, `-CertificateProfileName`, `-SignToolPath`, and `-DlibPath`.
The helper modifies the supplied artifact in place. Treat a failure as an unshippable artifact;
it may already have been modified before a later verification failure.

The helper requests SHA-256 signing and a SHA-256 RFC3161 timestamp from Microsoft's timestamp
service. It requires successful `signtool verify /pa /all /tw`, a valid Authenticode signature,
and a timestamp certificate. There is no untimestamped Azure fallback. These flags and metadata
follow [Microsoft's signing integration documentation](https://learn.microsoft.com/en-us/azure/artifact-signing/how-to-signing-integrations).

Offline regression checks: `python -m unittest discover -s scripts -p test_sign_artifact_release.py -v`.
They run the real helper under PowerShell 5 and 7 when installed, with fake SignTool and
Authenticode results. They do not exercise Azure credentials, real certificates, the network,
or production publication. A deliberately authorized real signing acceptance remains necessary
before releasing with this new build path.
