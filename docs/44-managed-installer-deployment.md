# Managed installer deployment

The installer is opt-in. Build and test a release for the deployment's exact HTTPS
control-plane URL, WSS signaling URL, and grant issuer public key before enabling it.
Do not publish the localhost or `support.example.invalid` VM fixtures.

Place `DeskRallySetup.exe`, `DeskRallyAgent.msi`, and `installer-manifest.json` in a
versioned directory outside the public viewer and download roots. Do not put an
enrollment token in this directory. Set these deployment variables:

```
MANAGED_INSTALL_HOST_DIR=/srv/deskrally/installers/<verified-release>
CP_MANAGED_INSTALL_CONTROL_PLANE_URL=https://remote.example.com/cp
```

Add `-f deploy/docker-compose.installer.yml` after the existing base and production
Compose files in **every** deployment and rollback command. Merely setting the
variables does not enable the feature. Validate the combined configuration with
`docker compose ... config --quiet` before recreating services. The overlay uses a
read-only bind mount and refuses to create a missing source directory.

At startup, the control plane checks the manifest, artifact hashes, deployment
URLs and issuer key, then snapshots the release bytes. A mismatch fails startup.
Switch releases by selecting another verified directory and recreating the control
plane; replacing files underneath a running server does not publish a new release.
Keep the previous directory and configuration for rollback.

The authenticated console supplies the short-lived enrollment token inside each
downloaded ZIP. The public support client is a separate artifact: configure its
download URL and SHA-256 in the viewer build environment and preserve that build
configuration across automated deployments. Only the support executable belongs
in the public download directory; a personalized installation ZIP does not.

Validation on 2026-09-15: the optional overlay passed Compose configuration
validation, layered over the deployment's existing base and production files.
This is configuration validation, not evidence of a published installer or an
end-to-end install. Those require the corresponding release acceptance results.
