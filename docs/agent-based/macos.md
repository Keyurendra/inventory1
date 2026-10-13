# Agent-based macOS scanning

The existing [`agent-install.sh`](../../agent-install.sh) supports both macOS
and Linux. On macOS it installs the Omni binary and a daily launchd job named
`com.accuknox.omni`; a separate macOS installer is not required.

Use a release that includes macOS scanning and AI agent discovery. On Apple
Silicon the installer selects `omni-darwin-arm64`; on an Intel Mac it selects
`omni-darwin-amd64`.

```bash
curl -fsSLO https://accuknox-omni.s3.us-east-1.amazonaws.com/latest/agent-install.sh
chmod +x agent-install.sh

export OMNI_ARTIFACT_API_TOKEN='<ARTIFACT_API_TOKEN>'
./agent-install.sh \
    --artifact-endpoint=https://cspm.accuknox.com/api/v1/artifact/ \
    --tenant-id=000 \
    --artifact-label=CHANGEME
```

Create the API token under **Settings → Tokens** and the label under
**Settings → Labels**. The installer asks for administrator access to place
the binary in `/usr/local/bin`, the databases and token in
`/var/lib/accuknox-omni`, and the launchd plist in `/Library/LaunchDaemons`.
It starts the first scan after installation. Do not use a `latest/` binary
until this feature has been released there.

Each successful VM scan publishes one Trivy rootfs `TR` artifact. It includes
macOS vulnerability findings, application dependency findings, and a top-level
`AIAgentDetections` array with matches from the AI agent catalog. An empty
array means the catalog loaded but no agents matched. The installer downloads
the Trivy vulnerability and Java databases and the AI agent catalog before
each scan. Malware scanning is disabled by default; container image scanning
is also disabled by default.

## Install a local pre-release binary

To test an unreleased build, copy the binary for the Mac's architecture to the
host, install it, and tell the shared installer to keep that binary:

```bash
sudo install -m 755 ./omni-darwin-arm64 /usr/local/bin/omni
export OMNI_ARTIFACT_API_TOKEN='<ARTIFACT_API_TOKEN>'
OMNI_SKIP_DOWNLOAD=true ./agent-install.sh \
    --artifact-endpoint=https://cspm.accuknox.com/api/v1/artifact/ \
    --tenant-id=000 \
    --artifact-label=CHANGEME
```

On an Intel Mac, use the `omni-darwin-amd64` binary instead.

## Air-gap installation

Stage `db/trivy.db`, `java-db/trivy-java.db`, and
`aiagent/aiagentscan.json` under `/var/lib/accuknox-omni/` from a connected
machine. The macOS OS vulnerability feed is fetched separately from the
MacAdmins SOFA URL at scan time; an isolated Mac also needs access to that
feed, or a reachable mirror supplied with `--macos-feed-url` in the installer
arguments. Then install the local binary as above and set
`OMNI_SKIP_DB_DOWNLOAD=true` in the installer environment.

## Check scan status

```bash
sudo launchctl print system/com.accuknox.omni
sudo tail -n 100 /var/lib/accuknox-omni/omni.log
sudo tail -n 100 /var/lib/accuknox-omni/omni.err.log
```

To trigger another scan, run
`sudo launchctl kickstart -k system/com.accuknox.omni`. To uninstall, run
`sudo /usr/local/bin/omni-uninstall.sh`.
