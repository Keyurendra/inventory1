TL;DR:

```
curl https://accuknox-omni.s3.us-east-1.amazonaws.com/v0.1.2/agent-install.sh |\
    OMNI_ARTIFACT_API_TOKEN="<REDACTED>" \
    bash -s - \
        --artifact-endpoint=https://cspm.accuknox.com/api/v1/artifact/ \
        --tenant-id=000 \
        --artifact-label=CHANGEME
```

- Artifact API tokens can be created under Settings -> Tokens.
- Labels can be created under Settings -> Labels.

The `v0.1.2` download above is an example of the installation flow. AI agent
discovery below requires a release that contains that feature.

The installation script creates a systemd service and a daily systemd timer.
It downloads the Trivy vulnerability and Java databases and the AI agent
catalog. VM rootfs reports include a top-level `AIAgentDetections` array when
the catalog is available. An empty array means no catalog matches were found
on the host. Container image reports do not include host AI detections;
container image scanning requires a separate opt-in.

## Air-gap Installation

1. Download the Omni binary:
    - amd64: <https://accuknox-omni.s3.us-east-1.amazonaws.com/v0.1.2/omni-linux-amd64>
    - arm64: <https://accuknox-omni.s3.us-east-1.amazonaws.com/v0.1.2/omni-linux-arm64>
2. Place the binary at `/usr/local/bin/omni`
3. Place the installation script on the host

```
chmod +x agent-install.sh
chmod +x /usr/local/bin/omni

export OMNI_ARTIFACT_API_TOKEN="<REDACTED>"
export OMNI_VULN_DB_REPOSITORY="ghcr.io/aquasecurity/trivy-db" # replace with your private registry
export OMNI_SKIP_DOWNLOAD=1
./agent-install.sh
```

Copy the `db/`, `java-db/`, and `aiagent/` database directories into
`/var/lib/accuknox-omni/` before running an air-gap scan. Set
`OMNI_SKIP_DB_DOWNLOAD=true` when the VM cannot reach the database registries.

## FAQs

- How can I check scan status on the host?

```
systemctl status omni.timer
systemctl status omni.service
journalctl -u omni
```

- Scan is getting OOMKilled. How do I adjust resource usage?

By default, the systemd service is limited to 2G memory and 10% CPU
utilization. Both can be adjusted by setting the following environment
variables and re-running the installation script:

```
OMNI_MAX_MEMORY=2G
OMNI_CPU_QUOTA=10%
```

- Why is malware scanning disabled? How do I enable it?

Malware scanning is CPU-intensive and can take a long time to complete on
limited resources. We thus, do not recommend malware scanning for agent-based
installations.

To enable malware scans, please set the environment variable below and re-run
the installation script.

```
OMNI_SKIP_MALWARE_SCAN=false
```

- How to uninstall?

```
/usr/local/bin/omni-uninstall.sh
```
