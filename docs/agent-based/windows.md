TL;DR:

```
# Download installer script
Invoke-WebRequest -Uri 'https://accuknox-omni.s3.us-east-1.amazonaws.com/v0.1.2/agent-install.ps1' -OutFile .\agent-install.ps1

# Run installation script to setup agent
.\agent-install.ps1 `
    -ArtifactEndpoint https://cspm.accuknox.com/api/v1/artifact/ `
    -TenantId 000 `
    -ArtifactLabel CHANGEME `
    -ArtifactApiToken "<REDACTED>" `
    -SkipMalwareScan $true
```

- Artifact API tokens can be created under Settings -> Tokens.
- Labels can be created under Settings -> Labels.

The `v0.1.2` download above is an example of the installation flow. The
combined Windows report and AI agent discovery below require a release that
contains those features.

The installation script creates a Windows scheduled task.

Each successful live vulnerability scan publishes one Trivy rootfs artifact for
the VM. It combines MSRC Windows update findings, Trivy application dependency
findings from every fixed local drive, and Windows host inventory. If the MSRC
scan or any fixed-drive scan fails, no partial vulnerability artifact is sent.
Offline Windows scans continue to publish the WINVM report.

The installer downloads and updates the MSRC, Trivy vulnerability, and Trivy
Java databases, plus the AI agent catalog. When the catalog is available, the
same VM rootfs artifact includes a top-level `AIAgentDetections` array with
catalog matches for installed AI tools. An empty array means no matches were
found. Network drives and drives Windows classifies as removable are not
scanned.

## Air-gap Installation

1. Download & Extract all-in-one.zip from S3

```ps1
Invoke-WebRequest `
    -Uri "https://accuknox-omni.s3.us-east-1.amazonaws.com/latest/all-in-one.zip" `
    -OutFile all-in-one.zip `
    -UseBasicParsing
Expand-Archive -Path ".\all-in-one.zip" -DestinationPath .\ -Force
cd .\all-in-one\
```

Before moving the bundle to an isolated VM, make sure `database\db\trivy.db`,
`database\java-db\trivy-java.db`, `database\msrc\db.sqlite3`, and
`database\aiagent\aiagentscan.json` are present. On a connected Windows
machine, run `.\omni.exe db download msrc vuln java aiagent --destination .\database`
from the bundle directory if they are missing.

2. Move ClamAV Database to its Appropriate Location

```ps1
New-Item -ItemType Directory -Path "C:\Program Files\ClamAV" -Force
Move-Item -Path .\database\clamav\ -Destination "C:\Program Files\ClamAV\database" -Force
```

3. Move MSRC, Trivy, and AI Agent Databases to their Appropriate Locations

```ps1
New-Item -ItemType Directory -Path "C:\ProgramData\Accuknox\Omni" -Force
Move-Item -Path .\database\msrc\ -Destination "C:\ProgramData\Accuknox\Omni" -Force
Move-Item -Path .\database\db\ -Destination "C:\ProgramData\Accuknox\Omni" -Force
Move-Item -Path .\database\java-db\ -Destination "C:\ProgramData\Accuknox\Omni" -Force
Move-Item -Path .\database\aiagent\ -Destination "C:\ProgramData\Accuknox\Omni" -Force
```

4. Install Omni Binary to its Appropriate Location

```ps1
New-Item -ItemType Directory -Path "C:\Program Files\AccuKnox\Omni\" -Force
Move-Item -Path .\omni.exe -Destination "C:\Program Files\AccuKnox\Omni\" -Force
```

5. Run the installation script

```ps1
.\agent-install.ps1 `
    -ArtifactEndpoint https://cspm.demo.accuknox.com/api/v1/artifact/ `
    -TenantId 000 `
    -ArtifactLabel CHANGEME `
    -ArtifactApiToken "<REDACTED>" `
    -ClamavMSIInstallerFile clamav.msi `
    -SkipOmniDownload $true `
    -SkipDatabaseDownload $true
```
