<#
.SYNOPSIS
    Install and configure AccuKnox Omni for Windows
.DESCRIPTION
    Downloads, installs, and configures AccuKnox Omni with Windows Task Scheduler
.PARAMETER Version
    Version of Omni to install (default: latest)
.PARAMETER DownloadUrl
    Custom URL to download Omni from
.PARAMETER SkipOmniDownload
    Skip downloading Omni binary
.PARAMETER ArtifactEndpoint
    Artifact API endpoint
.PARAMETER ArtifactApiToken
    API token for artifact access
.PARAMETER ArtifactLabel
    Artifact Label
.PARAMETER TenantId
    Tenant ID
.PARAMETER ExtraArgs
    Additional arguments to pass to the Omni agent scan command
.PARAMETER TriggerImmediately
    Run scan immediately after installation (default: true)
.PARAMETER ClamavMSIInstallerFile
    Path to ClamAV MSI installer (.msi) for airgapped installation.
.PARAMETER SkipDatabaseDownload
    Skip downloading ClamAV, MSRC, Trivy, and AI agent databases
.PARAMETER SkipVulnScan
    Skip vulnerability scanning
.PARAMETER SkipMalwareScan
    Skip malware scanning
.PARAMETER OverrideHostname
    Override hostname in the final artifact
#>

[CmdletBinding()]
param(
    [string]$Version = "latest",
    [string]$DownloadUrl = "",
    [bool]$SkipOmniDownload = $false,
    [Parameter(Mandatory=$true)][string]$ArtifactEndpoint = "",
    [Parameter(Mandatory=$true)][string]$ArtifactApiToken = "",
    [Parameter(Mandatory=$true)][string]$ArtifactLabel = "",
    [Parameter(Mandatory=$true)][string]$TenantId = "",
    [Parameter(ValueFromRemainingArguments=$true)][string[]]$ExtraArgs = @(),
    [bool]$TriggerImmediately = $true,
    [string]$ClamavMSIInstallerFile = "",
    [bool]$SkipDatabaseDownload = $false,
    [bool]$SkipVulnScan = $false,
    [bool]$SkipMalwareScan = $false,
    [string]$OverrideHostname = ""
)

$Global:OmniInstallPath = "C:\Program Files\Accuknox\Omni"
$Global:OmniHomeDir = "C:\ProgramData\Accuknox\Omni"
$Global:TaskMalwareScan = "AccuKnox Omni Malware Scan"
$Global:TaskVulnScan = "AccuKnox Omni Vuln Scan"

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Cyan
}

function Write-Warn {
    param([string]$Message)
    Write-Warning "[WARN] $Message"
}

function Write-Fatal {
    param([string]$Message)
    Write-Error "[ERROR] $Message" -ErrorAction Stop
}

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    $admin = [Security.Principal.WindowsBuiltInRole]::Administrator
    if (-not $p.IsInRole($admin)) {
        Write-Fatal "Run this script as Administrator"
    }
}

function Test-Prerequisites {
    Test-Admin

    if ($PSVersionTable.PSVersion.Major -lt 3) {
        Write-Fatal "PowerShell 3.0 or later is required"
    }

    if ($PSVersionTable.PSVersion.Major -le 4) {
        Write-Info ("Running on PowerShell {0} compatibility mode" -f `
            $PSVersionTable.PSVersion)
    }

    # Windows Server 2012/2012 R2 + PowerShell 3/4 often needs
    # explicit TLS 1.2 for HTTPS downloads.
    try {
        $p = [Net.ServicePointManager]::SecurityProtocol
        [Net.ServicePointManager]::SecurityProtocol = $p -bor 3072
    }
    catch {
        Write-Warn "Unable to force TLS 1.2. HTTPS download may fail: $_"
    }

    try {
        Import-Module ScheduledTasks -ErrorAction Stop
    }
    catch {
        Write-Fatal "ScheduledTasks module is required: $_"
    }
}

function Test-Architecture {
    $arch = [System.Environment]::GetEnvironmentVariable("PROCESSOR_ARCHITECTURE")
    switch ($arch) {
        "AMD64" { return "amd64" }
        "ARM64" { return "arm64" }
        default { Write-Fatal "Unsupported architecture: $arch" }
    }
}

function Get-FileFromUrl {
    param(
        [string]$Url,
        [string]$OutputPath
    )

    try {
        Write-Info "Downloading from $Url..."
        Invoke-WebRequest -Uri $Url -OutFile $OutputPath -UseBasicParsing
        Write-Info "Download completed"
    }
    catch {
        Write-Fatal "Download failed: $_"
    }
}

function Install-ClamAV {
    $clamav = Get-Command clamscan -ErrorAction SilentlyContinue
    if ($clamav) {
        $clamPath = (Get-ChildItem "C:\Program Files" -Directory | Where-Object { $_.Name -match "ClamAV" }).FullName
        $script:ClamAVPath = $clamPath
        $script:FreshClamPath = Join-Path $clamPath "freshclam.exe"
        Write-Info "ClamAV is already installed at: $($clamav.Source)"
        return
    }

    if (-not [string]::IsNullOrEmpty($script:ClamavMSIInstallerFile)) {
        Write-Info "ClamAV not found. Installing via MSI installer $($script:ClamavMSIInstallerFile)"
        try {
            $proc = Start-Process msiexec.exe -PassThru -Wait -ArgumentList "/i `"$script:ClamavMSIInstallerFile`" /qn"
            if ($proc.ExitCode -ne 0) {
                Write-Fatal "Installation failed with exit code $($proc.ExitCode)"
            }
        }
        catch {
            Write-Fatal "Failed to execute MSI installer: $_"
        }
    }
    else {
        $winget = Get-Command winget -ErrorAction SilentlyContinue
        if (-not $winget) {
            Write-Fatal "winget is not installed. Please install Windows Package Manager (winget) first.`nVisit: https://aka.ms/getwinget"
        }
        try {
            & winget install --id=Cisco.ClamAV -e --silent --accept-package-agreements --accept-source-agreements
        }
        catch {
            Write-Fatal "Failed to install ClamAV using winget: $_"
        }
    }

    Write-Info "ClamAV installed successfully"

    $clamPath = (Get-ChildItem "C:\Program Files" -Directory | Where-Object { $_.Name -match "ClamAV" }).FullName
    $oldPath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::Machine)
    if (-not ($oldPath -split ';' | Where-Object { $_ -eq $clamPath })) {
        [Environment]::SetEnvironmentVariable("Path", "$oldPath;$clamPath", [EnvironmentVariableTarget]::Machine)
        Write-Info "ClamAV path added to system PATH"
    }

    $script:ClamAVPath = $clamPath
    $script:FreshClamPath = Join-Path $clamPath "freshclam.exe"
}

function Update-ClamAVDatabase {
    Create-Freshclam-Conf
    Write-Info "Updating ClamAV virus definitions with freshclam..."

    try {
        $freshclamOutput = & $script:FreshClamPath --verbose 2>&1

        if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq 1) {
            # exit code 1 means database is already up to date
            Write-Info "ClamAV virus definitions updated successfully"
        }
        else {
            Write-Warn "freshclam completed with exit code $LASTEXITCODE. Output: $freshclamOutput"
        }
    }
    catch {
        Write-Warn "Failed to run freshclam: $_. Continuing with installation..."
    }
}

function Update-VulnerabilityDatabases {
    Write-Info "Updating MSRC, Trivy, and AI agent databases..."

    try {
        $output = & $script:OmniBinPath db download msrc vuln java aiagent --destination "C:\ProgramData\AccuKnox\Omni" 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Info "MSRC, Trivy, and AI agent databases downloaded to C:\ProgramData\AccuKnox\Omni"
        }
        else {
            Write-Fatal "Failed to download vulnerability databases: $output"
        }
    }
    catch {
        Write-Fatal "Failed to download vulnerability databases: $_"
    }
}

function New-FreshClamScheduledTask {
    $taskName = "ClamAV Database Update"

    Write-Info "Creating scheduled task for automatic ClamAV updates: $taskName"

    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

    $action = New-ScheduledTaskAction `
        -Execute $script:FreshClamPath `
        -Argument "--verbose" `
        -WorkingDirectory $script:ClamAVPath

    $trigger = New-ScheduledTaskTrigger `
        -Once `
        -At 12am `
        -RepetitionInterval (New-TimeSpan -Hours 6) `
        -RepetitionDuration (New-TimeSpan -Days 3650)

    $settings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -StartWhenAvailable `
        -RunOnlyIfNetworkAvailable `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 30) `
        -RestartCount 3 `
        -RestartInterval (New-TimeSpan -Minutes 5)

    $principal = New-ScheduledTaskPrincipal `
        -UserId "NT AUTHORITY\SYSTEM" `
        -LogonType ServiceAccount `
        -RunLevel Highest

    $task = New-ScheduledTask `
        -Action $action `
        -Trigger $trigger `
        -Settings $settings `
        -Principal $principal `
        -Description "Automatically updates ClamAV virus definitions using freshclam"

    Register-ScheduledTask `
        -TaskName $taskName `
        -InputObject $task | Out-Null

    Write-Info "ClamAV update scheduled task created successfully"
    Write-Info "Updates will run every 6 hours"
}

function New-VulnerabilityDatabaseUpdateScheduledTask {
    $taskName = "MSRC and Trivy Database Update"

    Write-Info "Creating scheduled task for automatic vulnerability DB updates: $taskName"

    Unregister-ScheduledTask -TaskName "MSRC Database Update" -Confirm:$false -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

    $action = New-ScheduledTaskAction `
        -Execute $script:OmniBinPath `
        -Argument "db download msrc vuln java aiagent --destination=C:\ProgramData\AccuKnox\Omni"

    $trigger = New-ScheduledTaskTrigger `
        -Once `
        -At 12am `
        -RepetitionInterval (New-TimeSpan -Hours 12) `
        -RepetitionDuration (New-TimeSpan -Days 3650)

    $settings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -StartWhenAvailable `
        -RunOnlyIfNetworkAvailable `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 30) `
        -RestartCount 3 `
        -RestartInterval (New-TimeSpan -Minutes 5)

    $principal = New-ScheduledTaskPrincipal `
        -UserId "NT AUTHORITY\SYSTEM" `
        -LogonType ServiceAccount `
        -RunLevel Highest

    $task = New-ScheduledTask `
        -Action $action `
        -Trigger $trigger `
        -Settings $settings `
        -Principal $principal `
        -Description "Automatically updates MSRC, Trivy, and AI agent databases"

    Register-ScheduledTask `
        -TaskName $taskName `
        -InputObject $task | Out-Null

    Write-Info "MSRC, Trivy, and AI agent database update scheduled task created successfully"
    Write-Info "Updates will run every 12 hours"
}

function Initialize-Environment {
    $script:Arch = Test-Architecture
    Write-Info "Host architecture: $script:Arch"

    if (-not [string]::IsNullOrWhiteSpace($DownloadUrl)) {
        $script:OmniUrl = $DownloadUrl
    }
    else {
        $script:OmniUrl = "https://accuknox-omni.s3.us-east-1.amazonaws.com/$Version/omni-windows-$($script:Arch).exe"
    }

    if ([string]::IsNullOrEmpty($script:ArtifactApiToken)) {
        Write-Fatal "OMNI_ARTIFACT_API_TOKEN cannot be empty"
    }

    $script:OmniBinPath = Join-Path $Global:OmniInstallPath "omni.exe"
    $script:TokenFile = Join-Path $Global:OmniHomeDir "artifact.tok"
    $script:UninstallScript = Join-Path $Global:OmniInstallPath "Uninstall-Omni.ps1"
    $script:LogDir = Join-Path $Global:OmniHomeDir "logs"
    $script:MalwareScanLogFile = Join-Path $script:LogDir "omni-malware-scan.log"
    $script:VulnScanLogFile = Join-Path $script:LogDir "omni-vuln-scan.log"
    $script:LogWrapperScript = Join-Path $Global:OmniInstallPath "run-omni-with-logging.ps1"
}

function Test-Url {
    if (-not ($script:OmniUrl -match "^https?://")) {
        Write-Fatal "Only http:// and https:// URLs are supported for DownloadUrl (have $($script:OmniUrl))"
    }
}

function Save-Token {
    Write-Info "Creating home directory: $Global:OmniHomeDir"
    New-Item -ItemType Directory -Path $Global:OmniHomeDir -Force | Out-Null

    Write-Info "Saving token at $script:TokenFile"
    $enc = [System.Text.Encoding]::ASCII
    [System.IO.File]::WriteAllText(
        $script:TokenFile, $script:ArtifactApiToken, $enc
    )

    $acl = Get-Acl $script:TokenFile
    $acl.SetAccessRuleProtection($true, $false)
    $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) } | Out-Null

    $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "BUILTIN\Administrators", "FullControl", "Allow"
    )
    $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "NT AUTHORITY\SYSTEM", "FullControl", "Allow"
    )

    $acl.AddAccessRule($adminRule)
    $acl.AddAccessRule($systemRule)
    Set-Acl -Path $script:TokenFile -AclObject $acl
}

function Install-OmniBinary {
    $tempFile = [System.IO.Path]::GetTempFileName()

    try {
        Get-FileFromUrl -Url $script:OmniUrl -OutputPath $tempFile

        Write-Info "Installing binary to $script:OmniBinPath"
        New-Item -ItemType Directory -Path $Global:OmniInstallPath -Force | Out-Null
        Move-Item -Path $tempFile -Destination $script:OmniBinPath -Force

        if (-not (Test-Path $script:OmniBinPath)) {
            Write-Fatal "Executable omni binary not found at $script:OmniBinPath"
        }
    }
    catch {
        if (Test-Path $tempFile) {
            Remove-Item $tempFile -Force
        }
        throw
    }
}

function New-OmniScheduledTask {
    New-Item -ItemType Directory -Path $script:LogDir -Force | Out-Null

    [System.Collections.ArrayList]$tasks = @()
    if (-not $SkipVulnScan) {
        $tasks.Add($Global:TaskVulnScan)
    }
    if (-not $SkipMalwareScan) {
        $tasks.Add($Global:TaskMalwareScan)
    }

    if ($tasks.Count -eq 0) {
        Write-Fatal "Atleast one scan must be enabled"
    }

    foreach ($task in $tasks) {
        Write-Info "Removing existing scheduled task '$task' if present..."
        Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue

        Write-Info "Creating scheduled task: $task"

        [System.Collections.ArrayList]$argsList = @(
            "agent", "scan",
            "--artifact-endpoint=$ArtifactEndpoint",
            "--artifact-token-file=$script:TokenFile",
            "--artifact-label=$ArtifactLabel",
            "--tenant-id=$TenantId",
            "--vuln-db-directory=C:\ProgramData\AccuKnox\Omni"
        )

        if (-not [string]::IsNullOrWhiteSpace($OverrideHostname)) {
            $argsList.Add("--override-hostname=$OverrideHostname")
        }

        $logFile = ""
        if ($task -eq $Global:TaskMalwareScan) {
            $argsList.Add("--skip-vuln-scan")
            $logFile = $script:MalwareScanLogFile
        }
        if ($task -eq $Global:TaskVulnScan) {
            $argsList.Add("--skip-malware-scan")
            $logFile = $script:VulnScanLogFile
        }

        if ($ExtraArgs.Count -gt 0) {
            $argsList += $ExtraArgs
        }

        $argsString = $argsList -join " "

        $cmdArgument = "/c `"$script:OmniBinPath`" $argsString >> $logFile 2>&1"

        $action = New-ScheduledTaskAction `
            -Execute "cmd.exe" `
            -Argument $cmdArgument `
            -WorkingDirectory $Global:OmniHomeDir

        $trigger = New-ScheduledTaskTrigger `
            -Daily `
            -At 2am `
            -RandomDelay (New-TimeSpan -Minutes 10)

        $settings = New-ScheduledTaskSettingsSet `
            -AllowStartIfOnBatteries `
            -DontStopIfGoingOnBatteries `
            -StartWhenAvailable `
            -RunOnlyIfNetworkAvailable `
            -ExecutionTimeLimit (New-TimeSpan -Hours 2)

        $principal = New-ScheduledTaskPrincipal `
            -UserId "NT AUTHORITY\SYSTEM" `
            -LogonType ServiceAccount `
            -RunLevel Highest

        Register-ScheduledTask `
            -TaskName $task `
            -Action $action `
            -Trigger $trigger `
            -Settings $settings `
            -Principal $principal `
            -Description "$task agent" | Out-Null

        Write-Info "Scheduled task '$task' created successfully"
        Write-Info "Logs will be written to: $logFile"
    }
}

function Create-Freshclam-Conf {
    Write-Info "Creating freshclam conf: C:\Program Files\ClamAV\freshclam.conf"
    $conf = @"
DatabaseDirectory "C:\Program Files\ClamAV\database"
DatabaseMirror database.clamav.net
"@
    $conf | Out-File -FilePath "C:\Program Files\ClamAV\freshclam.conf" -Encoding UTF8
}

try {
    Write-Info "Starting AccuKnox Omni installation for Windows..."
    Test-Prerequisites
    Initialize-Environment
    Test-Url
    if (-not $SkipMalwareScan) {
        Install-ClamAV
        if (-not $SkipDatabaseDownload) {
            Update-ClamAVDatabase
            New-FreshClamScheduledTask
        }
        else {
            Write-Info "Skipping downloading ClamAV database"
            $dbPath = Join-Path "$script:ClamAVPath" "database"
            if (-not (Test-Path $dbPath)) {
                Write-Fatal "ClamAV database not found at $dbPath and download was skipped"
            }
        }
    }
    Save-Token
    if (-not $SkipOmniDownload) {
        Install-OmniBinary
    }
    else {
        Write-Info "Skipping downloading Omni binary"
        if (-not (Test-Path $script:OmniBinPath)) {
            Write-Fatal "Omni binary not found at $script:OmniBinPath and download was skipped"
        }
    }
    if (-not $SkipVulnScan) {
        if (-not $SkipDatabaseDownload) {
            Update-VulnerabilityDatabases
            New-VulnerabilityDatabaseUpdateScheduledTask
        }
        else {
            Write-Info "Skipping downloading MSRC, Trivy, and AI agent databases"
            foreach ($dbFile in @("msrc\db.sqlite3", "db\trivy.db", "java-db\trivy-java.db", "aiagent\aiagentscan.json")) {
                $dbPath = Join-Path -Path $Global:OmniHomeDir -ChildPath $dbFile
                if (-not (Test-Path $dbPath)) {
                    Write-Fatal "Vulnerability database not found at $dbPath and download was skipped"
                }
            }
        }
    }
    New-OmniScheduledTask
    if ($TriggerImmediately) {
        Write-Info "Starting initial scans..."
        if (-not $SkipVulnScan) {
            Start-ScheduledTask -TaskName $Global:TaskVulnScan
        }
        if (-not $SkipMalwareScan) {
            Start-ScheduledTask -TaskName $Global:TaskMalwareScan
        }
    }
    Write-Info "Installation completed successfully!"
    Write-Info ""
    Write-Info "Omni Scan Commands:"
    Write-Info "  Check vuln scan task status:      Get-ScheduledTask -TaskName 'AccuKnox Omni Vuln Scan'"
    Write-Info "  View vuln scan task info:         Get-ScheduledTaskInfo -TaskName 'AccuKnox Omni Vuln Scan'"
    Write-Info "  Check malware scan task status:   Get-ScheduledTask -TaskName 'AccuKnox Omni Malware Scan'"
    Write-Info "  View malware scan task info:      Get-ScheduledTaskInfo -TaskName 'AccuKnox Omni Malware Scan'"
    Write-Info "  Run vuln scan manually:           Start-ScheduledTask -TaskName 'AccuKnox Omni Vuln Scan'"
    Write-Info "  Run malware scan manually:        Start-ScheduledTask -TaskName 'AccuKnox Omni Malware Scan'"
    Write-Info "  View live log for malware scan:   Get-Content '$script:MalwareScanLogFile' -Wait"
    Write-Info "  View live log for vuln scan:      Get-Content '$script:VulnScanLogFile' -Wait"
    Write-Info ""
    Write-Info "ClamAV DB Update Commands:"
    Write-Info "  Check update task:     Get-ScheduledTask -TaskName 'ClamAV Database Update'"
    Write-Info "  View update info:      Get-ScheduledTaskInfo -TaskName 'ClamAV Database Update'"
    Write-Info "  Update manually:       Start-ScheduledTask -TaskName 'ClamAV Database Update'"
    Write-Info ""
    Write-Info "MSRC and Trivy DB Update Commands:"
    Write-Info "  Check update task:     Get-ScheduledTask -TaskName 'MSRC and Trivy Database Update'"
    Write-Info "  View update info:      Get-ScheduledTaskInfo -TaskName 'MSRC and Trivy Database Update'"
    Write-Info "  Update manually:       Start-ScheduledTask -TaskName 'MSRC and Trivy Database Update'"
}
catch {
    Write-Fatal $_.Exception.Message
}
