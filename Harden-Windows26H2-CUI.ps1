#requires -RunAsAdministrator
<#
.SYNOPSIS
    Windows 11 26H2 CUI/PII Privacy Hardening

.DESCRIPTION
    Defense-in-depth configuration intended for workstations handling
    CUI, PII, proprietary, or otherwise protected information.

    PRIMARY GOALS
      - Remove/block Windows Recall
      - Prevent Recall snapshots
      - Disable Click to Do
      - Disable selected Windows AI features that can process content
      - Reduce Windows diagnostic/telemetry exposure
      - Restrict diagnostic dumps/log uploads
      - Disable advertising/personalization/consumer experiences
      - Disable activity-history publishing/upload
      - Preserve Microsoft 365 Copilot
      - Preserve Defender, SmartScreen, Windows Update, Entra ID,
        Intune/MDM, CAC/certificates, WSL, Hyper-V and developer tools

    IMPORTANT
      This is hardening, not a certification of CMMC/NIST/DoD compliance.
      Organizational GPO/Intune policies may override local policy.

    Run from an elevated PowerShell session.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    # Enterprise/Education can honor diagnostic level 0 in supported
    # configurations. Pro generally cannot achieve the same level.
    [ValidateSet(0,1)]
    [int]$DiagnosticDataLevel = 1,

    # Set this only if your organization specifically wants the standalone
    # Windows Microsoft Copilot app removed. This DOES NOT intentionally
    # disable Microsoft 365 Copilot in Office.
    [switch]$RemoveWindowsCopilotApp,

    # Skip registry backups before applying local policy changes.
    [switch]$SkipBackup
)

$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"

# ---------------------------------------------------------------------------
# INITIALIZATION
# ---------------------------------------------------------------------------

$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$LogRoot   = Join-Path $env:ProgramData "CUI-Windows-Hardening"
$LogFile   = Join-Path $LogRoot "Hardening-$Timestamp.log"
$AuditFile = Join-Path $LogRoot "Audit-$Timestamp.txt"

New-Item -ItemType Directory -Path $LogRoot -Force | Out-Null

try {
    Start-Transcript -Path $LogFile -Force | Out-Null
} catch {}

function Write-Section {
    param([string]$Text)

    Write-Host ""
    Write-Host "================================================================"
    Write-Host " $Text"
    Write-Host "================================================================"
}

function Write-OK {
    param([string]$Text)
    Write-Host "[OK]   $Text" -ForegroundColor Green
}

function Write-WarnMsg {
    param([string]$Text)
    Write-Host "[WARN] $Text" -ForegroundColor Yellow
}

function Write-Fail {
    param([string]$Text)
    Write-Host "[FAIL] $Text" -ForegroundColor Red
}

function Confirm-RegKey {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
}

function Set-PolicyDWORD {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][int]$Value,
        [string]$Description = "$Path\$Name"
    )

    $TargetDescription = "$Path\$Name"

    if ($PSCmdlet.ShouldProcess($TargetDescription, "Set to $Value")) {
        try {
            Confirm-RegKey $Path

            New-ItemProperty `
                -Path $Path `
                -Name $Name `
                -PropertyType DWord `
                -Value $Value `
                -Force | Out-Null

            Write-OK "$Description = $Value"
        }
        catch {
            Write-Fail "$Description : $($_.Exception.Message)"
        }
    }
    else {
        Write-WarnMsg "[WhatIf] $Description = $Value"
    }
}

function Set-PolicyString {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Value,
        [string]$Description = "$Path\$Name"
    )

    $TargetDescription = "$Path\$Name"

    if ($PSCmdlet.ShouldProcess($TargetDescription, "Set to $Value")) {
        try {
            Confirm-RegKey $Path

            New-ItemProperty `
                -Path $Path `
                -Name $Name `
                -PropertyType String `
                -Value $Value `
                -Force | Out-Null

            Write-OK "$Description = $Value"
        }
        catch {
            Write-Fail "$Description : $($_.Exception.Message)"
        }
    }
    else {
        Write-WarnMsg "[WhatIf] $Description = $Value"
    }
}

function Get-RegValueSafe {
    param(
        [string]$Path,
        [string]$Name
    )

    try {
        return (Get-ItemPropertyValue -Path $Path -Name $Name -ErrorAction Stop)
    }
    catch {
        return "<not configured>"
    }
}

function Test-HardeningPreflight {
    $principal = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This script requires elevation. Start PowerShell as Administrator and try again."
    }

    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    if ($os -and ($os.Caption -notmatch 'Windows 11')) {
        Write-WarnMsg "This hardening script is intended for Windows 11. Detected: $($os.Caption)"
    }

    return $true
}

function Backup-RegistryValues {
    param(
        [Parameter(Mandatory)][string[]]$Paths,
        [Parameter(Mandatory)][string]$BackupRoot
    )

    if ($WhatIfPreference) {
        Write-WarnMsg "WhatIf enabled. Registry backup skipped."
        return @()
    }

    $BackupFolder = Join-Path $BackupRoot "RegistryBackup-$Timestamp"
    New-Item -ItemType Directory -Path $BackupFolder -Force | Out-Null

    $Files = @()

    foreach ($Path in $Paths | Sort-Object -Unique) {
        if (-not (Test-Path $Path)) {
            Write-WarnMsg "Skipping backup for missing key: $Path"
            continue
        }

        $ExportPath = $Path -replace '^HKLM:\\', 'HKLM\\' -replace '^HKCU:\\', 'HKCU\\'
        $SafeName = ($Path -replace '[^A-Za-z0-9_.-]', '_')
        $TargetFile = Join-Path $BackupFolder "$SafeName.reg"

        try {
            & reg.exe export $ExportPath $TargetFile /y | Out-Null
            $Files += $TargetFile
            Write-OK "Backup created for $Path"
        }
        catch {
            Write-WarnMsg "Could not back up $Path : $($_.Exception.Message)"
        }
    }

    return $Files
}

function Restore-RegistryValues {
    param(
        [Parameter(Mandatory)][string[]]$Files
    )

    foreach ($File in $Files) {
        if (-not (Test-Path $File)) {
            Write-WarnMsg "Backup file missing: $File"
            continue
        }

        try {
            & reg.exe import $File | Out-Null
            Write-OK "Restored registry backup: $File"
        }
        catch {
            Write-Fail "Could not restore backup: $File : $($_.Exception.Message)"
        }
    }
}

function Write-ComplianceSummary {
    param(
        [Parameter(Mandatory)][hashtable]$Checks
    )

    Write-Section "COMPLIANCE SUMMARY"

    $Failed = 0
    foreach ($Item in $Checks.GetEnumerator() | Sort-Object Key) {
        $Name = $Item.Key
        $Expected = $Item.Value.Expected
        $Actual = $Item.Value.Actual
        $Matches = ($Actual -eq $Expected)

        if (-not $Matches) {
            $Failed++
            Write-WarnMsg "$Name expected $Expected but found $Actual"
        }
        else {
            Write-OK "$Name = $Actual"
        }
    }

    if ($Failed -eq 0) {
        Write-OK "Overall compliance status: PASS"
    }
    else {
        Write-WarnMsg "Overall compliance status: FAILED ($Failed checks did not match expected values)"
    }
}


Write-Section "SYSTEM INFORMATION"

$OS = Get-CimInstance Win32_OperatingSystem
$CS = Get-CimInstance Win32_ComputerSystem

Write-Host "Computer : $env:COMPUTERNAME"
Write-Host "User     : $env:USERNAME"
Write-Host "Windows  : $($OS.Caption)"
Write-Host "Version  : $($OS.Version)"
Write-Host "Build    : $($OS.BuildNumber)"
Write-Host "Domain   : $($CS.Domain)"
Write-Host "Log      : $LogFile"

Write-Section "PRE-FLIGHT CHECK"
try {
    Test-HardeningPreflight | Out-Null
    Write-OK "Preflight checks passed."
}
catch {
    Write-Fail $_.Exception.Message
    throw
}

$WindowsAI = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"
$UserWindowsAI = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"
$DataCollection = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
$WER = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting"
$CloudContentCU = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
$CloudContentLM = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
$Advertising = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo"
$SystemPolicy = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
$Feedback = "HKCU:\SOFTWARE\Microsoft\Siuf\Rules"
$SearchPolicy = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
$BackupRoot = Join-Path $LogRoot "backup"

if (-not $SkipBackup) {
    Write-Section "REGISTRY BACKUP"
    $BackupFiles = Backup-RegistryValues -Paths @(
        $WindowsAI,
        $UserWindowsAI,
        $DataCollection,
        $WER,
        $CloudContentCU,
        $CloudContentLM,
        $Advertising,
        $SystemPolicy,
        $Feedback,
        $SearchPolicy
    ) -BackupRoot $BackupRoot

    if ($BackupFiles.Count -gt 0) {
        Write-OK "Registry backup stored in $BackupRoot"
    }
}
else {
    Write-WarnMsg "Registry backup skipped by parameter."
}

# ===========================================================================
# 1. WINDOWS RECALL
# ===========================================================================

Write-Section "1. BLOCK WINDOWS RECALL"

$WindowsAI = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"

# Microsoft policy:
# Allow Recall to be enabled
#
# 0 = Recall unavailable.
# Microsoft documents that disabling this policy disables Recall,
# removes its bits, and deletes saved snapshots after restart.

Set-PolicyDWORD `
    -Path $WindowsAI `
    -Name "AllowRecallEnablement" `
    -Value 0 `
    -Description "Block Recall enablement"


# Turn off saving snapshots for Recall.
#
# 1 = disable snapshot saving.

Set-PolicyDWORD `
    -Path $WindowsAI `
    -Name "DisableAIDataAnalysis" `
    -Value 1 `
    -Description "Disable Recall snapshot saving"


# Also apply user-level policy as defense in depth.

$UserWindowsAI = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"

Set-PolicyDWORD `
    -Path $UserWindowsAI `
    -Name "DisableAIDataAnalysis" `
    -Value 1 `
    -Description "Disable Recall snapshots for current user"


# Explicitly remove the optional Recall component if present.

Write-Host ""
Write-Host "Checking Recall optional feature..."

try {

    $RecallFeature = Get-WindowsOptionalFeature `
        -Online `
        -FeatureName "Recall" `
        -ErrorAction Stop

    Write-Host "Recall feature state: $($RecallFeature.State)"

    if ($RecallFeature.State -ne "DisabledWithPayloadRemoved") {

        Write-Host "Removing Recall optional feature..."

        Disable-WindowsOptionalFeature `
            -Online `
            -FeatureName "Recall" `
            -Remove `
            -NoRestart `
            -ErrorAction Stop | Out-Null

        Write-OK "Recall optional feature removal requested."
    }
    else {
        Write-OK "Recall payload already removed."
    }
}
catch {
    Write-WarnMsg "Recall optional feature isn't present or couldn't be queried: $($_.Exception.Message)"
}


# ===========================================================================
# 2. CLICK TO DO
# ===========================================================================

Write-Section "2. DISABLE CLICK TO DO"

# Click to Do takes a screenshot when activated and analyzes screen content.
# Microsoft policy:
#
# DisableClickToDo = 1
#
# This disables the component and its entry points.

Set-PolicyDWORD `
    -Path $WindowsAI `
    -Name "DisableClickToDo" `
    -Value 1 `
    -Description "Disable Click to Do"

Set-PolicyDWORD `
    -Path $UserWindowsAI `
    -Name "DisableClickToDo" `
    -Value 1 `
    -Description "Disable Click to Do for current user"


# ===========================================================================
# 3. OTHER WINDOWS AI CONTENT-GENERATION FEATURES
# ===========================================================================

Write-Section "3. DISABLE UNNEEDED WINDOWS AI CONTENT FEATURES"

# These do NOT target Microsoft 365 Copilot.
#
# They target inbox Windows AI functionality such as Paint Cocreator,
# generative fill, etc.

Set-PolicyDWORD `
    -Path $WindowsAI `
    -Name "DisableCocreator" `
    -Value 1 `
    -Description "Disable Paint Cocreator"

Set-PolicyDWORD `
    -Path $WindowsAI `
    -Name "DisableGenerativeFill" `
    -Value 1 `
    -Description "Disable Windows generative fill"

Set-PolicyDWORD `
    -Path $WindowsAI `
    -Name "DisableImageCreator" `
    -Value 1 `
    -Description "Disable Windows Image Creator"


# ===========================================================================
# 4. WINDOWS DIAGNOSTIC DATA
# ===========================================================================

Write-Section "4. RESTRICT WINDOWS DIAGNOSTIC DATA"

$DataCollection = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"

Set-PolicyDWORD `
    -Path $DataCollection `
    -Name "AllowTelemetry" `
    -Value $DiagnosticDataLevel `
    -Description "Windows diagnostic data level"


# Prevent users from increasing telemetry through Settings.

Set-PolicyDWORD `
    -Path $DataCollection `
    -Name "DisableTelemetryOptInSettingsUx" `
    -Value 1 `
    -Description "Disable diagnostic-data opt-in UI"


# Prevent additional diagnostic logs from being collected/sent.

Set-PolicyDWORD `
    -Path $DataCollection `
    -Name "LimitDiagnosticLogCollection" `
    -Value 1 `
    -Description "Limit diagnostic log collection"


# Restrict dump collection.

Set-PolicyDWORD `
    -Path $DataCollection `
    -Name "LimitDumpCollection" `
    -Value 1 `
    -Description "Limit diagnostic dump collection"


# ===========================================================================
# 5. WINDOWS ERROR REPORTING DATA
# ===========================================================================

Write-Section "5. RESTRICT WINDOWS ERROR REPORTING"

$WER = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting"

# Keep WER itself available for enterprise support,
# but prevent requests for extra data.

Set-PolicyDWORD `
    -Path $WER `
    -Name "DontSendAdditionalData" `
    -Value 1 `
    -Description "WER: don't send additional data"


# ===========================================================================
# 6. TAILORED EXPERIENCES / PERSONALIZATION
# ===========================================================================

Write-Section "6. DISABLE DIAGNOSTIC-DATA PERSONALIZATION"

$CloudContentCU = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"

Set-PolicyDWORD `
    -Path $CloudContentCU `
    -Name "DisableTailoredExperiencesWithDiagnosticData" `
    -Value 1 `
    -Description "Disable tailored experiences using diagnostic data"


# ===========================================================================
# 7. MICROSOFT CONSUMER EXPERIENCES
# ===========================================================================

Write-Section "7. DISABLE MICROSOFT CONSUMER EXPERIENCES"

$CloudContentLM = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"

Set-PolicyDWORD `
    -Path $CloudContentLM `
    -Name "DisableWindowsConsumerFeatures" `
    -Value 1 `
    -Description "Disable Microsoft consumer experiences"

Set-PolicyDWORD `
    -Path $CloudContentLM `
    -Name "DisableCloudOptimizedContent" `
    -Value 1 `
    -Description "Disable cloud optimized content"

Set-PolicyDWORD `
    -Path $CloudContentLM `
    -Name "DisableConsumerAccountStateContent" `
    -Value 1 `
    -Description "Disable consumer account state content"


# ===========================================================================
# 8. WINDOWS SPOTLIGHT / SUGGESTED CONTENT
# ===========================================================================

Write-Section "8. DISABLE WINDOWS SPOTLIGHT SUGGESTIONS"

Set-PolicyDWORD `
    -Path $CloudContentCU `
    -Name "DisableWindowsSpotlightFeatures" `
    -Value 1 `
    -Description "Disable Windows Spotlight features"

Set-PolicyDWORD `
    -Path $CloudContentCU `
    -Name "DisableThirdPartySuggestions" `
    -Value 1 `
    -Description "Disable third-party Windows suggestions"

Set-PolicyDWORD `
    -Path $CloudContentCU `
    -Name "DisableWindowsSpotlightOnSettings" `
    -Value 1 `
    -Description "Disable Spotlight suggestions in Settings"


# ===========================================================================
# 9. ADVERTISING ID
# ===========================================================================

Write-Section "9. DISABLE ADVERTISING ID"

$Advertising = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo"

Set-PolicyDWORD `
    -Path $Advertising `
    -Name "DisabledByGroupPolicy" `
    -Value 1 `
    -Description "Disable Windows advertising ID"


# ===========================================================================
# 10. ACTIVITY HISTORY
# ===========================================================================

Write-Section "10. DISABLE ACTIVITY HISTORY CLOUD PUBLISHING"

$SystemPolicy = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"

# Do not publish activities to Microsoft/cloud services.

Set-PolicyDWORD `
    -Path $SystemPolicy `
    -Name "PublishUserActivities" `
    -Value 0 `
    -Description "Disable publishing user activities"


# Prevent cross-device upload of activities.

Set-PolicyDWORD `
    -Path $SystemPolicy `
    -Name "UploadUserActivities" `
    -Value 0 `
    -Description "Disable activity upload"


# Disable local Activity Feed collection.

Set-PolicyDWORD `
    -Path $SystemPolicy `
    -Name "EnableActivityFeed" `
    -Value 0 `
    -Description "Disable Windows Activity Feed"


# ===========================================================================
# 11. FEEDBACK REQUESTS
# ===========================================================================

Write-Section "11. DISABLE AUTOMATIC FEEDBACK REQUESTS"

$Feedback = "HKCU:\SOFTWARE\Microsoft\Siuf\Rules"

try {
    Confirm-RegKey $Feedback

    New-ItemProperty `
        -Path $Feedback `
        -Name "NumberOfSIUFInPeriod" `
        -PropertyType DWord `
        -Value 0 `
        -Force | Out-Null

    Write-OK "Disabled automatic Windows feedback prompts"
}
catch {
    Write-WarnMsg "Could not configure feedback frequency."
}


# ===========================================================================
# 12. WINDOWS SEARCH CLOUD CONTENT
# ===========================================================================

Write-Section "12. RESTRICT CLOUD SEARCH IN WINDOWS SEARCH"

# These settings affect Windows shell/search integration.
# They do NOT disable searching Exchange/SharePoint from within approved
# Microsoft 365 applications.

$SearchPolicy = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"

Set-PolicyDWORD `
    -Path $SearchPolicy `
    -Name "AllowCloudSearch" `
    -Value 0 `
    -Description "Disable Windows cloud search integration"


# ===========================================================================
# 13. OPTIONAL WINDOWS COPILOT APP REMOVAL
# ===========================================================================

Write-Section "13. WINDOWS COPILOT APP"

if ($RemoveWindowsCopilotApp) {

    Write-WarnMsg "Standalone Windows Copilot removal requested."

    # Policy is intentionally limited to the Windows Copilot app.
    # We are NOT changing Microsoft 365 Copilot/Office connected experiences.

    Set-PolicyDWORD `
        -Path $WindowsAI `
        -Name "RemoveMicrosoftCopilotApp" `
        -Value 1 `
        -Description "Remove standalone Microsoft Copilot app"
}
else {

    Write-Host "Standalone Windows Copilot app was NOT forcibly removed."
    Write-Host ""
    Write-Host "Microsoft 365 Copilot is intentionally preserved."
}


# ===========================================================================
# 14. EXPLICITLY DO NOT ALTER OFFICE/M365 COPILOT
# ===========================================================================

Write-Section "14. MICROSOFT 365 COPILOT PRESERVATION"

Write-OK "No Office connected-experience policies modified."
Write-OK "No Microsoft 365 Copilot policies modified."
Write-OK "No Word/Excel/PowerPoint/Outlook Copilot policies modified."
Write-OK "No Teams policies modified."
Write-OK "No Purview/DLP policies modified."
Write-OK "No sensitivity-label policies modified."


# ===========================================================================
# 15. SECURITY SERVICES WE INTENTIONALLY LEAVE ALONE
# ===========================================================================

Write-Section "15. SECURITY COMPONENTS PRESERVED"

Write-OK "Microsoft Defender configuration left intact."
Write-OK "SmartScreen configuration left intact."
Write-OK "Windows Update configuration left intact."
Write-OK "Windows Firewall configuration left intact."
Write-OK "Credential Guard configuration left intact."
Write-OK "BitLocker configuration left intact."
Write-OK "Entra ID configuration left intact."
Write-OK "Intune/MDM configuration left intact."
Write-OK "CAC/smart-card/certificate configuration left intact."
Write-OK "WSL configuration left intact."
Write-OK "Hyper-V configuration left intact."


# ===========================================================================
# 16. FORCE POLICY REFRESH
# ===========================================================================

Write-Section "16. REFRESH GROUP POLICY"

try {

    & gpupdate.exe /target:computer /force | Out-Host
    & gpupdate.exe /target:user /force | Out-Host

    Write-OK "Group Policy refresh completed."
}
catch {
    Write-WarnMsg "gpupdate failed: $($_.Exception.Message)"
}


# ===========================================================================
# 17. VERIFICATION / AUDIT REPORT
# ===========================================================================

Write-Section "17. GENERATING VERIFICATION REPORT"

$Audit = New-Object System.Collections.Generic.List[string]

$Audit.Add("WINDOWS 11 CUI/PII HARDENING AUDIT")
$Audit.Add("Generated: $(Get-Date)")
$Audit.Add("Computer : $env:COMPUTERNAME")
$Audit.Add("User     : $env:USERNAME")
$Audit.Add("Windows  : $($OS.Caption)")
$Audit.Add("Version  : $($OS.Version)")
$Audit.Add("Build    : $($OS.BuildNumber)")
$Audit.Add("")
$Audit.Add("=== WINDOWS AI ===")
$Audit.Add("AllowRecallEnablement = " + (Get-RegValueSafe -Path $WindowsAI -Name "AllowRecallEnablement"))
$Audit.Add("DisableAIDataAnalysis (machine) = " + (Get-RegValueSafe -Path $WindowsAI -Name "DisableAIDataAnalysis"))
$Audit.Add("DisableAIDataAnalysis (user) = " + (Get-RegValueSafe -Path $UserWindowsAI -Name "DisableAIDataAnalysis"))
$Audit.Add("DisableClickToDo (machine) = " + (Get-RegValueSafe -Path $WindowsAI -Name "DisableClickToDo"))
$Audit.Add("DisableClickToDo (user) = " + (Get-RegValueSafe -Path $UserWindowsAI -Name "DisableClickToDo"))
$Audit.Add("DisableCocreator = " + (Get-RegValueSafe -Path $WindowsAI -Name "DisableCocreator"))
$Audit.Add("DisableGenerativeFill = " + (Get-RegValueSafe -Path $WindowsAI -Name "DisableGenerativeFill"))
$Audit.Add("DisableImageCreator = " + (Get-RegValueSafe -Path $WindowsAI -Name "DisableImageCreator"))

$Audit.Add("")
$Audit.Add("=== DIAGNOSTIC DATA ===")
$Audit.Add("AllowTelemetry = " + (Get-RegValueSafe -Path $DataCollection -Name "AllowTelemetry"))
$Audit.Add("DisableTelemetryOptInSettingsUx = " + (Get-RegValueSafe -Path $DataCollection -Name "DisableTelemetryOptInSettingsUx"))
$Audit.Add("LimitDiagnosticLogCollection = " + (Get-RegValueSafe -Path $DataCollection -Name "LimitDiagnosticLogCollection"))
$Audit.Add("LimitDumpCollection = " + (Get-RegValueSafe -Path $DataCollection -Name "LimitDumpCollection"))

$Audit.Add("")
$Audit.Add("=== ERROR REPORTING ===")
$Audit.Add("DontSendAdditionalData = " + (Get-RegValueSafe -Path $WER -Name "DontSendAdditionalData"))

$Audit.Add("")
$Audit.Add("=== PERSONALIZATION / CONSUMER ===")
$Audit.Add("DisableTailoredExperiencesWithDiagnosticData = " + (Get-RegValueSafe -Path $CloudContentCU -Name "DisableTailoredExperiencesWithDiagnosticData"))
$Audit.Add("DisableWindowsConsumerFeatures = " + (Get-RegValueSafe -Path $CloudContentLM -Name "DisableWindowsConsumerFeatures"))
$Audit.Add("DisableCloudOptimizedContent = " + (Get-RegValueSafe -Path $CloudContentLM -Name "DisableCloudOptimizedContent"))
$Audit.Add("DisableConsumerAccountStateContent = " + (Get-RegValueSafe -Path $CloudContentLM -Name "DisableConsumerAccountStateContent"))
$Audit.Add("DisableWindowsSpotlightFeatures = " + (Get-RegValueSafe -Path $CloudContentCU -Name "DisableWindowsSpotlightFeatures"))
$Audit.Add("DisableThirdPartySuggestions = " + (Get-RegValueSafe -Path $CloudContentCU -Name "DisableThirdPartySuggestions"))
$Audit.Add("DisableWindowsSpotlightOnSettings = " + (Get-RegValueSafe -Path $CloudContentCU -Name "DisableWindowsSpotlightOnSettings"))

$Audit.Add("")
$Audit.Add("=== ADVERTISING / ACTIVITY ===")
$Audit.Add("DisabledByGroupPolicy = " + (Get-RegValueSafe -Path $Advertising -Name "DisabledByGroupPolicy"))
$Audit.Add("PublishUserActivities = " + (Get-RegValueSafe -Path $SystemPolicy -Name "PublishUserActivities"))
$Audit.Add("UploadUserActivities = " + (Get-RegValueSafe -Path $SystemPolicy -Name "UploadUserActivities"))
$Audit.Add("EnableActivityFeed = " + (Get-RegValueSafe -Path $SystemPolicy -Name "EnableActivityFeed"))

$Audit.Add("")
$Audit.Add("=== SEARCH ===")
$Audit.Add("AllowCloudSearch = " + (Get-RegValueSafe -Path $SearchPolicy -Name "AllowCloudSearch"))

$Audit.Add("")
$Audit.Add("=== COPILOT ===")
if ($RemoveWindowsCopilotApp) {
    $Audit.Add("RemoveMicrosoftCopilotApp = " + (Get-RegValueSafe -Path $WindowsAI -Name "RemoveMicrosoftCopilotApp"))
}
else {
    $Audit.Add("RemoveMicrosoftCopilotApp = not requested")
}

$Audit.Add("")
$Audit.Add("=== OPTIONAL FEATURE STATUS ===")
try {
    $RecallFeature = Get-WindowsOptionalFeature -Online -FeatureName "Recall" -ErrorAction Stop
    $Audit.Add("Recall feature state = $($RecallFeature.State)")
}
catch {
    $Audit.Add("Recall feature state = not present or not queryable")
}

$Audit.Add("")
$Audit.Add("=== REPORT NOTES ===")
$Audit.Add("This report captures the resulting registry values at the end of execution.")
$Audit.Add("Values may be overridden by enterprise GPO, Intune, or OS build differences.")
$Audit.Add("Review the transcript in $LogFile for execution details.")

$Audit | Out-File -FilePath $AuditFile -Encoding UTF8

$ComplianceChecks = @{
    "AllowRecallEnablement" = @{ Expected = 0; Actual = (Get-RegValueSafe -Path $WindowsAI -Name "AllowRecallEnablement") };
    "DisableAIDataAnalysis (machine)" = @{ Expected = 1; Actual = (Get-RegValueSafe -Path $WindowsAI -Name "DisableAIDataAnalysis") };
    "DisableAIDataAnalysis (user)" = @{ Expected = 1; Actual = (Get-RegValueSafe -Path $UserWindowsAI -Name "DisableAIDataAnalysis") };
    "DisableClickToDo (machine)" = @{ Expected = 1; Actual = (Get-RegValueSafe -Path $WindowsAI -Name "DisableClickToDo") };
    "DisableClickToDo (user)" = @{ Expected = 1; Actual = (Get-RegValueSafe -Path $UserWindowsAI -Name "DisableClickToDo") };
    "AllowTelemetry" = @{ Expected = $DiagnosticDataLevel; Actual = (Get-RegValueSafe -Path $DataCollection -Name "AllowTelemetry") };
    "DisableTelemetryOptInSettingsUx" = @{ Expected = 1; Actual = (Get-RegValueSafe -Path $DataCollection -Name "DisableTelemetryOptInSettingsUx") };
    "PublishUserActivities" = @{ Expected = 0; Actual = (Get-RegValueSafe -Path $SystemPolicy -Name "PublishUserActivities") };
    "UploadUserActivities" = @{ Expected = 0; Actual = (Get-RegValueSafe -Path $SystemPolicy -Name "UploadUserActivities") };
    "DisableWindowsConsumerFeatures" = @{ Expected = 1; Actual = (Get-RegValueSafe -Path $CloudContentLM -Name "DisableWindowsConsumerFeatures") };
    "AllowCloudSearch" = @{ Expected = 0; Actual = (Get-RegValueSafe -Path $SearchPolicy -Name "AllowCloudSearch") };
    "DisabledByGroupPolicy" = @{ Expected = 1; Actual = (Get-RegValueSafe -Path $Advertising -Name "DisabledByGroupPolicy") }
}

Write-ComplianceSummary -Checks $ComplianceChecks

Write-OK "Audit report saved to $AuditFile"
Write-Host ""
Write-Host "Logs: $LogFile"
Write-Host "Audit: $AuditFile"

if ($BackupRoot -and (Test-Path $BackupRoot)) {
    Write-Host "Backup root: $BackupRoot"
}

try {
    Stop-Transcript | Out-Null
}
catch {}
