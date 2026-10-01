# Windows CUI Hardening for Windows 11 26H2

This repository contains a PowerShell script that applies a set of local Windows 11 hardening settings intended for workstations that handle controlled unclassified information (CUI), personally identifiable information (PII), proprietary data, or other sensitive content.

The script is focused on reducing telemetry, disabling AI-related features that can process local content, and preventing cloud-side activity publishing and personalization features that are not needed for a hardened workstation. It includes safety controls for dry-run execution, registry backup, and post-change compliance checks so it is safer to use in enterprise or lab environments.

## What this script is for

The goal is to reduce the exposure surface of a Windows 11 device by adjusting local policy and Windows features in a defensive, workstation-focused way. The script is designed to:

- disable or restrict Windows Recall and Recall snapshot capture
- disable Click to Do
- disable unsupported or unnecessary Windows AI content-generation features
- lower Windows diagnostic data collection
- restrict error reporting and diagnostic log/dump collection
- disable tailored experiences that use diagnostic data
- disable consumer experience and Windows Spotlight content
- disable advertising ID and activity publishing/upload behaviors
- restrict Windows Search cloud integration
- optionally remove the standalone Windows Copilot app

The script explicitly preserves several security and enterprise features, including:

- Microsoft Defender
- SmartScreen
- Windows Update
- Windows Firewall
- Credential Guard
- BitLocker
- Microsoft Entra ID
- Intune/MDM
- certificate and smart-card configuration
- WSL and Hyper-V
- Microsoft 365 Copilot in Office applications

## Important notes

This is a hardening script, not a certification artifact.

- It does not guarantee CMMC, NIST, or DoD compliance.
- It is not a substitute for organizational GPO, Intune, or security baselines.
- Local policy or enterprise policy may override or revert settings.
- Some settings may vary by device edition, build, or hardware support.
- Features like Recall and Windows AI components can change across Windows builds.

Use this on a test machine first, especially if you need to validate compatibility with your environment.

## Prerequisites

Before running the script:

- use an elevated PowerShell session
- run on a supported Windows 11 26H2 device
- ensure you have local administrator rights
- confirm that your organization approves the hardening changes
- back up the system or snapshot the VM if you are making changes in a managed environment
- review the output in the generated log and audit files before deploying broadly

This script is intended for testing and controlled local remediation. It is not a substitute for centralized configuration management.

## Files in this repo

- `Harden-Windows26H2-CUI.ps1` - the hardening script
- `README.md` - this documentation

## How to run it

Open an elevated Windows PowerShell session and run the script from the folder containing it.

### Basic run

```powershell
Set-Location "C:\Path\To\Windows-Cui-Harden"
.\Harden-Windows26H2-CUI.ps1
```

### Lower diagnostic data more aggressively

```powershell
.\Harden-Windows26H2-CUI.ps1 -DiagnosticDataLevel 0
```

### Remove the standalone Windows Copilot app

```powershell
.\Harden-Windows26H2-CUI.ps1 -RemoveWindowsCopilotApp
```

### Preview changes without applying them

```powershell
.\Harden-Windows26H2-CUI.ps1 -WhatIf
```

This prints the registry values the script would change without modifying the system.

### Skip the registry backup before applying policy changes

```powershell
.\Harden-Windows26H2-CUI.ps1 -SkipBackup
```

By default, the script creates registry backups under `C:\ProgramData\CUI-Windows-Hardening\backup` before changing policy values. Use this switch only when you intentionally do not want a backup.

### Run with both options

```powershell
.\Harden-Windows26H2-CUI.ps1 -DiagnosticDataLevel 0 -RemoveWindowsCopilotApp -WhatIf
```

If execution is blocked by PowerShell policy, you can temporarily bypass it for the current session:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\Harden-Windows26H2-CUI.ps1
```

## What happens when it runs

The script will:

1. validate that the session is elevated and the operating system is compatible
2. create a log directory under `C:\ProgramData\CUI-Windows-Hardening`
3. create a registry backup unless `-SkipBackup` is used
4. start transcript logging
5. set local registry policy values under `HKLM:\SOFTWARE\Policies\...` and `HKCU:\SOFTWARE\Policies\...`
6. disable optional Windows features such as Recall when present
7. refresh Group Policy by invoking `gpupdate.exe /target:computer /force` and `gpupdate.exe /target:user /force`
8. generate a timestamped audit log and transcript in the log directory
9. print a compliance summary showing expected vs actual values for key settings

## Log locations

The script writes logs to:

- `C:\ProgramData\CUI-Windows-Hardening\Hardening-<timestamp>.log`
- `C:\ProgramData\CUI-Windows-Hardening\Audit-<timestamp>.txt`
- `C:\ProgramData\CUI-Windows-Hardening\backup\RegistryBackup-<timestamp>\...`

These logs can help verify which settings were written, whether the script completed successfully, and what registry backups were created before the change.

## Guidance for enterprise use

For managed endpoint environments, this script should usually be treated as a local remediation tool or a reference for Intune or GPO baselines. In many enterprise environments, centralized policy is the safer way to enforce the same settings across many devices.

This script includes a dry-run mode and compliance summary, but it is still best used as a controlled baseline for test devices and lab environments before converting the same settings into an organization-managed policy model.

Before using it broadly, validate:

- your organization approves the privacy and telemetry reductions
- the device is in a supported branch and edition
- business workflows do not require Recall, Click to Do, or other AI features
- security and support teams are aware of the change
- the endpoint is not already managed by a GPO or Intune policy that overrides the local values

## Troubleshooting

### Script does not run

Check that:

- the shell is elevated
- execution policy allows local scripts
- the machine is not subject to a policy that blocks the changes
- you are not trying to run it in a non-admin PowerShell session

### Group Policy refresh fails

The script catches the failure and writes a warning, but the registry changes may still have been written successfully.

### Settings are not present after execution

This can happen if:

- an organization policy is overriding local policy
- the device uses a different Windows build than expected
- the feature does not exist on the device in the current build
- the value was rolled back by another policy or application

### Compliance check shows unexpected values

Review the generated audit file and compare expected vs actual values. If a value is not matching, check whether a local or enterprise policy is controlling that key.

## Security and operational caution

This script makes policy changes to a live operating system. It is intended for administrators who understand the impact of disabling AI, diagnostic, and privacy features.

Do not run this script in an environment where:

- local settings must remain unchanged
- legal or governance approvals have not been obtained
- the machine must remain in a default consumer configuration

## Summary

This script is best viewed as a targeted hardening baseline for privacy-conscious Windows 11 systems handling sensitive information. It is especially useful for workstations that need to reduce reputation, telemetry, and local AI-content processing exposure while preserving core enterprise security and productivity features.

The current version is safer than the original baseline because it includes dry-run behavior, preflight validation, registry backups, and post-change compliance checks. It remains best suited for controlled local remediation and validation before converting the same policy values into Group Policy, Intune, or MDM configuration.
