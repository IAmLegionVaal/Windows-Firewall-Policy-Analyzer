# Windows Firewall Policy Analyzer

PowerShell tools for Windows Firewall profile, policy and rule analysis plus guarded rule repair.

## Analyze

Use the repository's analyzer script to review profiles and firewall rules before making changes.

## Repair

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Windows_Firewall_Policy_Repair_Toolkit.ps1 -EnableAllProfiles -DryRun
```

Examples:

```powershell
.\Windows_Firewall_Policy_Repair_Toolkit.ps1 -EnableAllProfiles
.\Windows_Firewall_Policy_Repair_Toolkit.ps1 -EnableRule 'Approved Rule'
.\Windows_Firewall_Policy_Repair_Toolkit.ps1 -DisableRule 'Problem Rule'
.\Windows_Firewall_Policy_Repair_Toolkit.ps1 -RemoveRule 'Obsolete Support Rule'
.\Windows_Firewall_Policy_Repair_Toolkit.ps1 -NewRuleName 'Support HTTPS' -Direction Outbound -Protocol TCP -LocalPort 443
```

The repair script validates exact rule names, captures selected rules and profile state before and after repair, groups newly created rules under `Support Managed Rules`, and supports `-DryRun`, confirmation, logs and clear exit codes.

## Author

Dewald Pretorius — L2 IT Support Engineer
