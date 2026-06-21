[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param(
 [switch]$EnableAllProfiles,
 [string]$EnableRule,
 [string]$DisableRule,
 [string]$RemoveRule,
 [string]$NewRuleName,
 [ValidateSet('Inbound','Outbound')][string]$Direction='Inbound',
 [ValidateSet('TCP','UDP')][string]$Protocol='TCP',
 [int]$LocalPort,
 [switch]$DryRun,
 [switch]$Yes,
 [string]$OutputPath=(Join-Path $env:ProgramData 'WindowsFirewallPolicyRepair')
)
$ErrorActionPreference='Stop';$script:Failures=0;$script:Actions=0
$run=Join-Path $OutputPath (Get-Date -Format yyyyMMdd_HHmmss);New-Item -ItemType Directory $run -Force|Out-Null
$log=Join-Path $run 'repair.log';$before=Join-Path $run 'before.json';$after=Join-Path $run 'after.json'
function Log($m){"$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $m"|Tee-Object -FilePath $log -Append}
function Admin{$p=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent());$p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)}
function State{[pscustomobject]@{Collected=Get-Date;Profiles=Get-NetFirewallProfile|Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction;SelectedRules=@($EnableRule,$DisableRule,$RemoveRule,$NewRuleName)|Where-Object {$_}|ForEach-Object{Get-NetFirewallRule -DisplayName $_ -ErrorAction SilentlyContinue|Select-Object DisplayName,Enabled,Direction,Action,Profile}}}
function Act($d,[scriptblock]$a){$script:Actions++;Log $d;if($DryRun){Log "DRY-RUN: $d";return};try{&$a;Log "SUCCESS: $d"}catch{$script:Failures++;Log "FAILED: $d - $($_.Exception.Message)"}}
State|ConvertTo-Json -Depth 6|Set-Content $before -Encoding UTF8
if(-not($EnableAllProfiles -or $EnableRule -or $DisableRule -or $RemoveRule -or $NewRuleName)){Write-Error 'Choose at least one repair action.';exit 2}
if($NewRuleName -and ($LocalPort -lt 1 -or $LocalPort -gt 65535)){Write-Error '-LocalPort must be between 1 and 65535.';exit 2}
if(-not $DryRun -and -not(Admin)){Write-Error 'Run from elevated PowerShell.';exit 4}
if(-not $Yes -and -not $DryRun){if((Read-Host 'Apply selected Windows Firewall changes? Type YES') -ne 'YES'){Log 'Cancelled.';exit 10}}
if($EnableAllProfiles){Act 'Enabling all Windows Firewall profiles' {Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True}}
if($EnableRule){Get-NetFirewallRule -DisplayName $EnableRule -ErrorAction Stop|Out-Null;Act "Enabling firewall rule $EnableRule" {Enable-NetFirewallRule -DisplayName $EnableRule}}
if($DisableRule){Get-NetFirewallRule -DisplayName $DisableRule -ErrorAction Stop|Out-Null;Act "Disabling firewall rule $DisableRule" {Disable-NetFirewallRule -DisplayName $DisableRule}}
if($RemoveRule){Get-NetFirewallRule -DisplayName $RemoveRule -ErrorAction Stop|Out-Null;Act "Removing firewall rule $RemoveRule" {Remove-NetFirewallRule -DisplayName $RemoveRule}}
if($NewRuleName){Act "Creating $Direction allow rule $NewRuleName for $Protocol port $LocalPort" {New-NetFirewallRule -DisplayName $NewRuleName -Group 'Support Managed Rules' -Direction $Direction -Action Allow -Protocol $Protocol -LocalPort $LocalPort -Profile Any|Out-Null}}
Start-Sleep 2;State|ConvertTo-Json -Depth 6|Set-Content $after -Encoding UTF8
if($script:Failures){exit 20};Log "Repair completed. Actions: $script:Actions";exit 0
