#Requires -Version 5.1
<#
  tmHids.ps1 -- trigger endpoint detections on a Windows host running a Wazuh
  agent + Sysmon. Lazy, portable companion to tmOrion.ps1 (network side).

  Each test generates the telemetry one Wazuh rule keys on -- a process
  creation, a registry write, a handle to lsass -- then undoes itself. No actual
  malware runs: renamed system binaries only echo, downloads are dummy stubs,
  registry/user/Defender changes are reverted by a cleanup step that always runs.

  Curated subset of the full TestMyEDR catalogue (../testmyedr), one or two of
  the strongest detections per MITRE tactic. The full 90-test suite with its web
  UI lives there; this is the grab-and-go version.

    .\tmHids.ps1          menu
    .\tmHids.ps1 -1       run test 1
    .\tmHids.ps1 -99      run everything (that your privilege level allows)
    .\tmHids.ps1 -l       list tests

  Run elevated to include the admin-only tests (marked [admin] in the list);
  without elevation they are skipped, not failed.

  GOTCHAS
    - Sysmon must be installed and configured, or almost nothing here is logged.
    - Test 1 (disable Defender) needs Tamper Protection OFF or Set-MpPreference
      is blocked by the OS before any rule can fire. Cleanup re-enables it.
    - Several tests spawn a short-lived child process on purpose: the rule keys
      on the *process creation* event (parent/child image, command line), which
      only exists if a real process is created -- so running the command inline
      in this shell would generate nothing.
#>

$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Run a command line as a short-lived child process so Sysmon logs EID 1
# (process creation). -Wait so cleanup does not race the process.
# Start-Process rejects an empty -ArgumentList, so omit it when there are no args.
function Start-Child([string]$FilePath, [string[]]$Arguments) {
  if ($Arguments) { Start-Process -FilePath $FilePath -ArgumentList $Arguments -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue }
  else            { Start-Process -FilePath $FilePath -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue }
}

# Launch a process that may hang (rundll32, fodhelper), give it a moment to
# generate its telemetry, then kill ONLY that PID -- never a blanket taskkill by
# image name, which would also take out legitimate instances on the host.
function Start-AndReap([string]$FilePath, [string[]]$Arguments, [int]$Seconds = 3) {
  $p = if ($Arguments) { Start-Process -FilePath $FilePath -ArgumentList $Arguments -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue }
       else            { Start-Process -FilePath $FilePath -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue }
  Start-Sleep -Seconds $Seconds
  if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
}

# Open a handle to a process with read access and close it immediately. This is
# the whole credential-dump / injection "attack": the ProcessAccess event
# (Sysmon EID 10) is what the rule matches; we never read a byte of memory.
function Open-ProcessHandle([string]$ProcName) {
  $sig = '[DllImport("kernel32.dll",SetLastError=true)] public static extern IntPtr OpenProcess(uint a, bool b, int c);' +
         '[DllImport("kernel32.dll",SetLastError=true)] public static extern bool CloseHandle(IntPtr h);'
  if (-not ('TmHids.Proc' -as [type])) {
    Add-Type -Name 'Proc' -Namespace 'TmHids' -MemberDefinition $sig -ErrorAction SilentlyContinue
  }
  $t = Get-Process $ProcName -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not $t) { Write-Host "      $ProcName not running"; return }
  $h = [TmHids.Proc]::OpenProcess(0x1010, $false, $t.Id)   # PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
  if ($h -ne [IntPtr]::Zero) {
    [void][TmHids.Proc]::CloseHandle($h)
    Write-Host "      opened handle to $ProcName PID $($t.Id) with 0x1010 access"
  } else {
    Write-Host "      OpenProcess on $ProcName failed (expected without the right privilege)"
  }
}

# Curated tests. Run/Cleanup are scriptblocks; Cleanup always runs after Run.
$Tests = @(
  @{ Num=1; Admin=$false; Tactic='Defense Evasion';   Rule='92008';
     Name='Defender realtime-disable command (-WhatIf, no change)';
     # SAFE BY DESIGN: -WhatIf makes Set-MpPreference emit the command line the rule
     # keys on WITHOUT applying anything, so Defender is never actually weakened --
     # the host that runs this is left exactly as it was. Verified: realtime stays
     # enabled, yet 92007->92008 still fire.
     # Launch via cmd.exe, NOT directly from this powershell: a powershell->powershell
     # spawn is caught by the generic rule 92027 first and 92008 never gets
     # attributed. A cmd parent keeps parentImage=cmd.exe so the chain fires.
     Run={ Start-Child 'cmd.exe' @('/c powershell.exe -Command "Set-MpPreference -DisableRealtimeMonitoring $true -WhatIf"') };
     Cleanup={} }

  @{ Num=2; Admin=$false; Tactic='Defense Evasion';   Rule='92016';
     Name='Masqueraded certutil.exe (renamed LOLBin)';
     # The masquerade filename must NOT contain "certutil": rule 92016 matches
     # originalFileName=CertUtil.exe (from PE metadata) AND image != certutil.exe.
     # A name like "notcertutil.exe" contains the substring and trips the negate,
     # so the rule excludes it. tmhids_cu.exe keeps originalFileName intact.
     Run={ Copy-Item "$env:WINDIR\System32\certutil.exe" "$env:TEMP\tmhids_cu.exe" -Force -ErrorAction SilentlyContinue
           Start-Child "$env:TEMP\tmhids_cu.exe" @('-?') };
     Cleanup={ Remove-Item "$env:TEMP\tmhids_cu.exe" -Force -ErrorAction SilentlyContinue } }

  @{ Num=3; Admin=$false; Tactic='Execution';         Rule='92057';
     Name='Encoded PowerShell command (nested powershell.exe)';
     # powershell.exe -> powershell.exe -EncodedCommand; decodes to Write-Host 'tmHIDS'.
     # The parent must be powershell.exe (this script) for the rule to match --
     # a cmd.exe intermediary breaks the parent chain and it never fires.
     Run={ Start-Child 'powershell.exe' @('-NoProfile','-EncodedCommand','VwByAGkAdABlAC0ASABvAHMAdAAgACcAdABtAEgASQBEAFMAJwA=') };
     Cleanup={} }

  @{ Num=4; Admin=$false; Tactic='Execution';         Rule='92081';
     Name='Rundll32 with suspicious (.txt) extension';
     Run={ 'tmhids' | Set-Content "$env:PUBLIC\tmhids_fake.txt" -Force
           Start-AndReap 'rundll32.exe' @("$env:PUBLIC\tmhids_fake.txt,#1") 3 };
     Cleanup={ Remove-Item "$env:PUBLIC\tmhids_fake.txt" -Force -ErrorAction SilentlyContinue } }

  @{ Num=5; Admin=$false; Tactic='Privilege Escalation'; Rule='92046';
     Name='Fodhelper.exe UAC bypass (ms-settings hijack)';
     Run={ $k = 'HKCU:\Software\Classes\ms-settings\Shell\Open\command'
           New-Item -Path $k -Force | Out-Null
           Set-ItemProperty -Path $k -Name '(default)' -Value 'cmd.exe /c echo tmHIDS_fodhelper_bypass'
           Set-ItemProperty -Path $k -Name 'DelegateExecute' -Value ''
           Start-AndReap 'fodhelper.exe' @() 3 };
     Cleanup={ Remove-Item 'HKCU:\Software\Classes\ms-settings' -Recurse -Force -ErrorAction SilentlyContinue } }

  @{ Num=6; Admin=$false; Tactic='Persistence';       Rule='92301';
     Name='Registry Run key (startup persistence)';
     Run={ Start-Child 'reg.exe' @('add','HKCU\Software\Microsoft\Windows\CurrentVersion\Run','/v','tmHIDS','/d','C:\Users\Public\tmhids.lnk','/f') };
     Cleanup={ Start-Child 'reg.exe' @('delete','HKCU\Software\Microsoft\Windows\CurrentVersion\Run','/v','tmHIDS','/f') } }

  @{ Num=7; Admin=$false; Tactic='Persistence';       Rule='92309';
     Name='COM hijack CLSID registry key';
     # Writes InprocServer32\(Default) -> a DLL in AppData: the real COM-hijack
     # technique, and the only CLSID write the deployed Sysmon config forwards
     # (it watches "...\InprocServer32\(Default)", not LocalServer32).
     # KNOWN GAP on this manager: rule 92308/92309 matches "CLSID.*LocalServer",
     # so this correct telemetry currently fires nothing. Broaden the rule to
     # CLSID.*(LocalServer|InprocServer) and this lights up. See README.
     Run={ $dll = Join-Path $env:LOCALAPPDATA 'tmhids.dll'
           Start-Child 'reg.exe' @('add','HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-TMHIDS00001}\InprocServer32','/ve','/d',$dll,'/f') };
     Cleanup={ Start-Child 'reg.exe' @('delete','HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-TMHIDS00001}','/f') } }

  @{ Num=8; Admin=$true;  Tactic='Credential Access'; Rule='92026';
     Name='Reg.exe SAM hive dump';
     # reg save fails if the file exists, so pre-delete, then dump, then cleanup.
     Run={ Remove-Item 'C:\Users\Public\tmhids_sam.hiv' -Force -ErrorAction SilentlyContinue
           Start-Child 'reg.exe' @('save','HKLM\SAM','C:\Users\Public\tmhids_sam.hiv') };
     Cleanup={ Remove-Item 'C:\Users\Public\tmhids_sam.hiv' -Force -ErrorAction SilentlyContinue } }

  @{ Num=9; Admin=$true;  Tactic='Credential Access'; Rule='92900';
     Name='LSASS handle access (credential-dump pattern)';
     Run={ Open-ProcessHandle 'lsass' };
     Cleanup={} }

  @{ Num=10; Admin=$false; Tactic='Process Injection'; Rule='61618';
     Name='Masqueraded svchost.exe from non-standard path';
     Run={ Copy-Item "$env:WINDIR\System32\cmd.exe" "$env:TEMP\svchost.exe" -Force -ErrorAction SilentlyContinue
           Start-Child "$env:TEMP\svchost.exe" @('/c','echo tmHIDS masqueraded svchost') };
     Cleanup={ Remove-Item "$env:TEMP\svchost.exe" -Force -ErrorAction SilentlyContinue } }

  @{ Num=11; Admin=$true;  Tactic='Account Manipulation'; Rule='92040';
     Name='Local user account creation (net.exe)';
     Run={ Start-Child 'net.exe' @('user','tmHIDS_User','TestP@ss123!','/add','/comment:tmHIDS') };
     Cleanup={ Start-Child 'net.exe' @('user','tmHIDS_User','/delete') } }

  @{ Num=12; Admin=$false; Tactic='Discovery';        Rule='92077';
     Name='WMI antivirus product enumeration';
     # wmic.exe is deprecated and may be absent on very recent Windows 11 builds.
     Run={ Start-Child 'wmic.exe' @('/namespace:\\root\SecurityCenter2','Path','AntiVirusProduct','Get','displayName') };
     Cleanup={} }
)

# ---------------------------------------------------------------------------

function Invoke-HidsTest([int]$n) {
  $t = $Tests | Where-Object { $_.Num -eq $n }
  if (-not $t) { Write-Host "  no such test: $n"; return }
  Write-Host ''
  Write-Host ("  [{0}] {1}  -> rule {2}" -f $t.Num, $t.Name, $t.Rule)
  if ($t.Admin -and -not $IsAdmin) {
    Write-Host '      SKIPPED. Needs an elevated (Run as administrator) session.'
    return
  }
  try { & $t.Run }
  catch { Write-Host "      error: $($_.Exception.Message)" }
  finally { & $t.Cleanup }   # always revert, even if Run threw partway
  Write-Host '      done.'
}

# Batch runner. These tests are designed to trip EDR, and Defender's behavior
# engine will TERMINATE the powershell.exe that runs them -- observed on the
# fodhelper UAC-bypass test (Behavior:Win32/UACBypassExp). If the whole batch
# shared one process, that kill would abort every later test AND skip the killed
# test's finally cleanup, leaving e.g. the ms-settings hijack key behind.
# So each test runs in its own short-lived child process (the individual -N
# path, which the host tolerates), and the orchestrator re-runs that test's
# cleanup afterwards as insurance in case the child was killed mid-run.
function Invoke-HidsBatch {
  $exe = Join-Path $PSHOME 'powershell.exe'
  foreach ($t in $Tests) {
    if ($t.Admin -and -not $IsAdmin) {
      Write-Host ''
      Write-Host ("  [{0}] {1}  -> rule {2}" -f $t.Num, $t.Name, $t.Rule)
      Write-Host '      SKIPPED. Needs an elevated (Run as administrator) session.'
      continue
    }
    & $exe -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath "-$($t.Num)"
    try { & $t.Cleanup } catch { }   # insurance: child may have been killed before its own cleanup
  }
}

function Show-Usage {
  Write-Host ''
  Write-Host '  tmHids -- trigger endpoint detections on a Wazuh + Sysmon host'
  Write-Host ("  elevation: {0}" -f $(if ($IsAdmin) { 'admin (all tests available)' } else { 'standard (admin tests will be skipped)' }))
  Write-Host ''
  foreach ($t in $Tests) {
    Write-Host ("    -{0,-2}  {1,-20} {2,-48} -> {3}{4}" -f `
      $t.Num, $t.Tactic, $t.Name, "rule $($t.Rule)", $(if ($t.Admin) { '  [admin]' } else { '' }))
  }
  Write-Host '    -99  run all of them'
  Write-Host ''
}

if ($args.Count -gt 0) {
  foreach ($a in $args) {
    if     ($a -eq '-99')              { Invoke-HidsBatch }
    elseif ($a -match '^-(\d+)$')      { Invoke-HidsTest ([int]$Matches[1]) }
    elseif ($a -in '-l','--list')      { Show-Usage }
    elseif ($a -in '-h','--help','/?') { Show-Usage }
    else   { Write-Host "  unknown argument: $a"; Show-Usage; exit 1 }
  }
  Write-Host ''
  exit 0
}

while ($true) {
  Write-Host ''
  Write-Host ("  tmHids -- {0}" -f $(if ($IsAdmin) { 'elevated' } else { 'standard (admin tests skipped)' }))
  Write-Host ''
  foreach ($t in $Tests) {
    Write-Host ("    {0,2})  {1,-20} {2}{3}" -f $t.Num, $t.Tactic, $t.Name, $(if ($t.Admin) { '  [admin]' } else { '' }))
  }
  Write-Host '     A)  RUN ALL'
  Write-Host '     Q)  Quit'
  $sel = Read-Host "`n  Choose which test you'd like to run"
  if     ($sel -match '^[Qq]')   { Write-Host ''; exit 0 }
  elseif ($sel -match '^[Aa]')   { Invoke-HidsBatch }
  elseif ($sel -match '^\d+$')   { Invoke-HidsTest ([int]$sel) }
  else   { Write-Host '  pick a number from the list' }
}
