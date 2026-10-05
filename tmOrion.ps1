#Requires -Version 5.1
<#
  tmOrion.ps1 -- trigger network detections on a deployed Suricata/Zeek sensor.
  Windows PowerShell port of tmOrion.sh. Same six tests, same signatures.

  Run it from a host INSIDE the network the sensor is watching. Each test
  generates one piece of ordinary-looking traffic that a stock Emerging Threats
  ruleset alerts on. Nothing malicious runs, nothing is installed, nothing is
  written to disk.

    .\tmOrion.ps1          menu
    .\tmOrion.ps1 -1       run test 1
    .\tmOrion.ps1 -99      run everything
    .\tmOrion.ps1 -l       list tests

  Two hosts to point it at (environment variables, same names as the bash tool):
    TMORION_TARGET      an external HTTP host. Any will do -- the signatures
                        match the request, not the reply, so a 404 is fine.
                        Default example.com.
    TMORION_LAN_TARGET  a host on your own network, used by the scan and lateral
                        movement tests. No default: those two generate traffic
                        you need to be authorised to send, so you have to name it.
    TMORION_DNS         resolver to send the malicious-domain lookup to. Defaults
                        to your first non-loopback DNS server, else 1.1.1.1.
#>

$Target    = if ($env:TMORION_TARGET)     { $env:TMORION_TARGET }     else { 'example.com' }
$LanTarget = if ($env:TMORION_LAN_TARGET) { $env:TMORION_LAN_TARGET } else { '' }

$Tests = @(
  @{ Num = 1; Name = 'Malware C2 check-in            -> sid 2029231  ET MALWARE Zeoticus Ransomware CnC' }
  @{ Num = 2; Name = 'Malicious domain DNS lookup    -> sid 2029346  ET MALWARE Possible Winnti DNS Lookup' }
  @{ Num = 3; Name = 'Phishing credential submission -> sid 2017753  ET PHISHING Successful Remax Phish' }
  @{ Num = 4; Name = 'Port scan / host discovery     -> sid 2003068  ET SCAN Potential SSH Scan OUTBOUND' }
  @{ Num = 5; Name = 'Lateral movement SSH + RDP     -> sid 2038967  ET INFO SSH-2.0-Go version string' }
  @{ Num = 6; Name = 'Command output in HTTP reply   -> sid 2100498  GPL ATTACK_RESPONSE id check returned root' }
)

# ---------------------------------------------------------------------------

function Test-LanTarget {
  if ($LanTarget) { return $true }
  Write-Host '  SKIPPED. This test sends traffic to a host on your own network.'
  Write-Host '  Name it first:  $env:TMORION_LAN_TARGET = "10.0.0.5"'
  return $false
}

# Resolver the malicious-domain lookup is sent to. We query an explicit external
# resolver rather than the system default so the query leaves the host where the
# sensor can see it, instead of being answered from the local client cache.
function Get-DnsServer {
  if ($env:TMORION_DNS) { return $env:TMORION_DNS }
  $s = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
         Select-Object -ExpandProperty ServerAddresses -ErrorAction SilentlyContinue |
         Where-Object { $_ -and $_ -notmatch '^127\.' } |
         Select-Object -First 1
  if ($s) { return $s }
  return '1.1.1.1'
}

# Fire a single SYN and move on -- we never complete or use the connection, the
# packet leaving the host is the whole point. Used by the scan test, where what
# the signatures count is outbound SYNs, not established sessions.
# ponytail: fire-and-forget, not a real connect scan. That is all the sigs need.
function Send-Syn([string]$RemoteHost, [int]$Port) {
  try {
    $c = New-Object System.Net.Sockets.TcpClient
    [void]$c.BeginConnect($RemoteHost, $Port, $null, $null)
    Start-Sleep -Milliseconds 40
    $c.Close()
  } catch { }
}

# Connect (with timeout) and send a payload. Used by the lateral-movement test,
# which has to actually reach the port for Zeek to log the ssh/rdp message.
function Send-Payload([string]$RemoteHost, [int]$Port, [byte[]]$Payload, [int]$TimeoutMs = 3000) {
  $c = New-Object System.Net.Sockets.TcpClient
  try {
    $iar = $c.BeginConnect($RemoteHost, $Port, $null, $null)
    if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs)) { $c.Close(); return }
    $c.EndConnect($iar)
    $s = $c.GetStream()
    $s.Write($Payload, 0, $Payload.Length)
    $s.Flush()
    Start-Sleep -Milliseconds 200
    $c.Close()
  } catch { } finally { $c.Close() }
}

# A C2 check-in: the URI and the three-character User-Agent are what the
# signature keys on. The reply is irrelevant, so any HTTP host works.
function Invoke-Test1 {
  curl.exe -s -m 10 -A 'DxD' "http://$Target/supersecretstring?babyDontHeartMe=1" > $null 2>&1
}

# A lookup for a domain on a public C2 list. Only the DNS query leaves the host
# -- nothing ever connects to the domain, so this is the safest test here.
function Invoke-Test2 {
  Resolve-DnsName -Name 'update.livehost.live' -Server (Get-DnsServer) -Type A -QuickTimeout -ErrorAction SilentlyContinue | Out-Null
}

# The victim submitting credentials to a phishing kit, which is the half of a
# phish a network sensor can actually see. The "Sign+In" field and the
# /hotmail.php path are the match.
function Invoke-Test3 {
  curl.exe -s -m 10 `
    -A 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36' `
    -d 'login=user%40example.com&passwd=Summer2026%21&Sign+In=Sign+In' `
    "http://$Target/hotmail.php" > $null 2>&1
}

# Two halves, and they deliberately go to different hosts.
#
# The signature is scoped $HOME_NET -> $EXTERNAL_NET 22, so the SSH probes have
# to leave the network to match -- pointing them at a host on your own LAN fires
# nothing. It counts SYNs by source, 5 within 120 seconds, so six is enough.
#
# Zeek's scan detection has no such direction constraint but wants breadth, so
# the wide sweep goes at the LAN host instead of hammering a stranger's box.
function Invoke-Test4 {
  1..6 | ForEach-Object { Send-Syn $Target 22 }
  if (-not (Test-LanTarget)) { return }
  Write-Host "      sweeping 300 ports on $LanTarget for Zeek scan detection ..."
  1..300 | ForEach-Object { Send-Syn $LanTarget $_ }
}

# An SSH client identifying itself as SSH-2.0-Go, then an RDP connection request
# carrying an mstshash cookie. Both are logged by Zeek (ssh.log, rdp.log)
# whether or not the target actually runs those services.
function Invoke-Test5 {
  if (-not (Test-LanTarget)) { return }
  Send-Payload $LanTarget 22 ([System.Text.Encoding]::ASCII.GetBytes("SSH-2.0-Go`r`n"))

  # 0x33 is the total TPKT length and 0x2e the X.224 length indicator (total
  # minus the 4-byte TPKT header and the indicator itself). Both have to match
  # the cookie length or Zeek's RDP analyzer rejects the message and rdp.log
  # stays empty -- change the username and these two bytes change with it.
  $pre    = [byte[]](0x03,0x00,0x00,0x33,0x2e,0xe0,0x00,0x00,0x00,0x00,0x00)
  $cookie = [System.Text.Encoding]::ASCII.GetBytes("Cookie: mstshash=administrator`r`n")
  $post   = [byte[]](0x01,0x00,0x08,0x00,0x03,0x00,0x00,0x00)
  Send-Payload $LanTarget 3389 ($pre + $cookie + $post)
}

# Command output coming back over HTTP -- the classic sign of a web shell or a
# successful RCE. The signature matches the string anywhere in the payload, so
# sending it works as well as receiving it.
function Invoke-Test6 {
  curl.exe -s -m 10 -d 'uid=0(root) gid=0(root) groups=0(root)' "http://$Target/" > $null 2>&1
}

# ---------------------------------------------------------------------------

function Invoke-OrionTest([int]$n) {
  $t = $Tests | Where-Object { $_.Num -eq $n }
  if (-not $t) { Write-Host "  no such test: $n"; return }
  Write-Host ''
  Write-Host "  [$n] $($t.Name)"
  & "Invoke-Test$n"
  Write-Host '      done.'
}

function Show-Usage {
  Write-Host ''
  Write-Host '  tmOrion -- trigger network detections on a Suricata/Zeek sensor'
  Write-Host ''
  foreach ($t in $Tests) { Write-Host ("    -{0}   {1}" -f $t.Num, $t.Name) }
  Write-Host '    -99  run all of them'
  Write-Host ''
  Write-Host "  TMORION_TARGET      external HTTP host    (now: $Target)"
  Write-Host ("  TMORION_LAN_TARGET  host on your network  (now: {0})" -f $(if ($LanTarget) { $LanTarget } else { 'not set' }))
  Write-Host ''
}

if (-not (Get-Command curl.exe -ErrorAction SilentlyContinue)) {
  Write-Host "  warning: curl.exe not found, the three HTTP tests will not run"
}

if ($args.Count -gt 0) {
  foreach ($a in $args) {
    if     ($a -eq '-99')                 { foreach ($t in $Tests) { Invoke-OrionTest $t.Num } }
    elseif ($a -match '^-(\d+)$')         { Invoke-OrionTest ([int]$Matches[1]) }
    elseif ($a -in '-l','--list')         { Show-Usage }
    elseif ($a -in '-h','--help','/?')    { Show-Usage }
    else   { Write-Host "  unknown argument: $a"; Show-Usage; exit 1 }
  }
  Write-Host ''
  exit 0
}

while ($true) {
  Write-Host ''
  Write-Host ("  tmOrion -- target: {0}   lan: {1}" -f $Target, $(if ($LanTarget) { $LanTarget } else { 'not set' }))
  Write-Host ''
  foreach ($t in $Tests) { Write-Host ("    {0})  {1}" -f $t.Num, $t.Name) }
  Write-Host '    A)  CHAOS! RUN ALL!'
  Write-Host '    Q)  Quit'
  $sel = Read-Host "`n  Choose which test you'd like to run"
  if     ($sel -match '^[Qq]')   { Write-Host ''; exit 0 }
  elseif ($sel -match '^[Aa]')   { foreach ($t in $Tests) { Invoke-OrionTest $t.Num } }
  elseif ($sel -match '^\d+$')   { Invoke-OrionTest ([int]$sel) }
  else   { Write-Host '  pick a number from the list' }
}
