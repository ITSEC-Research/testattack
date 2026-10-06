# testattack

Centralized, portable detection testing for **NIDS** and **HIDS**. One place to
safely fire the traffic and the endpoint activity that your network and host
sensors are supposed to alert on, so you can confirm they actually do.

Nothing malicious runs. Network tests send ordinary-looking packets a sensor
signatures on; endpoint tests generate the telemetry (a process creation, a
registry write, a handle to lsass) a rule keys on, then undo themselves. No
malware, no payloads, no persistence left behind.

| Layer | What it checks | Scripts |
|-------|----------------|---------|
| **NIDS** | Network sensor (Suricata / Zeek), Emerging Threats ruleset | `tmOrion.sh` (Linux), `tmOrion.ps1` (Windows) |
| **HIDS** | Endpoint agent (Wazuh + Sysmon) | `tmHids.ps1` (Windows) |

- **NIDS** tests run from any host *inside* the monitored network — Linux or
  Windows, whichever you have handy. Both scripts fire identical traffic.
- **HIDS** tests run *on* the Windows endpoint you want to validate.
- The full 90-test endpoint suite with a web UI lives separately in
  [`../testmyedr`](../testmyedr); `tmHids.ps1` is a grab-and-go subset of it.

## Requirements

**NIDS (`tmOrion.ps1` / `tmOrion.sh`)**
- A host inside the network a Suricata/Zeek sensor is watching.
- Windows: `curl.exe` (ships with Windows 10 1803+); DNS and TCP use built-ins.
- Linux: `curl`, `dig`, `nc`.

**HIDS (`tmHids.ps1`)**
- Windows 10/11, PowerShell 5.1+.
- Wazuh agent installed, **Sysmon installed and configured** (without it, almost
  nothing is logged).
- Run elevated (**Run as administrator**) to include the admin-only tests;
  without elevation they are skipped, not failed.

## Quick start (one-liner)

**NIDS — Linux**

```bash
# run all
curl -sSL https://raw.githubusercontent.com/ITSEC-Research/testattack/main/tmOrion.sh -o /tmp/tmOrion.sh && bash /tmp/tmOrion.sh -99

# interactive menu
curl -sSL https://raw.githubusercontent.com/ITSEC-Research/testattack/main/tmOrion.sh -o /tmp/tmOrion.sh && bash /tmp/tmOrion.sh
```

**NIDS — Windows (PowerShell)**

```powershell
# run all
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072; irm https://raw.githubusercontent.com/ITSEC-Research/testattack/main/tmOrion.ps1 -OutFile $env:TEMP\tmOrion.ps1; powershell -ExecutionPolicy Bypass -File $env:TEMP\tmOrion.ps1 -99

# interactive menu
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072; irm https://raw.githubusercontent.com/ITSEC-Research/testattack/main/tmOrion.ps1 -OutFile $env:TEMP\tmOrion.ps1; powershell -ExecutionPolicy Bypass -File $env:TEMP\tmOrion.ps1
```

**HIDS — Windows (elevated PowerShell)**

```powershell
# run all
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072; irm https://raw.githubusercontent.com/ITSEC-Research/testattack/main/tmHids.ps1 -OutFile $env:TEMP\tmHids.ps1; powershell -ExecutionPolicy Bypass -File $env:TEMP\tmHids.ps1 -99

# interactive menu
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072; irm https://raw.githubusercontent.com/ITSEC-Research/testattack/main/tmHids.ps1 -OutFile $env:TEMP\tmHids.ps1; powershell -ExecutionPolicy Bypass -File $env:TEMP\tmHids.ps1
```

The `-bor 3072` prefix forces TLS 1.2 for older
Windows builds; harmless on current ones.

## Usage

Each script runs the same three ways: interactive menu, a single test, or all.

### NIDS — Windows

```powershell
# Point it at hosts for your environment first (both optional).
$env:TMORION_TARGET     = "example.com"   # any external HTTP host; 404s are fine
$env:TMORION_LAN_TARGET = "10.0.0.5"      # a host on YOUR network (scan + lateral tests)

powershell.exe -ExecutionPolicy Bypass -File tmOrion.ps1        # menu
powershell.exe -ExecutionPolicy Bypass -File tmOrion.ps1 -2     # run test 2
powershell.exe -ExecutionPolicy Bypass -File tmOrion.ps1 -99    # run all
powershell.exe -ExecutionPolicy Bypass -File tmOrion.ps1 -l     # list
```

### NIDS — Linux

```bash
export TMORION_TARGET=example.com
export TMORION_LAN_TARGET=10.0.0.5
./tmOrion.sh            # menu
./tmOrion.sh -2         # run test 2
./tmOrion.sh -99        # run all
./tmOrion.sh -l         # list
```

### HIDS — Windows

```powershell
# Elevated prompt recommended (admin tests are skipped otherwise).
powershell.exe -ExecutionPolicy Bypass -File tmHids.ps1         # menu
powershell.exe -ExecutionPolicy Bypass -File tmHids.ps1 -1      # run test 1
powershell.exe -ExecutionPolicy Bypass -File tmHids.ps1 -99     # run all your privilege level allows
powershell.exe -ExecutionPolicy Bypass -File tmHids.ps1 -l      # list
```

After running, check your Wazuh / sensor dashboard for the rule IDs and
signature SIDs listed below. A test that fired but produced no alert is a
detection gap worth chasing.

## Included tests — NIDS

Traffic sent from inside the network. `LAN` tests need `TMORION_LAN_TARGET` set
(you must be authorised to send scan / lateral traffic to that host) and are
skipped otherwise.

| # | Test | Fires | Signature |
|---|------|-------|-----------|
| 1 | Malware C2 check-in | HTTP req to external host | sid 2029231 — ET MALWARE Zeoticus Ransomware CnC |
| 2 | Malicious domain DNS lookup | DNS query only (safest test) | sid 2029346 — ET MALWARE Possible Winnti DNS Lookup |
| 3 | Phishing credential submission | HTTP POST to external host | sid 2017753 — ET PHISHING Successful Remax Phish |
| 4 | Port scan / host discovery `LAN` | outbound SYNs + 300-port sweep | sid 2003068 — ET SCAN Potential SSH Scan OUTBOUND (+ Zeek scan) |
| 5 | Lateral movement SSH + RDP `LAN` | SSH banner + RDP mstshash cookie | sid 2038967 — ET INFO SSH-2.0-Go (+ Zeek ssh.log / rdp.log) |
| 6 | Command output in HTTP reply | HTTP body with `uid=0(root)` | sid 2100498 — GPL ATTACK_RESPONSE id check returned root |

## Included tests — HIDS

Endpoint activity on the Windows host. `[admin]` tests need an elevated session.
Rule IDs are Wazuh rule IDs. Every test reverts itself after running.

All tests are non-destructive: they generate the telemetry a rule keys on and
leave the host exactly as they found it. Nothing weakens the host's security
posture — the Defender test uses `-WhatIf`, so it raises the alert without ever
changing a setting.

| # | Tactic | Test | Wazuh rule | Admin | Fires¹ |
|---|--------|------|-----------|:-----:|:------:|
| 1 | Defense Evasion | Defender realtime-disable command (`-WhatIf`, no change) | 92008 | | ✓ |
| 2 | Defense Evasion | Masqueraded certutil.exe (renamed LOLBin) | 92016 | | ✓ |
| 3 | Execution | Encoded PowerShell command (nested powershell.exe) | 92057 | | ✓ |
| 4 | Execution | Rundll32 with suspicious (.txt) extension | 92081 | | ✓ |
| 5 | Privilege Escalation | Fodhelper.exe UAC bypass (ms-settings hijack) | 92046 | | ⚠ |
| 6 | Persistence | Registry Run key (startup persistence) | 92301 | | ✓ |
| 7 | Persistence | COM hijack CLSID registry key | 92309 | | ✗ |
| 8 | Credential Access | Reg.exe SAM hive dump | 92026 | ✓ | ⚠ |
| 9 | Credential Access | LSASS handle access (credential-dump pattern) | 92900 | ✓ | ✓ |
| 10 | Process Injection | Masqueraded svchost.exe from non-standard path | 61618 | | ✓ |
| 11 | Account Manipulation | Local user account creation (net.exe) | 92040 | ✓ | ✓ |
| 12 | Discovery | WMI antivirus product enumeration | 92077 | | ✓ |

¹ Validated live against the internal Wazuh manager (Windows 10 agent, Defender
active) on 2026-10-05. **9/12 fire reliably.** The other three are environmental,
not test defects:

- **5 (⚠ racy)** — Microsoft Defender's behavior engine detects the fodhelper
  UAC bypass (`Behavior:Win32/UACBypassExp`) and kills the process. If the child
  spawns under fodhelper before Defender wins the race, 92046 fires; otherwise
  Defender blocks it first. Fires on hosts without Defender RTP preempting.
- **8 (⚠ Defender-blocked)** — with Defender realtime on, `reg save HKLM\SAM` is
  blocked at process launch ("Access is denied"), so the rule never sees it. It
  fires when Defender is not the active AV (common for Wazuh+Sysmon-only hosts).
- **7 (✗ detection gap, product-side)** — the deployed Sysmon config only forwards
  COM-hijack writes ending in `\InprocServer32\(Default)`, but rule 92308/92309
  matches `CLSID.*LocalServer`. The two never intersect, so no registry write can
  trigger it. **Fix in the rule, not the test:** broaden rule 92308's
  `targetObject` regex to `CLSID.*(LocalServer|InprocServer)` (file
  `0860-sysmon_id_13.xml`). The test already writes the real-world InprocServer32
  variant, so it will light up once the rule is broadened.

## Safety notes

- No malware. Renamed system binaries only `echo`; "downloads" are dummy stubs;
  EICAR is not used here.
- **Nothing degrades the host's security posture.** The Defender test (1) uses
  `-WhatIf`: it emits the command line the rule detects but applies no change, so
  realtime protection is never actually disabled.
- HIDS tests undo themselves — a `cleanup` step runs after every test, even if
  the test errors partway (registry keys removed, temp users deleted, temp files
  deleted). Net effect on the host is nothing.
- HIDS tests kill only the specific PID they launched, never a blanket
  `taskkill` by image name that could hit legitimate processes.
- NIDS scan / lateral tests send traffic to a host *you* name and must be
  authorised to probe; they are skipped until you set `TMORION_LAN_TARGET`.

## Caveats

- These scripts generate telemetry and traffic; they do not read your sensor's
  alerts back. Correlation (did the rule actually fire?) is a manual check on
  the dashboard — or use the correlation tooling in `../testmyedr`.
- `wmic.exe` (HIDS test 12) is deprecated and may be absent on very recent
  Windows 11 builds.
- NIDS tests 4 and 5 depend on sensor rule direction/scope: SSH scan detection
  is scoped to traffic *leaving* the network, so those probes go to the external
  `TARGET`, while the broad sweep goes to the LAN host. See the comments in the
  scripts for the per-test rationale.
