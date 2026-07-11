# SPL Detection Queries — Home SIEM Lab

Splunk detection queries used against the lab environment: a Windows +
Ubuntu endpoint pair forwarding to a Splunk indexer, with pfSense
running Suricata as a network IDS, and Atomic Red Team used to
generate realistic attacker telemetry on the Windows host.

## Data Sources

| Index     | Source                                            | Notes                          |
|-----------|----------------------------------------------------|---------------------------------|
| `main`    | Windows App/System/Security logs, `/var/log/auth.log` | Default UF inputs               |
| `sysmon`  | `Microsoft-Windows-Sysmon/Operational`             | Endpoint telemetry for ATT&CK detections |
| `pfsense` | pfSense syslog + Suricata alerts                   | Network-layer events            |

---

## MITRE ATT&CK–Mapped Detections

Each of these was validated by running the matching Atomic Red Team
test on the Windows host, then confirming the query surfaces it.

### T1059.001 — Command and Scripting Interpreter: PowerShell

**Simulate:** `Invoke-AtomicTest T1059.001`

```spl
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1
Image="*\\powershell.exe"
| table _time, Computer, User, CommandLine, ParentImage
```

Flags any PowerShell process creation (Sysmon Event ID 1) and surfaces
the full command line + parent process, so you can spot suspicious
encoded commands or an unexpected parent (e.g. `winword.exe` spawning
`powershell.exe`).

**Sigma equivalent:** [`sigma-rules/t1059_001_powershell_execution.yml`](../sigma-rules/t1059_001_powershell_execution.yml)

---

### T1003.001 — OS Credential Dumping: LSASS Memory

**Simulate:** `Invoke-AtomicTest T1003.001`

```spl
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=10
TargetImage="*\\lsass.exe"
| table _time, Computer, SourceImage, TargetImage, GrantedAccess
| sort -_time
```

Sysmon Event ID 10 (ProcessAccess) against `lsass.exe` is the classic
credential-dumping signal (Mimikatz, procdump, etc). Watch
`GrantedAccess` values like `0x1010` or `0x1410` — these correspond to
access rights commonly requested by dumping tools.

**Sigma equivalent:** [`sigma-rules/t1003_001_lsass_memory_dump.yml`](sigma-rules/t1003_001_lsass_memory_dump.yml)

---

### T1547.001 — Registry Run Keys / Startup Folder

**Simulate:** `Invoke-AtomicTest T1547.001`

```spl
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=13
TargetObject="*\\CurrentVersion\\Run*"
| table _time, Computer, User, TargetObject, Details, Image
| sort -_time
```

Sysmon Event ID 13 (RegistryEvent - Value Set) catches persistence via
Run/RunOnce keys — a common technique for surviving reboots.

**Sigma equivalent:** [`sigma-rules/t1547_001_registry_run_key.yml`](sigma-rules/t1547_001_registry_run_key.yml)

---

### T1110.001 — Brute Force: Password Guessing (cross-platform)

**Simulate:** `Invoke-AtomicTest T1110.001`

```spl
index=*
(host="<windows-hostname>" EventCode=4625) OR (host="<linux-hostname>" "Failed password")
| rex field=_raw "Account Name:\s+(?<win_user>\S+)"
| rex field=_raw "Failed password for (?<invalid_linux_user>invalid user )?(?<lin_user>\S+)"
| eval OS = if(host="<windows-hostname>", "Windows", "Linux")
| eval User = coalesce(win_user, lin_user)
| timechart count by OS
```

Correlates Windows Event ID 4625 (failed logon) with Linux
`/var/log/auth.log` "Failed password" entries into a single
cross-platform timeline, tagged by OS.

> Replace `<windows-hostname>` / `<linux-hostname>` with your actual
> `host` values (e.g. `DESKTOP-XXXXX`, `ubuntu-hostname`) — hardcoding
> real hostnames in a public repo is a minor info-leak and worth
> avoiding.

**Sigma equivalent:** this single SPL search correlates two logsources at
once, which native Sigma rules (v1 schema) don't support directly. It's
split into two Sigma rules, one per platform, tied together with a Sigma
*correlation rule* (v2) — see
[`sigma-rules/t1110_001_brute_force_windows.yml`](sigma-rules/t1110_001_brute_force_windows.yml)
and
[`sigma-rules/t1110_001_brute_force_linux.yml`](sigma-rules/t1110_001_brute_force_linux.yml)
(the correlation rule itself is documented as a comment in the Windows file).

**Top targeted / attacking usernames:**

```spl
index=*
(host="<windows-hostname>" EventCode=4625) OR (host="<linux-hostname>" "Failed password")
| rex field=_raw "Account Name:\s+(?<win_user>\S+)"
| rex field=_raw "Failed password for (?<invalid_linux_user>invalid user )?(?<lin_user>\S+)"
| eval User = coalesce(win_user, lin_user)
| search User=* AND User!="-"
| stats count BY User
| sort - count
| head 10
```

(Added an explicit `head 10` — `| head` with no argument defaults to
10 anyway, but spelling it out makes the query self-documenting.)

---

## Suricata Alert Severity Panel (demo / placeholder data)

This panel was built **before** the real pfSense → Splunk syslog pipe
was fully producing parsed Suricata fields, as a placeholder so the
dashboard panel had something to render. It generates fake counts —
it is **not** reading real alerts yet:

```spl
index=* | head 1
| eval mock_data="1,2,3"
| makemv delim="," mock_data
| mvexpand mock_data
| eval Severity=case(mock_data=="1", "1 - High", mock_data=="2", "2 - Medium", mock_data=="3", "3 - Low")
| eval count=case(mock_data=="1", 14, mock_data=="2", 35, mock_data=="3", 82)
| fields Severity count
```

(Fixed a syntax bug from the original notes: `eval Severity-case(...)`
should be `eval Severity=case(...)` — a hyphen instead of an equals
sign, which would throw a search error.)

**TODO before treating this as a finished project artifact:** once
Suricata alerts are actually flowing into the `pfsense` index (see
`inputs.conf`), replace this with a real query against the parsed
`severity` field from the Suricata EVE JSON, e.g.:

```spl
index=pfsense sourcetype=pfsense_syslog alert.severity=*
| stats count BY alert.severity
```

Field names will depend on how pfSense formats the Suricata JSON
output — inspect a few raw events first (`index=pfsense | head 20`) to
confirm the actual field names before wiring this into a dashboard.

---


