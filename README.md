# Home SOC Lab — Endpoint & Network Detection Pipeline

![Splunk](https://img.shields.io/badge/Splunk-9.3-black?style=flat-square)
![Suricata](https://img.shields.io/badge/Suricata-IDS-orange?style=flat-square)
![pfSense](https://img.shields.io/badge/pfSense-firewall-blue?style=flat-square)
![Sysmon](https://img.shields.io/badge/Sysmon-endpoint%20telemetry-lightgrey?style=flat-square)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-mapped-red?style=flat-square)
![Atomic Red Team](https://img.shields.io/badge/Atomic%20Red%20Team-simulation-yellow?style=flat-square)

A self-built home lab that centralizes endpoint and network telemetry
into Splunk and maps detections to MITRE ATT&CK — built to practice the
full loop a SOC analyst actually works in: generate realistic attacker
behavior, capture it in logs, write the detection, and validate it fires.

![Architecture diagram]
<img width="3280" height="1800" alt="architecture-diagram" src="https://github.com/user-attachments/assets/669c20ab-dead-48e8-be44-3480e1feb2b9" />

---

## What this demonstrates

- **Log pipeline design** — Windows + Linux endpoints forwarding to a
  central Splunk indexer via Universal Forwarders, with a separate
  syslog path for network/firewall data.
- **Network-layer detection** — Suricata IDS running inline on pfSense,
  not just endpoint-only visibility.
- **MITRE ATT&CK–mapped detections** — four techniques simulated with
  Atomic Red Team and validated against hand-written SPL queries, not
  copy-pasted from a dashboard template.
- **Cross-platform correlation** — a single search correlating failed
  logins across both a Windows and a Linux host.
- **Documentation discipline** — every step reproducible from the notes
  in this repo, including the mistakes I hit along the way.

---

## Architecture at a glance

| Stage | Component | Role |
|---|---|---|
| Endpoints | Windows (Sysmon + WinEventLog) · Ubuntu (`auth.log`) | Data sources, both running a Splunk UF |
| Attack simulation | Atomic Red Team | Generates realistic attacker telemetry on the Windows host |
| Network perimeter | pfSense + Suricata (ET Open rules) | LAN gateway + inline IDS, forwards alerts via syslog |
| SIEM | Splunk Indexer / Search Head | Central store — `main`, `sysmon`, `pfsense` indexes |
| Detection | SPL + dashboards | MITRE ATT&CK–mapped queries, cross-OS correlation |

Full config: [`inputs.conf`](inputs.conf) · Full pfSense/Suricata build steps: [`pfsense-suricata/setup-notes.md`](pfsense-suricata/setup-notes.md)

---

## Detections

Simulated with Atomic Red Team, detected with hand-written SPL — see
[`spl-queries.md`](spl-queries.md) for the full query, sample output
fields, and notes on each one. Each detection also has a tool-agnostic
[Sigma](https://github.com/SigmaHQ/sigma) rule in
[`sigma-rules/`](sigma-rules/), so the logic isn't locked to Splunk.

| MITRE ATT&CK ID | Technique | Data source | Sigma rule |
|---|---|---|---|
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | PowerShell execution | Sysmon Event ID 1 | [`t1059_001_powershell_execution.yml`](sigma-rules/t1059_001_powershell_execution.yml) |
| [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | LSASS memory credential dumping | Sysmon Event ID 10 | [`t1003_001_lsass_memory_dump.yml`](sigma-rules/t1003_001_lsass_memory_dump.yml) |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Registry Run key persistence | Sysmon Event ID 13 | [`t1547_001_registry_run_key.yml`](sigma-rules/t1547_001_registry_run_key.yml) |
| [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Brute-force / password guessing | Windows EventCode 4625 + Linux `auth.log` | [`t1110_001_brute_force_windows.yml`](sigma-rules/t1110_001_brute_force_windows.yml) + [`t1110_001_brute_force_linux.yml`](sigma-rules/t1110_001_brute_force_linux.yml) |

> T1110.001 is split into two Sigma rules (Windows + Linux) tied together
> with a Sigma *correlation rule* example, since native Sigma rules can't
> reference two logsources at once the way the single cross-platform SPL
> search does. Documented as a comment in the Windows rule file.

Also included: a cross-platform failed-login correlation search and a
Suricata alert-severity panel (documented honestly in
`spl-queries.md` as a placeholder until the live EVE JSON field names
are confirmed — I'd rather show that in progress than fake a finished
panel).

---

## Reproducing this lab

1. Build the network: pfSense + Suricata — follow
   [`pfsense-suricata/setup-notes.md`](pfsense-suricata/setup-notes.md).
2. Install Splunk on the indexer VM, and a Universal Forwarder on the
   Windows and Ubuntu endpoints.
3. Drop in the relevant section of [`inputs.conf`](inputs.conf) on
   each host.
4. Install Sysmon on the Windows endpoint (SwiftOnSecurity config
   works well for a lab).
5. Run the Atomic Red Team tests listed in
   [`spl-queries.md`](spl-queries.md), then confirm each SPL query
   surfaces the corresponding event.

---

## Screenshots

<img width="1918" height="938" alt="Dashboards 3" src="https://github.com/user-attachments/assets/7fcea943-b404-4c61-a8cb-65e0642bf706" />
<img width="1918" height="938" alt="Dashboards (2)" src="https://github.com/user-attachments/assets/045e3e77-2c4c-47ca-bdbb-cf34d3bba7ac" />
<img width="1918" height="938" alt="Dashboards" src="https://github.com/user-attachments/assets/feac3ed7-792f-47e9-b6d2-48ed883645fc" />

---

## Lessons learned

- Remote logging and Suricata alert forwarding on pfSense are
  configured in two different places — enabling one doesn't get you
  the other for free.
- A single `head` with no argument silently defaults to 10 — worth
  spelling out explicitly in any query you're sharing publicly.
- Building the network detection layer (pfSense/Suricata) taught me
  far more about how alerts actually reach a SIEM than only running a
  SIEM against endpoint logs would have.



*Built as a personal home lab project — not affiliated with Splunk,
Suricata, pfSense, or MITRE.*
