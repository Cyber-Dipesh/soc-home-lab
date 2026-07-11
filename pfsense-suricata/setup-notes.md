# pfSense + Suricata Setup Notes

Role in the lab: pfSense is the router/firewall for the isolated LAN
segment the Windows and Ubuntu endpoints sit on, and Suricata runs
on it as a network-layer IDS. Both firewall events and Suricata
alerts are forwarded to the Splunk indexer over syslog (see
`inputs.conf` in the repo root for the receiving side).

---

## 1. Prerequisites

- VirtualBox or VMware Workstation/Player
- pfSense CE installer ISO
- A VM with **two virtual NICs**:
  - **Adapter 1 (WAN):** NAT or Bridged — gives pfSense internet access
  - **Adapter 2 (LAN):** Host-only — the isolated segment the Windows
    and Ubuntu lab endpoints will attach to

---

## 2. Install pfSense & Assign Interfaces

1. Boot the VM from the pfSense ISO and run through the installer
   (defaults are fine for a lab).
2. On first boot, the console menu asks you to assign interfaces —
   map Adapter 1 to **WAN** and Adapter 2 to **LAN**.

If a firewall rule locks you out of the console/GUI mid-setup:

```
Console menu > 8) Shell
pfctl -d      # temporarily disables packet filtering
```

Fix the offending rule, then either reboot or run `pfctl -e` to
re-enable filtering. Treat `pfctl -d` as a troubleshooting escape
hatch only — don't leave the firewall disabled.

---

## 3. Configure the LAN Interface IP

From the console menu: **2) Set interface(s) IP address** → select
**LAN**, then step through the prompts:

| Prompt                                   | Answer         |
|-------------------------------------------|----------------|
| Configure IPv4 via DHCP?                  | No             |
| Enter the new LAN IPv4 address             | `192.168.10.7` |
| Subnet bit count                          | `24`           |
| Upstream gateway (LAN has none)            | *(blank/Enter)*|
| Configure IPv6?                            | No             |
| Enable DHCP server on LAN?                 | No*            |
| Revert to HTTP as webConfigurator protocol?| No             |

\* Answered "No" here since lab endpoints are configured with static
IPs / manual forwarder config. Set this to "Yes" instead if you'd
rather have pfSense hand out DHCP leases to the Windows/Ubuntu VMs.

---

## 4. Log Into the Web GUI

Browse to `https://192.168.10.7` from a machine on the LAN segment.

- Default credentials: `admin` / `pfsense`
- **Change the default password immediately** — this is the first
  thing a reviewer/interviewer will ask about if they see a lab
  writeup with default creds still in it.

---

## 5. Install the Suricata Package

`System > Package Manager > Available Packages` → search **Suricata**
→ Install.

---

## 6. Configure Suricata

1. `Services > Suricata > Interfaces > Add`
   - Interface: choose **WAN** to see all inbound/outbound traffic,
     or **LAN** to focus on endpoint-generated traffic. For a home
     lab, WAN gives broader visibility.
   - Enable the interface, enable **Promiscuous Mode**.
2. `Services > Suricata > Global Settings`
   - Enable the **ET Open** rule source (free ruleset) and click
     **Update**.
3. Back in the interface's settings → **Categories** tab: enable the
   rule categories you care about for a lab (e.g., malware, exploit,
   scanning/recon, trojan-activity). Enabling everything is noisy —
   start narrow and expand.
4. `Services > Suricata > Interfaces` → click the play icon to start
   Suricata on that interface.

---

## 7. Forward Logs to Splunk

There are **two separate things** to forward — don't assume enabling
one gets you the other:

### 7a. pfSense system & firewall logs

`Status > System Logs > Settings`

- Enable **Remote Logging**
- **Remote log servers:** `<splunk-indexer-ip>:514`
- **Remote Syslog Contents:** check at minimum *System Events* and
  *Firewall Events* (check "Everything" if you want it all for now)
- Save

### 7b. Suricata alerts specifically

Enabling remote logging above forwards firewall/system logs — it does
**not** automatically include Suricata alerts. In the Suricata
interface settings, look for an **Alert Logging** tab and enable
sending alerts to the system log (exact wording varies by pfSense/
Suricata package version — check your installed version's tabs
directly rather than trusting a screenshot from a different release).
Prefer **EVE JSON** format over the legacy format if it's offered —
it's far easier for Splunk to field-extract.

Before trusting that alerts are reaching Splunk, confirm they're
landing locally first: `Status > System Logs > Suricata`.

---

## 8. Verify on the Splunk Side

- Confirm the `[udp://514]` stanza in `inputs.conf` (repo root) is
  active on the indexer and the `pfsense` index exists.
- Run `index=pfsense | head 20` in Splunk to inspect raw events before
  building anything on top of them.
- If fields aren't extracting cleanly, you likely need a dedicated
  `sourcetype` (and props.conf/transforms.conf) for the Suricata EVE
  JSON, separate from plain pfSense syslog — they won't parse the
  same way out of the box.

---

## Troubleshooting

- **No logs arriving at all:** check that a LAN firewall rule isn't
  blocking outbound UDP/514 from pfSense toward the indexer.
- **Locked out of the GUI after a rule change:** console shell →
  `pfctl -d` to disable filtering, fix the rule, then `pfctl -e` or
  reboot.
- **Version drift:** the Suricata package UI has moved things around
  across pfSense 2.6.x → 2.7.x. If a menu doesn't match these notes,
  check the installed version before assuming something's broken.

---

## Next Steps

- Once IDS visibility looks right, consider switching an interface to
  **IPS mode** (inline blocking) as a stretch goal.
- Once the real EVE JSON is parsing correctly in Splunk, swap the
  placeholder "Suricata Alert Severity" panel in `spl-queries.md` for
  a query against the real `alert.severity` field.
