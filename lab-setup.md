# Lab setup

How the lab is built, which log sources are connected, and the problems I hit while building it.

## Host

| Item | Value |
| --- | --- |
| Host | MacBook Pro M1 Pro, 16 GB RAM |
| Hypervisor | UTM (Apple Silicon, ARM64 guests) |
| Network | UTM shared network 192.168.64.0/24 |

## Machines

| Machine | OS | IP | RAM | Role |
| --- | --- | --- | --- | --- |
| wazuh-server | Ubuntu Server 24.04 ARM | 192.168.64.2 | CHECK | Wazuh 4.14 manager, indexer, dashboard (all-in-one) |
| ubuntu-victim | Ubuntu Server 24.04 ARM | 192.168.64.4 | CHECK | Linux target: SSH, nginx, Suricata, Wazuh agent |
| windows-victim | Windows 11 Pro ARM | 192.168.64.6 | CHECK | Windows target: Sysmon, PowerShell logging, Wazuh agent |
| Mac | macOS | 192.168.64.1 | – | Attacker: nmap, hydra, Nikto, curl |

Only the machines needed for a test run at the same time (wazuh-server + one victim), so everything fits in 16 GB.

## Build order

1. wazuh-server: install Wazuh all-in-one, open the dashboard at `https://192.168.64.2`.
2. ubuntu-victim: install the Wazuh agent pointing to 192.168.64.2 (ports 1514 and 1515).
3. ubuntu-victim: install Suricata and nginx, connect their logs to the agent.
4. windows-victim: install UTM guest tools, the Wazuh agent and Sysmon, enable PowerShell and audit logging.
5. Enable archives on wazuh-server so every event is stored, not only alerts.

## Log sources

### ubuntu-victim

SSH, sudo and user changes come from the system journal, which the agent reads by default. Suricata and nginx were added to `/var/ossec/etc/ossec.conf`:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata/eve.json</location>
</localfile>
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/nginx/access.log</location>
</localfile>
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/nginx/error.log</location>
</localfile>
```

Suricata (`/etc/suricata/suricata.yaml`), only the lines I changed:

```yaml
HOME_NET: "[192.168.64.4/32]"

af-packet:
  - interface: enp0s1
```

### windows-victim

Added to `C:\Program Files (x86)\ossec-agent\ossec.conf`:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
<localfile>
  <location>Microsoft-Windows-PowerShell/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Windows logging settings:

| Setting | Why | Used in |
| --- | --- | --- |
| Sysmon installed as a service | Process creation (EID 1) and file creation (EID 11) with full command lines | INC-006, INC-007, INC-008 |
| PowerShell Script Block Logging (EID 4104) | Shows the decoded content of PowerShell scripts | INC-007 |
| `auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable` | Logs scheduled task creation (EID 4698) | INC-008 |

### wazuh-server

Archives turned on in `/var/ossec/etc/ossec.conf`, so events that did not create an alert can still be searched:

```xml
<logall>yes</logall>
<logall_json>yes</logall_json>
```

Custom rules are in `/var/ossec/etc/rules/local_rules.xml` (copy in [`rules/local_rules.xml`](../rules/local_rules.xml)).

## Problems and fixes

| Problem | Cause | Fix |
| --- | --- | --- |
| Ubuntu installer crashed at "installing kernel" | Not enough RAM for the installer | Raised VM RAM to 4096 MB for the install, lowered it again afterwards |
| Installer kept booting from the ISO after install | Virtual CD still attached | Stopped the VM, removed the ISO in UTM (Edit → Drives → Clear) |
| Alerts missing in "Last 15 minutes" | VM clocks drifted by hours after the Mac slept, so alerts were stamped in the past | Installed chrony and set `makestep 1 -1` so the clock jumps to the correct time; `sudo chronyc makestep` to fix it immediately |
| Windows VM had no network | Missing network driver | Installed UTM guest tools |
| First SSH brute-force success not alerted (INC-002) | Not confirmed; archives were off, so the raw event could not be checked | Turned archives on and repeated the test; second run was detected (rule 40112) |
| Scheduled task creation not logged (INC-008) | Windows does not audit it by default | Enabled the "Other Object Access Events" audit policy |
| `Restart-Service WazuhSvc` failed | PowerShell was not run as administrator | Opened PowerShell with "Run as administrator" |

## Security

All attacks target only my own VMs on the private UTM network. Passwords and API keys are not stored in this repository.
