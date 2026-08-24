# Wazuh Detection Rules

![Wazuh](https://img.shields.io/badge/Wazuh-4.x-1f6feb)
![Platform](https://img.shields.io/badge/platform-Linux-333333)
![ATT&CK](https://img.shields.io/badge/ATT%26CK-mapped-b91c1c)

Behavioural detection content for [Wazuh](https://wazuh.com), aimed at Living-off-the-Land (LotL) techniques on Linux hosts. The current ruleset covers the GTFOBins class of privilege escalation and shell breakouts, mapped to MITRE ATT&CK. Rules run on the Wazuh manager against events collected from local agents.

Maintained by [magsec-IT](https://magsec-it.de).

## Scope

These rules target local privilege escalation and shell breakouts through trusted binaries: the GTFOBins pattern, where a legitimate tool (`find`, `awk`, `perl`, `vim`, `less`, `python`, ...) is abused to spawn a shell or run commands with elevated rights.

Detection is behavioural. Instead of matching file hashes, the rules look for the process and argument patterns these breakouts produce, seen through two independent sources:

- **sudo events** &ndash; high fidelity, built on the sudo logging Wazuh already classifies.
- **auditd `execve`** &ndash; wider coverage that also catches non-sudo breakouts such as SUID abuse and restricted-shell escapes.

Both sources are useful on their own. Running them together gives you a narrow, low-noise signal from sudo plus a broader net from auditd.

## Requirements

- Wazuh manager 4.x (the rules use `pcre2` matching and the `<mitre>` block).
- Linux agents forwarding the relevant logs:
  - sudo activity (`/var/log/auth.log` or `/var/log/secure`) for rule `100200`.
  - auditd (`/var/log/audit/audit.log`) with `execve` auditing enabled for rule `100210`.

For the auditd path, the host needs an audit rule that records `execve`:

```
-a always,exit -F arch=b64 -S execve -k exec
-a always,exit -F arch=b32 -S execve -k exec
```

and Wazuh configured to read the audit log:

```xml
<localfile>
  <log_format>audit</log_format>
  <location>/var/log/audit/audit.log</location>
</localfile>
```

## Repository layout

```
.
├── rules/
│   └── gtfobins_rules.xml
└── README.md
```

Each rule file is self-contained: it carries its own `<group>` root element, so it drops into `/var/ossec/etc/rules/` without touching the stock ruleset and without a multi-root conflict.

## Rule conventions

| Convention      | Value                                                        |
| --------------- | ----------------------------------------------------------- |
| Custom SID range | `>= 100000`                                                |
| Group taxonomy  | `magsec,gtfobins,` plus a per-rule `gtfobins,privilege_escalation,` |
| Matching        | `pcre2`                                                     |
| ATT&CK mapping  | a `<mitre>` block on every rule                             |
| Level           | scaled to the confidence of the source (see below)          |

Levels follow how much context the source gives:

- **12** for the sudo breakout. It only fires on events already classified as `sudo`, so the context is tight and false positives are rare.
- **10** for the auditd `execve` breakout. It is broad by design. Treat it as a starting point and tune it before you rely on it in production.

## Rules

| SID      | Level | Trigger              | Detects                                                                                                                      | ATT&CK              |
| -------- | ----- | -------------------- | --------------------------------------------------------------------------------------------------------------------------- | ------------------- |
| `100200` | 12    | `if_group: sudo`     | Shell escape via sudo: `find -exec`, `awk`/`perl` `system()`, `awk BEGIN{}`, `python os.system`/`pty.spawn`, `vim`/`less` `:!sh`, or a direct `sh`/`bash` | T1548.003, T1059.004 |
| `100210` | 10    | `decoded_as: auditd` | Shell escape seen in `execve`, including non-sudo paths (SUID abuse, restricted-shell escape)                                | T1548.001, T1059.004 |

## MITRE ATT&CK coverage

| Technique  | Name                                                          |
| ---------- | ------------------------------------------------------------- |
| T1548.003  | Abuse Elevation Control Mechanism: Sudo and Sudo Caching      |
| T1548.001  | Abuse Elevation Control Mechanism: Setuid and Setgid          |
| T1059.004  | Command and Scripting Interpreter: Unix Shell                 |

## Installation

On the Wazuh manager:

```bash
# 1. Copy the ruleset into the local rules directory
sudo cp rules/gtfobins_rules.xml /var/ossec/etc/rules/gtfobins_rules.xml

# 2. Match owner and permissions to the other files in that directory
#    (wazuh:wazuh on current packages)
sudo chown wazuh:wazuh /var/ossec/etc/rules/gtfobins_rules.xml
sudo chmod 660 /var/ossec/etc/rules/gtfobins_rules.xml

# 3. Validate against a real log line first (see Testing)

# 4. Restart the manager
sudo systemctl restart wazuh-manager
```

## Testing

Do not reload on production without checking a rule against a genuine event first. `wazuh-logtest` runs the full decode and rule pipeline interactively:

```bash
sudo /var/ossec/bin/wazuh-logtest
```

Paste a real sudo or auditd line and confirm three things:

1. the expected SID fires,
2. the field the rule matches on is actually present in the decoded event. auditd `execve` arguments land in `audit.execve.a*`, and the exact structure depends on your decoder,
3. the level and ATT&CK IDs are attached.

The inline comments in each rule note which fields to verify this way.

## Tuning and false positives

Rule `100200` (sudo) is deliberately narrow. Rule `100210` (auditd) casts a wider net and will match legitimate administrative use of `find -exec`, `awk`, and interpreters. Before you enable it in production:

- baseline the normal `execve` activity on the host,
- add exclusions for known-good automation and deployment tooling,
- keep the level low enough that it informs rather than pages, until you understand the noise.

## Contributing

Issues and pull requests are welcome. New rules should keep to the conventions above: an SID `>= 100000`, an ATT&CK mapping, a self-contained group root, and a comment noting how the detection was verified.

## License

Not licensed yet. Until a `LICENSE` file is added, default copyright applies. For shared detection content the common choices are the MIT License or the [Detection Rule License 1.1](https://github.com/SigmaHQ/Detection-Rule-License) that SigmaHQ uses.

## Contact

magsec-IT &ndash; Detection Engineering for modern infrastructure.

- Web: [magsec-it.de](https://magsec-it.de)
- Mail: [info@magsec-IT.de](mailto:info@magsec-IT.de)
