# Laurenz Magerkurth

Information security and detection engineering, with a focus on Blue Team work.

I build and tune detection content for [Wazuh](https://wazuh.com): behavioural rules mapped to MITRE ATT&CK, with an emphasis on Living-off-the-Land techniques (GTFOBins, LOLBAS) and the kind of privilege escalation that signature-based tooling tends to miss. This repository is where I publish that work.

Alongside it I run [magsec-IT](https://magsec-it.de), a small security practice for SMEs covering detection engineering, SIEM, and information security management.

## What I work on

- **Detection engineering** — Wazuh rules, MITRE ATT&CK mapping, Sigma, D3FEND countermeasures.
- **Living-off-the-Land detection** — GTFOBins and LOLBAS, behavioural rather than hash-based.
- **Security monitoring** — Wazuh SIEM, Suricata IDS/IPS, auditd, endpoint telemetry on RHEL / Rocky Linux.
- **Information security management** — ISMS, ISO 27002, NIS2, DORA, CIS Benchmark hardening.

## This repository

Custom, host-based Wazuh detection rules for Linux. The first set covers GTFOBins shell breakouts and local privilege escalation, observed through two independent sources (`sudo` events and auditd `execve`), each rule mapped to ATT&CK. The rule files carry their own group root, so they drop into `/var/ossec/etc/rules/` without touching the stock ruleset. Deployment and testing notes live in the comments of each rule and in [`rules/`](rules/).

Rules follow a small set of conventions: custom SID range `>= 100000`, `pcre2` matching, a `<mitre>` block on every rule, and levels scaled to the confidence of the source.


## Contact

- Web: [magsec-it.de](https://magsec-it.de)
- Mail: [info@magsec-IT.de](mailto:info@magsec-IT.de)
