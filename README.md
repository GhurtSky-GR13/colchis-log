# Colchis Execution Log (CEL)

## Verifiable execution history for AI systems

AI without logs is untrustworthy.
CEL makes AI execution provable.

**The black box recorder for AI systems.**
Think Git — but for AI execution.



![Python](https://img.shields.io/badge/python-3.8%2B-blue)




![License](https://img.shields.io/badge/license-Apache%202.0-green)




![Version](https://img.shields.io/badge/version-v0.2-orange)



---

## Why CEL?

Modern AI systems lack verifiable execution history.
Traditional logs are mutable, verbose, and difficult to audit.

CEL records every decision, tool call, and event as an immutable hash-chained frame — making execution fully auditable and traceable.

---

## Features

- Cryptographically verifiable — SHA-256 hash chain
- Tamper-evident audit trail — for regulatory and legal review
- Append-only binary log — compact and fast
- Lightweight — 109-byte frames, minimal overhead
- Compliance-ready — EU AI Act, GDPR, HIPAA
- Zero cloud dependency — works fully offline

---

## Quick Start

pip install flask reportlab
python3 cli.py init mylog.log
python3 cli.py append mylog.log --data "Agent started"
python3 cli.py verify mylog.log

---

## CEL Pro — $99

Includes Execution Proof generator and advanced tools.
Buy: https://ko-fi.com/s/50fccfeecd

---

## Author

Giorgi Ghurtskaia
Email: ghurtsky@gmail.com
