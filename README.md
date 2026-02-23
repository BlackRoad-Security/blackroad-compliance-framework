# blackroad-compliance-framework

Automated compliance scanning engine supporting CIS, OWASP Top-10, NIST CSF, SOC 2, and PCI-DSS controls.

## Supported Frameworks

| Framework | Controls | Description |
|-----------|----------|-------------|
| CIS | 7 | CIS Controls v8 |
| OWASP | 8 | OWASP Top-10 2021 |
| NIST | 5 | NIST Cybersecurity Framework |
| SOC2 | 4 | SOC 2 Type II Trust Services |
| PCI | 4 | PCI-DSS v4.0 |

## Automated Checks

- **CIS-6.1** – Scan for hardcoded secrets in source code
- **CIS-4.1** – Verify logging module usage  
- **CIS-3.1** – Verify encryption usage
- **CIS-1.1** – Check for dependency inventory (requirements.txt)
- **OWASP-A02** – Cryptographic failures detection
- **OWASP-A09** – Security logging verification
- **OWASP-A06** – Vulnerable component check

## Usage

```bash
# Scan all frameworks
python src/compliance_framework.py scan /path/to/project

# Scan specific framework
python src/compliance_framework.py scan . --framework OWASP

# JSON output
python src/compliance_framework.py scan . --format json --output report.json

# List past scans
python src/compliance_framework.py list-runs

# Add exception for a control
python src/compliance_framework.py add-exception CIS-7.1 "Legacy system, remediation Q2" --approved-by "ciso"

# List all controls
python src/compliance_framework.py list-controls --framework CIS
```

## Score Interpretation

| Score | Meaning |
|-------|---------|
| 90-100% | Excellent compliance |
| 70-89% | Good with some gaps |
| 50-69% | Moderate risk, action needed |
| < 50% | Poor – immediate remediation required |

## Tests

```bash
pytest tests/ -v --cov=src
```

## License

Proprietary – BlackRoad OS, Inc. All rights reserved.