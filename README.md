# DevSecOps + CTEM Lab

> ⚠️ **Deliberately vulnerable.** The app, the Dockerfile and the Terraform in this repo contain security flaws on purpose, so the scanners have something to find. Never deploy the app anywhere public, and destroy the cloud resources after each lab session.

A home lab that practises shift-left security and continuous exposure management:

| Area | What runs | Where |
|---|---|---|
| SAST | Semgrep (Python + Flask rules) | `.github/workflows/devsecops.yml` |
| Secrets | Gitleaks (whole git history) | workflow |
| SCA + SBOM | Trivy filesystem scan, CycloneDX SBOM | workflow |
| Container | Trivy image scan | workflow |
| IaC | Checkov on Terraform | workflow |
| DAST | OWASP ZAP baseline against the running container | workflow |
| Metrics | SARIF summary per build (tool, severity, top rules, CWE) | `metrics/sarif_summary.py` |
| CTEM prioritisation | CVSS + EPSS + CISA KEV + exposure + asset criticality | `ctem/prioritise.py` |
| Cloud remediation | Public S3 bucket playbook with dry-run | `playbooks/remediate_public_s3.py` |

**Gates:** merges to `main` are blocked on Semgrep ERROR findings, any detected secret, fixable CRITICAL/HIGH CVEs in dependencies or the image, and failed Checkov checks. ZAP reports only (DAST runs against a live app and is too slow and noisy to gate pull requests).

## Results
_Add screenshots and the numbers from each phase here: findings before vs after fixes, false positives tuned, playbook evidence._
