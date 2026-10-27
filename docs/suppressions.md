| ID | Tool | Rule | Location | Decision | Review by | Status |
|---|---|---|---|---|---|---|
| S-001 | Semgrep | `python.flask.security.audit.app-run-param-config.avoid_app_run_with_bad_host` | `app/app.py:58` | False positive (in context) | 2027-04-25 | Active |
| S-002 | trivy (fs+img)| CVE-2024-34069: Werkzeug debugger | app/requirements.txt:3 | Accepted risk(true positive)| 2026-11-08| Demo; PR #26 closed unmerged | 

## S-001: Flask binds to 0.0.0.0
- **Finding:** `app.run(host="0.0.0.0")` listens on all interfaces. Severity WARNING (doesn't fail the gate).
- **Why it's a false positive here:** the app only runs inside a container, where 0.0.0.0 means every interface of the container's own private network, not the host's. With 127.0.0.1, Docker's port forwarding can't reach the app, so the DAST job and load balancer health checks fail.
- **What controls exposure:** the port mapping (`docker run -p`), and in production the security group/NSG and the load balancer or ingress in front of the container. The bind address isn't the control.
- **Compensating control:** in production the app is reachable only through the load balancer, with no direct public port. Checkov checks the security groups in every PR.
- **Void if:** the app runs directly on a host or VM, outside a container.
- **Risk owner:** application owner (lab: Shanmuga, as app owner)
- **Approved by:** AppSec engineer (lab: Shanmuga; on a real team, someone other than the owner)
- **Date:** 2026-10-25
- **Review by:** 2027-04-25, or sooner if the deployment model changes
- **Ticket:** SEC-100 (lab) 

## S-002: CVE-2024-34069 in werkzeug 3.0.2
- **Finding:** HIGH: remote code execution through the Werkzeug debugger. werkzeug 3.0.2 is pinned with Flask 3.0.3; it failed the SCA and Container gates.
- **Why it's an accepted risk:** true positive: werkzeug 3.0.2 is in the image. The vulnerable code is the interactive debugger, which only runs in debug mode. Debug mode is off in every environment, so the vulnerable code is not reachable.
- **Why we can't fix it now:** The Flask 3.1 upgrade breaks the app and needs 2 weeks
- **Compensating control:** `debug=False` is set explicitly in `app.run` (it overrides `FLASK_DEBUG`), and the custom Semgrep rule `rules/flask-debug.yml` (severity ERROR) blocks any PR that sets `debug=True`.
- **Control gap (found and fixed 2026-10-27):** the original approval relied on Semgrep's registry rule `debug-enabled`, which is WARNING, so the ERROR-only gate let `debug=True` through. Evidence: old gate + `debug=True` → exit 0 (gap); new rule + `debug=True` → exit 1 (blocked); new rule + `debug=False` → exit 0 (no false positive).
- **Void if:** Debug mode enabled anywhere (debug=True, FLASK_DEBUG=1, flask run --debug), or a new Werkzeug CVE that's reachable
- **Risk owner:** application owner (lab: Shanmuga, as app owner)
- **Approved by:** CISO, because it's a HIGH CVE of the RCE class on a production path, above AppSec's approval limit
- **Date:** 2026-10-25
- **Review by:** Expires: 2026-11-08 (enforced by exp: in .trivyignore)
- **Ticket:** SEC-101
- **Fix plan:** SEC-101: upgrade to Flask 3.1 + Werkzeug 3.1 and remove the .trivyignore line before 2026-11-08.

## Register policy
1. **Entry first:** every suppression or exception is recorded here before it is merged: ID, finding, decision (false positive / accepted risk), reason, compensating control, void-if, risk owner, approver, date, review or expiry date, ticket.
2. **Approval by severity:** false positives and LOW/MEDIUM risks → AppSec engineer; HIGH or CRITICAL → CISO. Owners never approve their own exceptions.
3. **Maximum duration:** accepted HIGH/CRITICAL risks ≤ 30 days, MEDIUM ≤ 90 days; false positives are re-reviewed every 6 months.
4. **Expiry is enforced, not remembered:** Trivy entries carry `exp:YYYY-MM-DD`, so the gate fails again on that date. Semgrep `nosemgrep` and the Checkov baseline have no expiry, so they are re-checked in a monthly register review.
5. **Controls are tested:** each compensating control needs evidence that it blocks (gap / red / green runs) before approval. An untested control is not accepted.
6. **Ignore files are owned:** changes to `.trivyignore`, the Checkov baseline, `rules/` and this file need a code owner's review (`.github/CODEOWNERS`).
7. **Closing:** when the fix merges, remove the suppression line, confirm the gate is green without it, and set Status to Closed. The row stays for audit.