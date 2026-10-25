# Suppression and exception register

| ID | Tool | Rule | Location | Decision | Review by | Status |
|---|---|---|---|---|---|---|
| S-001 | Semgrep | `python.flask.security.audit.app-run-param-config.avoid_app_run_with_bad_host` | `app/app.py:58` | False positive (in context) | 2027-04-25 | Active |
| S-002 | trivy (fs+img)| CVE-2024-34069: Werkzeug debugger | app/requirements.txt:3 | Accepted risk(truepositive)| 2026-11-08| Active |

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
- **Ticket:** SEC-100 

## S-002: CVE-2024-34069 in werkzeug 3.0.2
- **Finding:** HIGH: remote code execution through the Werkzeug debugger. werkzeug 3.0.2 is pinned with Flask 3.0.3; it failed the SCA and Container gates.
- **Why it's an accepted risk:** true positive: werkzeug 3.0.2 is in the image. The vulnerable code is the interactive debugger, which only runs in debug mode. Debug mode is off in every environment, so the vulnerable code is not reachable.
- **Why we can't fix it now:** The Flask 3.1 upgrade breaks the app and needs 2 weeks
- **Compensating control:** `debug=False` is set explicitly in `app.run` (it overrides `FLASK_DEBUG`), and the Semgrep ERROR gate blocks any PR that sets `debug=True`.
- **Void if:** Debug mode enabled anywhere (debug=True, FLASK_DEBUG=1, flask run --debug), or a new Werkzeug CVE that's reachable
- **Risk owner:** application owner (lab: Shanmuga, as app owner)
- **Approved by:** CISO, because it's a HIGH CVE of the RCE class on a production path, above AppSec's approval limit
- **Date:** 2026-10-25
- **Review by:** Expires: 2026-11-08 (enforced by exp: in .trivyignore)
- **Ticket:** SEC-101
- **Fix plan:** SEC-101: upgrade to Flask 3.1 + Werkzeug 3.1 and remove the .trivyignore line before 2026-11-08.