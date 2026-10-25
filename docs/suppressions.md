| ID | Tool | Rule | Location | Decision | Review by | Status |
|---|---|---|---|---|---|---|
| S-001 | Semgrep | `python.flask.security.audit.app-run-param-config.avoid_app_run_with_bad_host` | `app/app.py:58` | False positive (in context) | 2027-04-25 | Active |

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