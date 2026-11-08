# Security Policy

## Supported versions

Only the latest commit on `main` receives security fixes.

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

Use GitHub's private vulnerability reporting: open the **Security** tab of this repository and choose **Report a vulnerability**. Include the affected component, steps to reproduce and the impact you observed.

You can expect an acknowledgement within a few days. Please give the maintainer reasonable time to ship a fix before disclosing details publicly.

## Scope notes

- Never include real credentials, RADIUS secrets, SNMP communities or production data in a report.
- Deployment hardening guidance (firewall, TLS, SELinux, systemd) is described in [docs/KURULUM.md](docs/KURULUM.md) (Turkish), and the implemented controls are listed in [docs/GUVENLIK_TARAMA.md](docs/GUVENLIK_TARAMA.md).
