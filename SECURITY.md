# Security Policy

## Supported Versions

We provide security fixes for the latest minor release. After a new minor is published, the previous minor receives security fixes for 30 days.

| Version | Supported |
|---------|-----------|
| 1.0.x   | ✅        |
| < 1.0   | ❌        |

## Reporting a Vulnerability

1. Do **not** open a public issue for suspected vulnerabilities.
2. Email security@odin.example with:
   - Description of the issue
   - Steps to reproduce / PoC
   - Impact assessment
   - Suggested remediation (if any)
3. You will receive an acknowledgment within 3 business days.
4. We aim to provide a fix or mitigation within 14 days.

## Criteria

We consider the following as security issues:
- Bypass of signature verification
- Incorrect CID / canonicalization leading to tamper-evasion
- Privilege escalation (for future multi-tenant modes)
- RCE, SSRF, path traversal, injection vulnerabilities

We typically do not treat these as security issues (but welcome improvements):
- Denial of service via extremely large request bodies beyond documented limits
- Lack of rate limiting configuration in user deployment

## Coordinated Disclosure

We will credit reporters (unless anonymity requested) in the release notes and CHANGELOG once a fix is available.

## Hardening Guidance
- Pin container image by digest in production.
- Run behind a reverse proxy / WAF that enforces TLS and IP allow-lists if possible.
- Rotate webhook provider secrets regularly; automate via your secrets manager.
- Monitor Prometheus metrics for spikes in 4xx (signature failures) and rate-limit rejections.
