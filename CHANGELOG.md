# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and this project adheres to Semantic Versioning.

## [1.0.0] - 2025-08-26
### Added
- Initial stable release: Generic/GitHub/Stripe/Twilio verification, ODIN envelope forwarding.
- Canonical JSON + CID hashing, Ed25519 signing utilities.
- Optional JSONL + Firestore persistence.
- Structured JSON logging toggle.
- In-memory sliding window rate limiting with LRU eviction.
- Prometheus metrics endpoint (optional).
- Comprehensive test suite (>=95% coverage).
- Docker multi-stage build, CI pipeline (tests, lint, security scans).
- CodeQL, Dependabot configuration.
- Makefile developer workflow helpers.
- README with quick start, env var documentation.

### Security
- Hardened Stripe signature verification (timestamp tolerance + multi-sig support).

### Removed / Breaking
- N/A (first stable tag).

## [Unreleased]

## [1.2.1] - 2025-08-26

## [1.2.0] - 2025-08-26

## [1.1.1] - 2025-08-26

## [1.1.0] - 2025-08-26
### Added
- Terraform ECS Fargate deployment module (`deploy/terraform`).
- Observability assets: Prometheus alert rules & Grafana dashboard.
- Automated semantic versioning workflow (auto-version) with conventional commits parsing.
- Commit message linting (Commitizen pre-commit + PR workflow).
- Version bump script enhanced to sync Helm chart (`scripts/bump_version.py`).

### Security / Supply Chain
- Container signing (cosign keyless) plus SBOM & provenance attestations.
- Trivy vulnerability gate (fail on HIGH/CRITICAL) in release pipeline.

### CI/CD
- Multi-tag container publishing (major, minor, latest).
- Automated release notes extraction from CHANGELOG.

### Documentation
- CONTRIBUTING guide, supply-chain security documentation additions.

### Internal
- Rate limiter & metrics previously added now documented; groundwork for future enhancements.

