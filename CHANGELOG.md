# Changelog

All notable changes to this project are documented here.

## [Unreleased]

### Added
- `.env.example` file documenting environment variables (#31)
- Integration tests for DNS and Vault (opt-in, `--run-integration`) (#23)
- `known_hosts_path` config field for strict SSH host key verification (#24)
- `.dockerignore` to reduce build context (#21)
- Test coverage for `app/main.py` raised to 100% (#20)

### Changed
- Helm chart `appVersion` updated from `latest` to `v0.4.0` (#28)
- Helm chart now generates `targets:` config instead of legacy `f5:` section (#22)
- `scripts/` directory is now copied into the Docker image (#18)

### Removed
- Legacy `F5Config`/`F5HostConfig` models and `f5_handler.py` (#22)
- `StrictHostKeyChecking=no` replaced with opt-in strict verification (#24)

### Fixed
- CodeQL security alerts — sanitized subprocess output logging (#17)
- Replaced `assert` statements with proper error handling (#19)

## [v0.4.0]

### Added
- Percentage-based renewal threshold (`renew_percentage`) (#8)
- Configurable OpenSSL key-generation parameters (`rsa`, `ecdsa`, `ed25519`)
- Prometheus-style health endpoint on `/health`

### Changed
- Migrated F5 handler to generic `DeployTarget` architecture
- Documentation site with MkDocs (English + French)

### Fixed
- F5 wildcard profile matching on subsequent deploys

## [v0.3.0]

### Added
- Ivanti Connect Secure and Exchange SMTP deployment targets
- Full test coverage for `app/targets/` module

## [v0.2.0]

### Added
- ACME_EAB support for GlobalSign Atlas
- Certificate auto-renewal via certbot
- Configurable deployment targets for F5 Big-IP
- Vault integration for certificate storage

## [v0.1.0]

### Added
- Initial release with basic ACME DNS-01 webhook
- Git-based zone file management
- Bearer token authentication
- Docker deployment
