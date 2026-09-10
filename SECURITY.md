# Security

This project is an early preview. Use the latest reviewed revision and build with
the Go version required by `go.mod` or a newer supported patch release. Automated
tests do not establish successful IBKR login or recovery for a real account.

## Reporting a vulnerability

Use the repository's [private vulnerability reporting](https://github.com/nite0x/ibkr-gateway-manager/security/advisories/new)
when available. Do not post credentials, account details, cookies, private keys, or
deployment configuration in a public issue. If private reporting is unavailable,
open an issue requesting a private contact without including vulnerability details.

Include the affected revision, a minimal reproduction using synthetic data, the
expected result, and the observed result. Never include a live IBKR session.

## Deployment

- Bind HTTP to loopback; use local TLS or an HTTPS reverse proxy for browser login.
- Use a unique management password and a separate Proxy Token per instance.
- Back up and restrict access to the data volume: it contains tokens and private keys.
- Give API clients only the token for the instance they need.
- Rotate exposed tokens and passwords. Deleting a file does not remove Git history.

IBKR authentication and two-factor authentication are completed manually. Session
keepalive does not eliminate IBKR's reauthentication requirements.
