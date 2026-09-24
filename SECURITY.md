# Security Policy

This library implements the client side of IP.Translator's end-to-end
encryption (see [docs/encryption.md](docs/encryption.md)). We explicitly
welcome review of the cryptographic code — that is one of the reasons this
repository is public.

## Reporting a vulnerability

Please do **not** open a public issue for security-relevant findings.
Instead, use GitHub's private vulnerability reporting on this repository
(*Security → Report a vulnerability*). We will respond as quickly as we can
and credit reporters in the fix release unless they prefer otherwise.

## Scope

- `iptranslator-client` (the PyPI package): message encryption
  (X-Wing KEM + AES-256-GCM), document blob encryption (`iptd-doc:v1`),
  signed key announcement verification (Ed25519 + ML-DSA-65), and the
  document job protocol built on them.
- The `ipt-client` command line is a reference implementation; findings
  there are welcome too.

Server-side issues (the IP.Translator service itself) can also be reported
through the same channel.
