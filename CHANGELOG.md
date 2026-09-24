# Changelog

## 2.1.0

Initial release, protocol-identical to
[IPTranslator.Client 2.1.0](https://github.com/ipappify/ipt-client-dotnet):

- end-to-end encrypted document translation jobs (create → upload → submit →
  poll → fetch, cancel), optional dictionary and translation-memory inputs;
- X-Wing KEM session keys, AES-256-GCM messages and `iptd-doc:v1` blobs,
  hybrid-signed key announcements with the built-in production verification key;
- `ipt-client` command line.
