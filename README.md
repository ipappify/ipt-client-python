# iptranslator-client

Python client for the [IP.Translator](https://www.ipappify.de/en/ip-translator) document
translation job API: batch translation of `.docx` documents, **end-to-end
encrypted** — the document is encrypted on your machine and decrypted only on
the GPU worker that translates it; the web service relays it unopened.

- **Post-quantum E2E encryption**: X-Wing KEM (ML-KEM-768 + X25519),
  AES-256-GCM bodies and blobs, hybrid-signed (Ed25519 + ML-DSA-65) key
  announcements. Details in [docs/encryption.md](docs/encryption.md).
- **Document jobs**: create → upload → submit → poll → fetch, with optional
  dictionaries (csv/tsv/xlsx) and translation memories (tmx). Details in
  [docs/document-jobs.md](docs/document-jobs.md).
- Python ≥ 3.10; the only dependency is
  [`cryptography`](https://cryptography.io) (≥ 49, for ML-KEM / ML-DSA).

This repository is intentionally small so the code — especially the
cryptography — is practical to review. See [SECURITY.md](SECURITY.md) for
reporting vulnerabilities. A .NET client with the same protocol lives in
[ipt-client-dotnet](https://github.com/ipappify/ipt-client-dotnet).

## Public beta

This client and the service behind it are in public beta.

- **Service URL**: until general availability, override the service URL with
  `https://iptranslator-prod-app-chhgdncubmguemhx.westeurope-01.azurewebsites.net`
  instead of `https://iptranslator.ipappify.de`.
- **API keys**: request one by email to <support@ipappify.de>.

## Install

```
pip install iptranslator-client
```

## Quick start

You need an API key. For the service's encryption key, the default is
rotation-proof: `connect()` obtains the current X-Wing public key from the
signed announcement in the Ping response and verifies it against the built-in
announcement verification key (`SERVICE_VERIFICATION_KEY`) — the web service
cannot forge the announcement. Pinning your own X-Wing encryption public key
(`service_public_key=`) is optional.

```python
import iptranslator_client as ipt

# public beta: this endpoint replaces https://iptranslator.ipappify.de until GA
client = ipt.connect(
    "https://iptranslator-prod-app-chhgdncubmguemhx.westeurope-01.azurewebsites.net",
    api_key="...")

# submit: the document is encrypted locally before upload
with open("patent.docx", "rb") as f:
    handle = client.submit("patent.docx", f.read(), source_language="de",
                           target_language="en", finalize=True)

# poll: the server holds each call up to 20 s and returns early on changes
status = client.wait(handle, on_progress=lambda s: print(s.state.value, s.progress_done, "/", s.progress_total))
if status.state != ipt.DocumentJobState.done:
    raise SystemExit(f"job ended {status.state.value} ({status.error_code})")

# fetch + decrypt the result, end-to-end verified
result = client.get_result(handle)
with open("patent.en.docx", "wb") as f:
    f.write(result.document)
print("billed units:", result.consumed_units)
```

The pieces behind `connect()` are public, mirroring the .NET client:

```python
from iptranslator_client import (DocumentJobClient, ManagementClient, WebApiRequestHandler,
                                 SignedKeyAnnouncement, SERVICE_VERIFICATION_KEY)

request_handler = WebApiRequestHandler(service_url, api_key)
ping = ManagementClient(request_handler).ping()
service_public_key = SignedKeyAnnouncement.parse(ping.signed_service_public_key) \
    .verify_and_get_public_key(SERVICE_VERIFICATION_KEY)
client = DocumentJobClient(request_handler, service_public_key)
```

`DocumentJobClient` is session-scoped: results can only be fetched through the
instance that submitted the job (the response is bound to the session key and
the blob key lives in the handle).

## Command line

The package installs `ipt-client`, a complete reference implementation
(submit, poll with server-side hold, fetch, cancel on Ctrl-C):

```
ipt-client input.docx output.docx [service.hybrid] --src de --trg en \
    [-f] [-d terms.xlsx] [-m memory.tmx]... [-s <service-url>] [-k <api-key>]
```

The key file is optional: when omitted, the built-in production announcement
verification key is used. Supply one to override it — either the pinned
X-Wing public key (`*.xwing`) or a different announcement verification key
(`*.hybrid`), raw or base64. The API key can also be supplied via the
`IPT_API_KEY` environment variable. Exit codes: 0 success, 1 error, 2 usage,
3 job did not complete. Run `ipt-client --help` for full usage.

## Development

```
pip install -e .[dev]
pytest
python -m build
```

The tests include cross-language vectors shared with the service and the .NET
client (message AAD formats, `iptd-doc:v1` blobs, announcement signatures),
pinned dev keys, tamper-detection cases, and a fake service that plays the
whole protocol including the worker's decapsulation.

## Repository layout

```
src/iptranslator_client/   the package (client, E2E crypto, wire contracts, CLI)
examples/                  usage example
tests/                     crypto + protocol tests
docs/                      encryption and document-job protocol docs
```

This repository is a curated extract of the IP.Translator codebase: it contains
exactly the client pieces needed for the document job API (plus Ping for key
announcements). The full product (Word add-in, interactive translation, GenAI
review) lives in a private repository which is authoritative; changes here are
synced from it.

## License

[MIT](LICENSE)
