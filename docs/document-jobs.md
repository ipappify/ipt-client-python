# Document Translation Jobs

Batch whole-document translation of `.docx` files, end-to-end encrypted.
Client entry point: [`DocumentJobClient`](../src/iptranslator_client/document_job_client.py);
wire contracts: [`contracts.py`](../src/iptranslator_client/contracts.py).

## Flow

```
create ──▶ upload ──▶ submit ──▶ poll ──▶ fetch
```

1. **Create** (`CreateDocumentJob`) — the server issues a job id and per-job
   SAS URLs: a client-facing upload URL for the input document (plus optional
   dictionary / translation-memory slots when requested) and the worker-facing
   URLs the client will embed in the encrypted job message.
2. **Upload** — the client encrypts the document with a fresh per-job blob key
   (`iptd-doc:v1`, slot `in`) and PUTs it straight to blob storage. Optional
   inputs are sealed under the same key in their own slots (`dict`, `tm0`…).
3. **Submit** (`SubmitDocumentJob`) — the client builds the end-to-end
   encrypted `translate_document` request whose body carries the blob key and
   the worker-facing URLs, and submits it. The web app relays the message
   unopened; `request_id` equals the job id so completion can be correlated
   without opening it. `document_name` / `document_custom_ref` are informational
   (they appear in the usage report).
4. **Poll** (`GetDocumentJob`) — returns state (`queued`, `running`, `done`,
   `failed`, `cancelled`) and segment progress. `wait_seconds` (0–25) asks the
   server to hold the call until something changes, so a polling loop stays
   responsive without tight polling or connection-lifetime risk.
   `DocumentJobClient.wait()` wraps this loop.
5. **Fetch** (`DocumentJobClient.get_result`) — downloads the encrypted result
   (slot `out`), decrypts it with the job's blob key, decrypts the worker's
   job summary from the response envelope, and verifies the job-id echo. The
   response's GCM AAD binds `consumed_units` and `object_id`, so the billed
   units are verified end-to-end.

`cancel()` requests cancellation; the worker honors it between segments. Jobs
that fail per segment still complete — the summary reports `translated` /
`failed` counts.

## Optional inputs

- **Dictionary** — one `csv`, `tsv`, or `xlsx` file. The worker imports it
  into the document and applies matching terms per segment.
- **Translation memories** — up to 16 `tmx` files. Exact source matches are
  applied directly and are **not billed**; the rest is used as translation
  context.

Both ride their own encrypted blobs under the job key; the server never sees
their content.

## Finalize

`finalize=True` asks the worker to produce a finished document (unwrap the
segment controls and drop the IP.Translator binding). With `finalize=False`
the output keeps the binding, so it can be post-edited with the IP.Translator
Word add-in.

## Billing verification

Billing is by translated segment. The completion envelope carries
`consumed_units` and an `object_id`, both bound into the response's GCM AAD
(tamper-evident end-to-end). The worker additionally uploads a content-free
per-segment usage blob: items in document order with
`sum(units) == consumed_units` and `SHA-256` over the concatenated per-segment
`object_id`s equal to the envelope `object_id` — so per-segment billing is
verifiable against the envelope. Segments already translated for the same
document (or applied from an exact TM match) are deduplicated and not billed
again.

## Errors

- `ServiceError` (with `code`, a `ResponseCode`) for non-OK envelope codes;
  `QuotaExceededError` (with `upgrade_uri`) and `ServiceCanceledError` are
  subclasses.
- `JobNotDoneError` when `get_result()` is called on a job that is not `done`
  (the `status` attribute carries the last status incl. `error_code`).
- `EncryptionError` when anything fails to authenticate or verify: a tampered
  envelope, a result fetched through a different session, a bad announcement.
- `TransportError` for HTTP-level failures (`status`, `url`).

## Example

See [`examples/translate_document.py`](../examples/translate_document.py) and
the [`ipt-client`](../src/iptranslator_client/cli.py) command line for
complete reference implementations (submit, poll with server-side hold, fetch,
cancel on Ctrl-C), and the [README](../README.md) for a minimal snippet.
