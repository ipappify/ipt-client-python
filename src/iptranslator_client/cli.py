"""``ipt-client`` — submits a .docx document translation job via the end-to-end
encrypted :class:`DocumentJobClient`, waits for completion, and writes the
translated document to the output path. Reference implementation, parallel to
``ipt-client-cmd`` in the .NET client.

Exit codes: 0 success, 1 unexpected error, 2 usage error, 3 job did not
complete (failed or canceled).
"""

from __future__ import annotations

import argparse
import base64
import os
import signal
import sys
import threading
from typing import Optional, Sequence

from . import announcement, xwing
from ._version import __version__
from .contracts import DocumentJobLimits, DocumentJobState
from .defaults import SERVICE_URL, SERVICE_VERIFICATION_KEY
from .document_job_client import DocumentJobClient
from .management_client import ManagementClient
from .request_handler import WebApiRequestHandler

API_KEY_ENV_VAR = "IPT_API_KEY"


class UsageError(Exception):
    pass


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ipt-client",
        description="Translate a .docx document with IP.Translator (end-to-end encrypted batch job).",
        epilog=f"""key-file (optional; raw binary or base64 text, chosen by extension —
when omitted, the built-in production verification key is used):
  *.xwing   the service's X-Wing public key ({xwing.PUBLIC_KEY_SIZE} bytes)
  *.hybrid  the Ed25519+ML-DSA-65 verification key ({announcement.VERIFICATION_KEY_SIZE} bytes);
            the service key is then obtained from the Ping response's
            signed announcement, verified against this key

The API key falls back to the {API_KEY_ENV_VAR} environment variable.""",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("input", help="input .docx")
    p.add_argument("output", help="output .docx")
    p.add_argument("key_file", nargs="?", help="*.xwing or *.hybrid key file (optional)")
    p.add_argument("--src", required=True, help="source language (2-letter iso)")
    p.add_argument("--trg", required=True, help="target language (2-letter iso)")
    p.add_argument("-f", "--finalize", action="store_true", help="ask the worker to finalize the document")
    p.add_argument("-d", "--dictionary", help="dictionary (.csv, .tsv or .xlsx), applied per segment")
    p.add_argument("-m", "--tm", "--translation-memory", dest="tm", action="append", default=[],
                   help=f"translation memory (.tmx); repeat for multiple (max {DocumentJobLimits.MAX_TRANSLATION_MEMORIES})")
    p.add_argument("-s", "--service-url", default=SERVICE_URL, help=f"service base url (default: {SERVICE_URL})")
    p.add_argument("-k", "--api-key", help=f"api key (default: ${API_KEY_ENV_VAR})")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def _decode_key(file_bytes: bytes, key_size: int, key_file: str) -> str:
    """Accept the raw key (exact size) or a base64 text file; return the base64."""
    if len(file_bytes) == key_size:
        return base64.b64encode(file_bytes).decode("ascii")
    if file_bytes.startswith(b"\xef\xbb\xbf"):  # skip a UTF-8 BOM
        file_bytes = file_bytes[3:]
    text = file_bytes.decode("ascii", "replace").strip()
    try:
        if len(base64.b64decode(text, validate=True)) == key_size:
            return text
    except ValueError:
        pass
    raise UsageError(f"'{key_file}' is neither a raw {key_size}-byte key nor its base64 encoding.")


def _resolve_service_public_key(key_file: Optional[str], request_handler: WebApiRequestHandler) -> str:
    """An .xwing file holds the service key directly; a .hybrid file holds the
    verification key for the signed announcement delivered in the Ping response.
    Without a key file, the built-in production verification key drives the
    signed announcement flow."""
    management = ManagementClient(request_handler)
    if key_file is None:
        print("no key file given; using built-in service verification key.")
        key = management.resolve_service_public_key(SERVICE_VERIFICATION_KEY)
        print("service public key obtained from verified signed announcement.")
        return key
    with open(key_file, "rb") as f:
        data = f.read()
    ext = os.path.splitext(key_file)[1].lower()
    if ext == ".xwing":
        return _decode_key(data, xwing.PUBLIC_KEY_SIZE, key_file)
    if ext == ".hybrid":
        verification_key = _decode_key(data, announcement.VERIFICATION_KEY_SIZE, key_file)
        key = management.resolve_service_public_key(verification_key)
        print("service public key obtained from verified signed announcement.")
        return key
    raise UsageError(f"unsupported key file extension '{ext}' (expected .xwing or .hybrid).")


def _validate(args) -> None:
    if not os.path.isfile(args.input):
        raise UsageError(f"input file '{args.input}' does not exist.")
    if args.key_file is not None and not os.path.isfile(args.key_file):
        raise UsageError(f"key file '{args.key_file}' does not exist.")
    if args.dictionary is not None:
        if not os.path.isfile(args.dictionary):
            raise UsageError(f"dictionary file '{args.dictionary}' does not exist.")
        fmt = os.path.splitext(args.dictionary)[1].lstrip(".").lower()
        if fmt not in DocumentJobLimits.DICTIONARY_FORMATS:
            raise UsageError(f"dictionary file '{args.dictionary}' must be ."
                             + ", .".join(DocumentJobLimits.DICTIONARY_FORMATS) + ".")
    if len(args.tm) > DocumentJobLimits.MAX_TRANSLATION_MEMORIES:
        raise UsageError(f"at most {DocumentJobLimits.MAX_TRANSLATION_MEMORIES} translation memories are supported.")
    for tm in args.tm:
        if not os.path.isfile(tm):
            raise UsageError(f"translation memory '{tm}' does not exist.")
        if os.path.splitext(tm)[1].lower() != ".tmx":
            raise UsageError(f"translation memory '{tm}' must be a .tmx file.")


def _read(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def run(args, cancel_event: threading.Event) -> int:
    api_key = args.api_key or os.environ.get(API_KEY_ENV_VAR) or None
    request_handler = WebApiRequestHandler(args.service_url, api_key)
    service_public_key = _resolve_service_public_key(args.key_file, request_handler)
    client = DocumentJobClient(request_handler, service_public_key)

    document_bytes = _read(args.input)
    document_name = os.path.basename(args.input)
    dictionary = _read(args.dictionary) if args.dictionary else None
    dictionary_format = os.path.splitext(args.dictionary)[1].lstrip(".").lower() if args.dictionary else None
    translation_memories = [_read(tm) for tm in args.tm]

    print(f"submitting {document_name} ({len(document_bytes):,} bytes), {args.src} -> {args.trg}, "
          f"finalize: {args.finalize}"
          + (f", dictionary: {os.path.basename(args.dictionary)}" if dictionary is not None else "")
          + (f", translation memories: {len(translation_memories)}" if translation_memories else "")
          + " ...")
    handle = client.submit(document_name, document_bytes, args.src, args.trg, args.finalize,
                           dictionary=dictionary, dictionary_format=dictionary_format,
                           translation_memories=translation_memories or None)
    print(f"job {handle.job_id_wire} submitted.")

    def on_progress(status):
        state = status.state.value if status.state else "?"
        print(f"state: {state}, progress: {status.progress_done}/{status.progress_total}")

    cancel_requested = False

    def should_cancel() -> bool:
        nonlocal cancel_requested
        if cancel_event.is_set() and not cancel_requested:
            cancel_requested = True
            print("canceling job ...", file=sys.stderr)
            return True
        return False

    # the server holds the call up to 20 s and returns early on any
    # state/progress change, so this loop is not a tight poll
    status = client.wait(handle, wait_seconds=20, on_progress=on_progress, should_cancel=should_cancel)
    if status.state != DocumentJobState.done:
        state = status.state.value if status.state else "?"
        print(f"job ended {state}" + (f" ({status.error_code})." if status.error_code else "."), file=sys.stderr)
        return 3

    result = client.get_result(handle)
    with open(args.output, "wb") as f:
        f.write(result.document)
    print(f"result written to {args.output} ({len(result.document):,} bytes).")
    if result.summary is not None:
        s = result.summary
        print(f"summary: {s.translated}/{s.total} translated, {s.failed} failed.")
    print(f"consumed units: {result.consumed_units}.")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
        _validate(args)
    except UsageError as e:
        print(e, file=sys.stderr)
        print(file=sys.stderr)
        parser.print_usage(sys.stderr)
        return 2
    except SystemExit as e:  # argparse's own usage errors (2) / --help, --version (0)
        return e.code if isinstance(e.code, int) else 2

    cancel_event = threading.Event()
    previous = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, lambda *_: cancel_event.set())
    try:
        return run(args, cancel_event)
    except UsageError as e:
        print(e, file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("canceled.", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    finally:
        signal.signal(signal.SIGINT, previous)


if __name__ == "__main__":
    sys.exit(main())
