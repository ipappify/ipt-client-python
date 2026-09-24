"""Minimal end-to-end example: translate one .docx document.

    IPT_API_KEY=... python examples/translate_document.py patent.docx patent.en.docx de en
"""

import os
import sys

import iptranslator_client as ipt

# public beta: this endpoint replaces https://iptranslator.ipappify.de until GA
SERVICE_URL = "https://iptranslator-prod-app-chhgdncubmguemhx.westeurope-01.azurewebsites.net"


def main(input_path: str, output_path: str, src: str, trg: str) -> int:
    # resolves the service's encryption key from the verified signed announcement
    client = ipt.connect(SERVICE_URL, api_key=os.environ["IPT_API_KEY"])

    with open(input_path, "rb") as f:
        handle = client.submit(os.path.basename(input_path), f.read(), src, trg, finalize=True)
    print(f"job {handle.job_id_wire} submitted")

    def on_progress(status: ipt.GetDocumentJobResponse) -> None:
        print(f"{status.state.value}: {status.progress_done}/{status.progress_total}")

    status = client.wait(handle, wait_seconds=20, on_progress=on_progress)
    if status.state != ipt.DocumentJobState.done:
        print(f"job ended {status.state.value} ({status.error_code})", file=sys.stderr)
        return 3

    result = client.get_result(handle)
    with open(output_path, "wb") as f:
        f.write(result.document)
    summary = result.summary
    print(f"written {output_path}: {summary.translated}/{summary.total} segments translated, "
          f"{summary.failed} failed, {result.consumed_units} units billed")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 5:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(*sys.argv[1:]))
