# SPDX-License-Identifier: AGPL-3.0-or-later
"""``pencheff-sentry`` CLI — boots the HTTP proxy sidecar."""
from __future__ import annotations

import argparse
import sys

from .core import GuardrailConfig
from .proxy import serve


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="pencheff-sentry",
        description="Runtime LLM guardrail proxy.",
    )
    sub = parser.add_subparsers(dest="cmd")

    s = sub.add_parser("serve", help="Run the HTTP proxy sidecar.")
    s.add_argument("--upstream", required=True,
                   help="OpenAI-compatible base URL (e.g. https://api.openai.com/v1).")
    s.add_argument("--host", default="0.0.0.0")
    s.add_argument("--port", type=int, default=4242)
    s.add_argument(
        "--audit-log", default=None,
        help="Path to a JSONL audit log. Records decisions only — never "
             "the prompt/response body.",
    )
    s.add_argument(
        "--max-output-tokens", type=int, default=None,
        help="LLM10 ceiling — block responses whose completion_tokens exceed this.",
    )
    s.add_argument(
        "--allow-pii-in-response", action="store_true",
        help="Don't block PII shapes in model output. Use only when the "
             "model is *expected* to echo PII the user supplied.",
    )

    args = parser.parse_args()
    if args.cmd != "serve":
        parser.print_help()
        return 0

    cfg = GuardrailConfig(
        block_pii_in_response=not args.allow_pii_in_response,
        max_output_tokens=args.max_output_tokens,
    )
    serve(
        upstream=args.upstream,
        host=args.host,
        port=args.port,
        audit_log=args.audit_log,
        config=cfg,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
