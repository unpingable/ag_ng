#!/usr/bin/env python3
"""Serve one explicitly synthetic operator-beta display case on loopback."""

import argparse
import signal
import threading

from browser_fixture import Fixture, demo


CASES = ("launch", "active", "no-process", "uncertain", "refused", "failed", "success", "outage")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case", choices=CASES)
    parser.add_argument("--port", type=int, default=8767)
    parser.add_argument("--max-seconds", type=int, default=7200)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be in 1..65535")
    if not 1 <= args.max_seconds <= 7200:
        parser.error("max-seconds must be in 1..7200")

    server = demo.DemoServer(("127.0.0.1", args.port), Fixture(args.case))
    timer = threading.Timer(args.max_seconds, server.shutdown)
    timer.daemon = True
    timer.start()
    signal.signal(signal.SIGTERM, lambda _signum, _frame: server.shutdown())
    print(
        f"DISPLAY_FIXTURE case={args.case} url={server.origin}/ "
        f"max_seconds={args.max_seconds}",
        flush=True,
    )
    try:
        server.serve_forever()
    finally:
        timer.cancel()
        server.server_close()


if __name__ == "__main__":
    main()
