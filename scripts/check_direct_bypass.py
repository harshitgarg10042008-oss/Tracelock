"""Verify that a workload cannot directly reach the protected destination."""

from __future__ import annotations

import socket
import sys

DESTINATION_HOST = "fake-destination"
DESTINATION_PORT = 8000


def main() -> int:
    try:
        socket.create_connection((DESTINATION_HOST, DESTINATION_PORT), timeout=3)
    except (OSError, TimeoutError) as error:
        print(f"DIRECT_BYPASS_DENIED: {type(error).__name__}")
        return 0

    print("DIRECT_BYPASS_FAILED: workload reached fake-destination directly")
    return 1


if __name__ == "__main__":
    sys.exit(main())
