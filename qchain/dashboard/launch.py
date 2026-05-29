"""Launch three dashboard nodes locally for a multi-node demo.

This script forks three subprocesses, each running its own dashboard
on a different HTTP port. After it's running, open three browser tabs:
    http://127.0.0.1:8101    (Node A)
    http://127.0.0.1:8102    (Node B)
    http://127.0.0.1:8103    (Node C)

You'll see them connect to each other and gossip events in real time.

Run with: python -m qchain.dashboard.launch
"""

import signal
import subprocess
import sys
import time

NODES = [
    {"id": "A", "p2p": 19101, "http": 8101, "peers": []},
    {"id": "B", "p2p": 19102, "http": 8102, "peers": ["127.0.0.1:19101"]},
    {"id": "C", "p2p": 19103, "http": 8103, "peers": ["127.0.0.1:19101", "127.0.0.1:19102"]},
]


def main():
    procs = []
    print("Launching dashboard nodes...")
    for cfg in NODES:
        args = [
            sys.executable, "-m", "qchain.dashboard.server",
            "--node-id", cfg["id"],
            "--port", str(cfg["p2p"]),
            "--http", str(cfg["http"]),
        ]
        for peer in cfg["peers"]:
            args += ["--peer", peer]
        p = subprocess.Popen(args)
        procs.append(p)
        print(f"  Node {cfg['id']}: P2P :{cfg['p2p']}, HTTP :{cfg['http']}  (pid {p.pid})")
        time.sleep(0.5)  # stagger startups

    print()
    print("=" * 60)
    print("Open these in three browser tabs:")
    for cfg in NODES:
        print(f"  http://127.0.0.1:{cfg['http']}/")
    print("=" * 60)
    print()
    print("Press Ctrl+C to stop all nodes.")

    def shutdown(*_):
        print("\nShutting down...")
        for p in procs:
            p.terminate()
        for p in procs:
            try:
                p.wait(timeout=3)
            except subprocess.TimeoutExpired:
                p.kill()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # Block forever; signal handler will tear things down
    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()
