#!/usr/bin/env python3
import argparse
import gzip
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class Handler(BaseHTTPRequestHandler):
    state_dir: Path

    def do_GET(self):
        if self.path == "/healthz":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok\n")
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("content-length", "0")))
        if self.headers.get("content-encoding", "").lower() == "gzip":
            body = gzip.decompress(body)
        destination = "logs.received" if "logs" in self.path else "metrics.received"
        with (self.state_dir / destination).open("ab") as stream:
            stream.write(b"\n--- " + self.path.encode() + b" ---\n")
            stream.write(body)
            stream.write(b"\n")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok\n")

    def log_message(self, fmt, *args):
        return


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-dir", required=True)
    parser.add_argument("--port", type=int, default=43190)
    args = parser.parse_args()
    Handler.state_dir = Path(args.state_dir)
    Handler.state_dir.mkdir(parents=True, exist_ok=True)
    ThreadingHTTPServer(("0.0.0.0", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
