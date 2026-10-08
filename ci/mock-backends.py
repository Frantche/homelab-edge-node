#!/usr/bin/env python3
import http.server
import socketserver
import threading


class HTTP(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"edge-http-ok\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return


class TCP(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(b"tcp:" + self.request.recv(4096))


http_server = http.server.ThreadingHTTPServer(("127.0.0.1", 18080), HTTP)
tcp_server = socketserver.ThreadingTCPServer(("127.0.0.1", 19001), TCP)
tcp_server.daemon_threads = True

threading.Thread(target=tcp_server.serve_forever, daemon=True).start()
http_server.serve_forever()
