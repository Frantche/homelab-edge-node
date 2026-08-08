#!/usr/bin/env python3
import http.server
import socket
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


def udp():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 19002))
    while True:
        payload, peer = sock.recvfrom(65535)
        sock.sendto(b"udp:" + payload, peer)


threading.Thread(target=http.server.ThreadingHTTPServer(("127.0.0.1", 18080), HTTP).serve_forever, daemon=True).start()
threading.Thread(target=socketserver.ThreadingTCPServer(("127.0.0.1", 19001), TCP).serve_forever, daemon=True).start()
udp()

