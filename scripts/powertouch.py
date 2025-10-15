#!/usr/bin/env uv
# uv requirements:
# - zeroconf
#
# To run: uv run powertouch.py
#
#  Copyright (C) 2025 Yubico.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import http.server
import socketserver
import threading
import urllib.request
import time
import socket
try:
    from zeroconf import ServiceInfo, Zeroconf
except ImportError:
    raise ImportError("zeroconf package is required. If using uv, add 'zeroconf' to requirements.")

BASE_URL = "http://192.168.7.1"
USB_PORT = 6  # Change as needed


def get_endpoint(path):
    return f"{BASE_URL}/usb{USB_PORT}/{path}"


def send_request(url):
    try:
        with urllib.request.urlopen(url, timeout=2) as resp:
            pass
    except Exception as e:
        print(f"Error requesting {url}: {e}")


class PowerTouchHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/powerOn":
            threading.Thread(target=send_request, args=(get_endpoint("power/on"),)).start()
            self.respond_ok()
        elif self.path == "/powerOff":
            threading.Thread(target=send_request, args=(get_endpoint("power/off"),)).start()
            self.respond_ok()
        elif self.path == "/shortTouch":
            threading.Thread(target=self.short_touch).start()
            self.respond_ok()
        elif self.path == "/longTouch":
            threading.Thread(target=self.long_touch).start()
            self.respond_ok()
        else:
            self.send_error(404, "Not Found")

    def do_POST(self):
        self.do_GET()  # Accept POST for all endpoints

    def short_touch(self):
        send_request(get_endpoint("touch/on"))
        time.sleep(0.3)  # 300 ms
        send_request(get_endpoint("touch/off"))

    def long_touch(self):
        send_request(get_endpoint("touch/on"))
        time.sleep(3)
        send_request(get_endpoint("touch/off"))

    def respond_ok(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status": "OK"}')


# Add Zeroconf service advertisement

def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip


class ZeroconfAdvertiser:
    def __init__(self, port):
        self.zeroconf = Zeroconf()
        self.port = port
        self.info = None

    def start(self):
        ip = get_ip()
        desc = {'path': '/'}
        self.info = ServiceInfo(
            "_powertouch._tcp.local.",
            "PowerTouchServer._powertouch._tcp.local.",
            addresses=[socket.inet_aton(ip)],
            port=self.port,
            properties=desc,
            server="powertouch.local."
        )
        self.zeroconf.register_service(self.info)
        print(f"Advertised mDNS service at {ip}:{self.port}")

    def stop(self):
        if self.info:
            self.zeroconf.unregister_service(self.info)
        self.zeroconf.close()


if __name__ == "__main__":
    PORT = 8080
    advertiser = ZeroconfAdvertiser(PORT)
    advertiser.start()
    try:
        with socketserver.ThreadingTCPServer(("", PORT), PowerTouchHandler) as httpd:
            print(f"Serving on port {PORT}")
            httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        advertiser.stop()
