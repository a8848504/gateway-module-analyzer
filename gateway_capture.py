#!/usr/bin/env python3
"""Capture gateway TCP streams and read gateway IDs from ETHE frames."""

import argparse
import itertools
import socketserver
import tempfile
from collections import Counter
from datetime import datetime
from ipaddress import IPv4Address
from pathlib import Path


class EtheDecoder:
    def __init__(self):
        self.buffer = bytearray()
        self.valid_frames = 0
        self.invalid_frames = 0
        self.placeholder_frames = 0
        self.gateway_ids = Counter()

    def feed(self, chunk):
        self.buffer.extend(chunk)
        discovered = []
        offset = 0
        while (start := self.buffer.find(b"ETHE", offset)) >= 0:
            offset = start
            if len(self.buffer) - start < 6:
                break
            payload_size = int.from_bytes(self.buffer[start + 4:start + 6], "big")
            end = start + 22 + payload_size
            if end > len(self.buffer):
                break
            frame = self.buffer[start:end]
            if frame[-1] != ord("M") or sum(frame[4:-2]) % 256 != frame[-2]:
                self.invalid_frames += 1
                offset = start + 1
                continue

            self.valid_frames += 1
            gateway_id = bytes(frame[-14:-2])
            if gateway_id in (bytes(12), b"\x55" * 12, b"\xff" * 12):
                self.placeholder_frames += 1
            else:
                key = gateway_id, frame[6]
                self.gateway_ids[key] += 1
                if self.gateway_ids[key] == 1:
                    discovered.append(key)
            offset = end
        else:
            offset = max(offset, len(self.buffer) - 3)
        del self.buffer[:offset]
        return discovered


def describe_gateway(gateway_id, gateway_type):
    description = f"gateway_id={gateway_id.hex().upper()} type=0x{gateway_type:02X}"
    if gateway_type in (0x01, 0x06):  # Ethernet data and heartbeat
        reported_ip = IPv4Address(gateway_id[:4])
        reported_port = int.from_bytes(gateway_id[4:6], "big")
        mac = gateway_id[6:].hex(":").upper()
        description += f" mac={mac} reported_address={reported_ip}:{reported_port}"
    return description


class CaptureHandler(socketserver.BaseRequestHandler):
    def handle(self):
        peer_ip, peer_port = self.client_address
        capture_number = next(self.server.capture_numbers)
        capture_path = self.server.capture_dir / f"{capture_number:04d}_{peer_ip}_{peer_port}.bin"
        received = 0
        decoder = EtheDecoder()

        with capture_path.open("xb", buffering=0) as capture:
            print(f"{timestamp()} connected {peer_ip}:{peer_port} file={capture_path.name}", flush=True)
            try:
                while chunk := self.request.recv(65536):
                    capture.write(chunk)
                    if received == 0:
                        print(f"{timestamp()} first data {peer_ip}:{peer_port} bytes={len(chunk)}", flush=True)
                    received += len(chunk)
                    for gateway_id, gateway_type in decoder.feed(chunk):
                        description = describe_gateway(gateway_id, gateway_type)
                        print(f"{timestamp()} {peer_ip}:{peer_port} {description}", flush=True)
            except ConnectionError as error:
                print(f"{timestamp()} {peer_ip}:{peer_port} {error}", flush=True)
            finally:
                print(f"{timestamp()} disconnected {peer_ip}:{peer_port} total_bytes={received}", flush=True)


class CaptureServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, capture_dir):
        self.capture_dir = capture_dir
        self.capture_numbers = itertools.count(1)
        super().__init__(address, CaptureHandler)


def timestamp():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def analyze_capture(path):
    decoder = EtheDecoder()
    received = 0
    with path.open("rb") as capture:
        while chunk := capture.read(65536):
            received += len(chunk)
            decoder.feed(chunk)
    print(
        f"{path.name}: bytes={received} valid_frames={decoder.valid_frames} "
        f"invalid_frames={decoder.invalid_frames} placeholder_frames={decoder.placeholder_frames}"
    )
    for (gateway_id, gateway_type), count in decoder.gateway_ids.most_common():
        print(f"{describe_gateway(gateway_id, gateway_type)} frames={count}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=7115)
    parser.add_argument("--output", type=Path, help="Parent directory for a new capture directory")
    parser.add_argument("--analyze", type=Path, metavar="CAPTURE", help="Analyze a saved TCP stream")
    args = parser.parse_args()

    if args.analyze:
        analyze_capture(args.analyze)
        return

    capture_dir = Path(tempfile.mkdtemp(prefix="gateway-capture-", dir=args.output)).resolve()
    with CaptureServer((args.host, args.port), capture_dir) as server:
        host, port = server.server_address
        print(f"{timestamp()} listening {host}:{port} output={capture_dir}", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
