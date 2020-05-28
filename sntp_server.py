import socket
import threading
import sys
import argparse
import queue
import struct
import time
import datetime

SYSTEM_NTP_DIFFERENCE = (datetime.date(1970, 1, 1) - datetime.date(1900, 1,
                                                                   1)).days * 24 * 60 * 60
OFFSET = 0


class SNTPPacket:
    PACKET_FORMAT = ">3B b 5I 3Q"

    def __init__(self, version=4, mode=3, packet_transmit_timestamp=0,
                 orig_timestamp=0):
        self.leap = 0
        self.version = version
        self.mode = mode
        self.stratum = 0
        self.poll = 0
        self.precision = 0
        self.root_delay = 0
        self.root_dispersion = 0
        self.ref_clock_id = 0
        self.ref_timestamp = 0
        if not orig_timestamp:
            self.orig_timestamp = time.time()
        else:
            self.orig_timestamp = orig_timestamp
        self.receive_timestamp = 0
        self.transmit_timestamp = packet_transmit_timestamp

    def __bytes__(self):
        return struct.pack(SNTPPacket.PACKET_FORMAT,
                           (self.leap << 6 | self.version << 3 |
                            self.mode),
                           self.stratum,
                           self.poll,
                           self.precision,
                           self.root_delay,
                           self.root_dispersion,
                           self.ref_clock_id,
                           self.ref_timestamp,
                           self.ref_timestamp,
                           self.orig_timestamp,
                           SNTPPacket.format_time(
                               self.transmit_timestamp + OFFSET),
                           SNTPPacket.format_time(
                               time.time() + SYSTEM_NTP_DIFFERENCE + OFFSET)
                           )

    @classmethod
    def parse_packet(cls, packet):
        if len(packet) < 48:
            return None
        version = (packet[0] & 56) >> 3
        mode = packet[0] & 7
        if mode != 3:
            return None
        original_timestamp = int.from_bytes(packet[40:48], 'big')
        transmit_timestamp = int(time.time() + SYSTEM_NTP_DIFFERENCE)
        return SNTPPacket(version, 4, transmit_timestamp, original_timestamp)

    @classmethod
    def format_time(cls, timestamp):
        return int(timestamp * (2 ** 32))


class SNTPServer:
    def __init__(self, port, workers=10):
        self.is_working = True
        self.server_port = port

        self.to_send = queue.Queue()
        self.received = queue.Queue()

        self.server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server.bind(('127.0.0.1', self.server_port))

        self.receiver = threading.Thread(target=self.receive_request)
        self.workers = [threading.Thread(target=self.handle_request) for _ in
                        range(workers)]

    def start(self):
        for w in self.workers:
            w.setDaemon(True)
            w.start()
        self.receiver.setDaemon(True)
        self.receiver.start()
        print(f"Listening to port {self.server_port}")
        print(f"Offset is {OFFSET} seconds")
        while self.is_working:
            pass

    def handle_request(self):
        while self.is_working:
            try:
                packet, address = self.received.get(block=False)
            except queue.Empty:
                pass
            else:
                if packet:
                    self.server.sendto(bytes(packet), address)

    def receive_request(self):
        while self.is_working:
            try:
                data, addr = self.server.recvfrom(1024)
                self.received.put((SNTPPacket.parse_packet(data), addr))
                print(f'Request:\nIP: {addr[0]}\nPort: {addr[1]}\n')
            except socket.error:
                return

    def stop(self):
        self.is_working = False
        self.receiver.join()
        for w in self.workers:
            w.join()
        self.server.close()


def parse_args(args):
    parser = argparse.ArgumentParser(
        description="Simple NTP server with time trick option!")
    parser.add_argument('-d', action='store', dest='offset', type=int, default=0,
                        help='Offset to the current time.')
    parser.add_argument('-p', '--port', action='store', type=int, default=123)
    args = parser.parse_args(args)
    if args.port < 1 or args.port > 65535:
        print('Port is incorrect')
        exit(2)
    return args


def main(argv):
    args = parse_args(argv[1:])
    global OFFSET
    OFFSET = args.offset
    server = SNTPServer(args.port)
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()


if __name__ == "__main__":
    main(sys.argv)
