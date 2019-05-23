import socket
import argparse
import numpy as np
from concurrent.futures import ProcessPoolExecutor
from sniffer import Sniffer
import time
from util import sntp
from util import dns
import struct


class Port:
    def __init__(self, port_type, port):
        self.port_type = port_type
        self.port = port
        self.protocol = None

    def __str__(self):
        return f'{self.port}/{self.port_type} {self.protocol}'


class Scanner:
    def __init__(self, host, start, end):
        self.start = start
        self.end = end
        self.host = host

    def scan_ports(self, need_udp):
        futures = []
        result = []
        with ProcessPoolExecutor(max_workers=50) as e:
            for ports in filter(
              lambda x: x.size > 0,
              np.array_split(range(self.start, self.end + 1), 100)):
                futures.append(e.submit(self.scan_tcp_ports, ports))
        for future in futures:
            result += future.result()

        if need_udp:
            result += self.scan_udp_ports(range(self.start, self.end + 1))
        return result

    def _scan_ports(self, ports, scan_func):
        open_ports = []
        for number in ports:
            port, is_open = scan_func(number)
            if is_open:
                open_ports.append(port)
        return open_ports

    def scan_tcp_ports(self, ports):
        return self._scan_ports(ports, self.scan_tcp_port)

    def scan_tcp_port(self, port):
        with socket.socket() as s:
            s.settimeout(0.1)
            result = s.connect_ex((self.host, port))
        return Port('TCP', port), not result

    def scan_udp_ports(self, ports):
        s = Sniffer()
        s.start()
        self._scan_ports(ports, self.scan_udp_port)
        s.stop.set()
        s.join()
        closed_ports = self.get_closed_udp_ports(s.packets)
        return [Port('UDP', p) for p in ports if p not in closed_ports]

    def scan_udp_port(self, port):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(b'', (self.host, port))
            time.sleep(0.1)
            return Port('UDP', port), True

    def get_closed_udp_ports(self, icmp_packets):
        ports = []
        for p in icmp_packets:
            icmp_type, icmp_code = struct.unpack_from('!2B', p, 20)
            if (icmp_type, icmp_code) != (3, 3):
                continue
            port = struct.unpack_from('!H', p, 50)[0]
            ports.append(port)
        return ports


class Qualifier:
    def __init__(self, host, ports):
        self.host = host
        self.tcp_ports = list(filter(lambda x: x.port_type == 'TCP', ports))
        self.udp_ports = list(filter(lambda x: x.port_type == 'UDP', ports))

    def determine_protocols_udp(self):
        sntp_request = sntp.get_request()
        dns_request = dns.create_message()
        for port in self.udp_ports:
            if self.try_determine_udp(sntp_request, port):
                port.protocol = 'SNTP'
            if self.try_determine_udp(dns_request, port):
                port.protocol = 'DNS'

    def try_determine_udp(self, request, port):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(1)
            s.sendto(request, (self.host, port.port))
            try:
                data = s.recv(1024)
                return True
            except socket.timeout:
                return False

    def determine_protocols_tcp(self):
        for port in self.tcp_ports:
            with socket.socket() as s:
                s.settimeout(0.5)
                try:
                    s.connect((self.host, port.port))
                    data = s.recv(1024).decode()
                    if data[:3] == '220':
                        port.protocol = 'SMTP'
                    if data[:3] == '+OK':
                        port.protocol = 'POP3'
                except socket.timeout:
                    if self.determine_http(s):
                        port.protocol = 'HTTP'
                        continue
                    if self.determine_dns_tcp((self.host, port.port)):
                        port.protocol = 'DNS'

    def determine_http(self, s):
        data = self.send_request_tcp(b'GET / HTTP/1.1\nHOST: 111\n\n', s)
        return data[:4] == b'HTTP'

    def determine_dns_tcp(self, addr):
        message = dns.create_message()
        with socket.socket() as s:
            s.connect(addr)
            s.settimeout(0.5)
            self.send_request_tcp(struct.pack('!H', len(message)), s)
            data = self.send_request_tcp(message, s)
        return len(data) != 0

    def send_request_tcp(self, request, sock):
        try:
            sock.sendall(request)
            data = sock.recv(1024)
        except socket.error:
            return ''
        return data



def main():
    args = parse_args()
    scanner = Scanner(args.host, args.start, args.end)
    open_ports = scanner.scan_ports(args.udp)
    q = Qualifier(args.host, open_ports)
    q.determine_protocols_tcp()
    print(', '.join(map(str, q.tcp_ports)))
    if args.udp:
        q.determine_protocols_udp()
        print(', '.join(map(str, q.udp_ports)))


def parse_args():
    parser = argparse.ArgumentParser(
        description='port scanner')
    parser.add_argument('host', metavar='HOST',
                        help='host for scan')
    parser.add_argument('start', metavar='FROM',
                        help='start point in range of ports', type=int)
    parser.add_argument('end', metavar='TO',
                        help='end point in range of ports', type=int)
    parser.add_argument('-u', '--udp', action='store_true',
                        dest='udp', help='include udp')
    return parser.parse_args()


if __name__ == '__main__':
    main()
