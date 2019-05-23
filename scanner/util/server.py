import socket
import struct
import datetime
import argparse


class Message:
    def __init__(self, version, originate, receive, transmit):
        self.version = version
        self.originate = originate
        self.receive = receive
        self.transmit = transmit

    @staticmethod
    def from_request(data):
        first_byte = struct.unpack_from('!B', data, 0)[0]
        version = (first_byte & 56) >> 3
        transmit_timestamp_int = struct.unpack_from('!I', data, 40)[0]
        transmit_timestamp_fraction = struct.unpack_from('!I', data, 44)[0]
        transmit_timestamp = Helper.to_time(
            transmit_timestamp_int, transmit_timestamp_fraction)
        return Message(version, None, None, transmit_timestamp)


class Server:
    def __init__(self, delta):
        self.delta = delta

    def get_response(self, message):
        response = struct.pack('!2BH', 4 + message.version << 3, 1, 0)
        for _ in range(5):
            response += struct.pack('!I', 0)
        times = [message.originate, message.receive,
                 self.get_current_time() + self.delta]
        for time in times:
            response += struct.pack('!II', int(time), Helper.to_frac(time))
        return response

    def get_current_time(self):
        diff = (datetime.datetime.utcnow() -
                datetime.datetime(1900, 1, 1, 0, 0, 0))
        return diff.total_seconds()


class Helper:
    @staticmethod
    def to_time(integ, frac):
        return integ + float(frac)/2**32

    @staticmethod
    def to_frac(timestamp):
        return int(abs(timestamp - int(timestamp)) * 2**32)


def main():
    server = Server(float(parse_args().shift))
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 123))
        s.listen(1)
        while True:
            client, addr = s.accept()
            data = client.recv(1024)
            if not data:
                continue
            receive = server.get_current_time() + server.delta
            request = Message.from_request(data)
            response = server.get_response(
                Message(request.version, request.transmit, receive, None))
            client.sendall(response)


def parse_args():
    parser = argparse.ArgumentParser(
        description='Lying SNTP server')
    parser.add_argument('shift', metavar='SHIFT',
                        help='time shift for server in seconds')
    return parser.parse_args()


if __name__ == '__main__':
    main()
