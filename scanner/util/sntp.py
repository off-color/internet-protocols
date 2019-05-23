import socket
import struct
import util.server as server


def main():
    with socket.socket() as s:
        s.connect(('127.0.0.1', 123))
        data = get_request()
        s.sendall(data)
        response = s.recv(1024)
        t4 = server.Server(0).get_current_time()
        parse_response(response, t4)


def get_request():
    request = struct.pack('!2BH', 11, 0, 0)
    t = server.Server(0).get_current_time()
    request += struct.pack(
        '!11I', 0, 0, 0, 0, 0, 0, 0, 0, 0, int(t), server.Helper.to_frac(t))
    return request


def parse_response(response, t4):
    t1 = parse_time(response, 24)
    t2 = parse_time(response, 32)
    t3 = parse_time(response, 40)
    delay = (t4 - t3) + (t2 - t1)
    offset = ((t2 - t1) + (t3 - t4)) / 2
    print(delay)
    print(server.Server(0).get_current_time())
    print(server.Server(0).get_current_time() + offset)


def parse_time(data, index):
    time_int = struct.unpack_from('!I', data, index)[0]
    time_fraction = struct.unpack_from('!I', data, index + 4)[0]
    time = server.Helper.to_time(time_int, time_fraction)
    return time


if __name__ == '__main__':
    main()
