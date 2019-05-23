import socket
import re
import threading
import ssl
import gzip

HOST = '127.0.0.1'
PORT = 8080
AD = b'<div id="ads_left" class="ads_left_empty"></div>'


class Session:
    def __init__(self, client_sock):
        self.client_sock = client_sock

    def session(self):
        while True:
            data = recieve(self.client_sock)
            if not data:
                break
            # decoded_data = data.decode()
            addr = Helper.get_address(data)
            with socket.socket() as server_sock:
                server_sock.settimeout(2)
                try:
                    method = Helper.get_method(data)
                    if method == 'CONNECT':
                        server_sock.connect(addr)
                        self.client_sock.sendall(b'HTTP/1.1 200 OK\r\n\r\n')
                        self.client_sock = ssl.wrap_socket(
                            self.client_sock, keyfile='key.pem',
                            certfile='cert.pem',
                            server_side=True,
                            do_handshake_on_connect=False)
                        self.client_sock.do_handshake()
                        server_sock = wrap_socket(server_sock, addr)
                        # self.client_sock = wrap_socket(self.client_sock)
                        tunneling = Tunneling(
                            addr, self.client_sock, server_sock)
                        tunneling.tunneling()
                        break
                    else:
                        server_sock.connect(addr)
                        server_sock.sendall(data)
                except socket.timeout:
                    continue
                Helper.forward(server_sock, self.client_sock.sendall)


class Tunneling:
    def __init__(self, addr, client_sock, server_sock):
        self.addr = addr
        self.client_sock = client_sock
        self.server_sock = server_sock

    def tunneling(self):
        while True:
            data = recieve(self.client_sock)
            if not data:
                break
            self.server_sock.sendall(data)
            response = recieve(self.server_sock)
            if 'vk.com' in self.addr[0]:
                try:
                    response = Handler.delete_ads(response)
                except Exception as e:
                    print(e)
            self.client_sock.sendall(response)


class Handler:
    @staticmethod
    def delete_ads(response):
        if Helper.get_encoding(response) == 'gzip':
            headers = response.split(b'\r\n\r\n')[0]
            decoded = gzip.decompress(response.split(b'\r\n\r\n')[1])
            if AD in decoded:
                decoded, x = re.subn(AD, b'', decoded)
                encoded = gzip.compress(decoded)
                headers = Helper.set_header(
                    headers, b'Content-Length', str(len(encoded)).encode())
                return headers + b'\r\n\r\n' + gzip.compress(decoded)
        return response


class Helper:
    @staticmethod
    def get_address(data):
        host = Helper.get_header(data, b'Host')
        if host is None:
            return
        if ':' in host:
            host, port = host.split(':')
            return (host, int(port))
        return (host, 80)

    @staticmethod
    def get_method(data):
        first_line = data.split(b'\n')[0]
        return first_line.split(b' ')[0].decode()

    @staticmethod
    def get_encoding(data):
        return Helper.get_header(data, b'Content-Encoding')

    @staticmethod
    def get_header(data, header):
        found = re.findall(header + b': (.+)\r\n', data)
        if found:
            return found[0].decode()

    @staticmethod
    def set_header(data, header, value):
        return re.sub(
            header + b': .+\r\n', header + b': ' + value + b'\r\n', data)

    @staticmethod
    def forward(sock, func):
        part = b''
        try:
            while True:
                part = sock.recv(1024)
                if not part:
                    break
                func(part)
                part = b''
        except socket.timeout:
            func(part)


def wrap_socket(sock, addr):
    context = ssl._create_default_https_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context.wrap_socket(sock, server_hostname=addr[0])


def recieve(s):
    data = b''
    part = b''
    try:
        while True:
            part = s.recv(1024)
            if not len(part):
                break
            data += part
            part = b''
    except socket.timeout:
        data += part
    return data


def main():
    with socket.socket() as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(10)

        while True:
            conn, addr = s.accept()
            conn.settimeout(1)
            session = Session(conn)
            d = threading.Thread(target=session.session)
            d.setDaemon(True)
            d.start()


if __name__ == '__main__':
    main()
