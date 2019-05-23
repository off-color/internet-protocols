import socket
from threading import Thread, Event
import select


class Sniffer(Thread):
    def __init__(self):
        super().__init__()
        self.sniffer = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        self.stop = Event()
        self.packets = []

    def run(self):
        while not self.stop.is_set():
            ready = select.select([self.sniffer], [], [], 1)
            if ready[0] == []:
                continue
            rec_packet, addr = self.sniffer.recvfrom(1024)
            self.packets.append(rec_packet)
        self.sniffer.close()


if __name__ == '__main__':
    s = Sniffer()
    s.run()
