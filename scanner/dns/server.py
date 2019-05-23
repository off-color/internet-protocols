import socket
import struct
from datetime import datetime, timedelta
import pickle
import os.path
from collections import defaultdict
import argparse

FORWARDER = ''


class Parser:
    @staticmethod
    def read_by_zero_byte(data, pos):
        result = ''
        current_byte, pos = Parser.read_bytes(data, pos, '>B', 1)
        while current_byte != 0:
            if current_byte <= 63:
                name = struct.unpack_from(f'>{current_byte}s', data, pos)[0]
                pos += current_byte
                result += name.decode() + '.'
                current_byte, pos = Parser.read_bytes(data, pos, '>B', 1)
            else:
                index = struct.unpack_from('>H', data, pos - 1)[0]
                index -= 49152
                name, _ = Parser.read_by_zero_byte(data, index)
                result += name
                pos += 1
                break
        return result, pos

    @staticmethod
    def read_bytes(data, pos, string, count):
        result = struct.unpack_from(string, data, pos)[0]
        pos += count
        return result, pos

    @staticmethod
    def pack_labels(name):
        result = b''
        label_list = name.split('.')
        for label in label_list:
            label_b = label.encode('idna')
            result += struct.pack('>b', len(label_b))
            result += label_b
        return result


class CacheRecord:
    def __init__(self, data, ttl, date):
        self.data = data
        self.ttl = ttl
        self.date = date


class Question:
    def __init__(self, qname, qtype):
        self.qname = qname
        self.qtype = qtype

    @staticmethod
    def from_bytes(data, pos):
        qname, pos = Parser.read_by_zero_byte(data, pos)
        qtype, pos = Parser.read_bytes(data, pos, '>H', 2)
        pos += 2
        return Question(qname, qtype), pos

    @staticmethod
    def get_questions(data, pos, count):
        questions = []
        for _ in range(count):
            q, pos = Question.from_bytes(data, pos)
            questions.append(q)
        return questions, pos


class ResourceRecord:
    def __init__(self, name, type, ttl, rdata):
        self.name = name
        self.type = type
        self.ttl = ttl
        self.rdata = rdata

    @staticmethod
    def from_bytes(data, pos, rdata_label):
        name, pos = Parser.read_by_zero_byte(data, pos)
        # pos -= 1
        type, pos = Parser.read_bytes(data, pos, '>H', 2)
        pos += 2
        ttl, pos = Parser.read_bytes(data, pos, '>I', 4)
        rdlength, pos = Parser.read_bytes(data, pos, '>H', 2)
        rdata = struct.unpack_from(f'>{rdlength}s', data, pos)
        if rdata_label:
            rdata = Parser.read_by_zero_byte(data, pos)
        pos += rdlength
        return ResourceRecord(name, type, ttl, rdata), pos

    @staticmethod
    def get_records(data, pos, count, rdata_label):
        result = []
        for _ in range(count):
            rr, pos = ResourceRecord.from_bytes(data, pos, rdata_label)
            result.append(rr)
        return result, pos


class Message:
    def __init__(
      self, questions, answers, authorities, additionals, id, flags):
        self.questions = questions
        self.answers = answers
        self.authorities = authorities
        self.additionals = additionals
        self.id = id
        self.flags = flags

    @staticmethod
    def from_bytes(data):
        id, flags, qdcount, ancount, nscount, arcount =\
            struct.unpack_from('>6H', data, 0)
        position = 12
        questions, position = Question.get_questions(data, position, qdcount)
        answers, position = ResourceRecord.get_records(
            data, position, ancount, questions[0].qtype == 2)
        authorities, position = ResourceRecord.get_records(
            data, position, nscount, True)
        additionals, position = ResourceRecord.get_records(
            data, position, arcount, False)
        return Message(questions, answers, authorities, additionals, id, flags)


class Server:
    def __init__(self):
        self.cache = self.load_cache()

    def handle_request(self, request):
        question = request.questions[0]
        message = Message(request.questions, [], [], [], 4390, 2**15)
        key = (question.qname, question.qtype)
        if key in self.cache:
            for rr in self.cache[key]:
                if (rr.date +
                        timedelta(seconds=rr.ttl) < datetime.now()):
                    self.cache.pop(key)
                    message = self.get_info_from_forwarder(question)
                    break
                else:
                    message.answers.append(rr.data)
        else:
            message = self.get_info_from_forwarder(question)
        return message

    def get_info_from_forwarder(self, question):
        request_to_forwarder = self.create_request(question, 4390, 2**8)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(1)
            try:
                s.sendto(request_to_forwarder, (FORWARDER, 53))
                data = s.recv(65536)
            except (socket.timeout, socket.gaierror):
                return Message([question], [], [], [], 0, 2**15 + 2)
        message = Message.from_bytes(data)
        self.update_cache(question, message)
        return message

    def update_cache(self, question, message):
        key = (question.qname, question.qtype)
        self.clean_cache_before_update(key)
        for i in range(len(message.answers)):
            self.cache[key].append(
                CacheRecord(message.answers[i],
                            message.answers[i].ttl, datetime.now()))
        key = (question.qname, 2)
        self.clean_cache_before_update(key)
        for authority in message.authorities:
            self.cache[key].append(
                CacheRecord(authority, authority.ttl, datetime.now()))
        for additional in message.additionals:
            if question.qtype == 2:
                break
            key = (additional.name, 1)
            self.clean_cache_before_update(key)
            self.cache[key].append(
                CacheRecord(additional, additional.ttl, datetime.now()))

    def clean_cache_before_update(self, key):
        if key in self.cache:
            self.cache.pop(key)

    def create_request(self, question, id, flags):
        return self.create_message(question, [], id, flags)

    def create_message(self, question, answers, id, flags):
        result = self.create_header(id, flags, 1, len(answers), 0, 0)
        result += Parser.pack_labels(question.qname)
        # request += struct.pack('>b', 0)
        result += struct.pack('>2H', question.qtype, 1)
        for answer in answers:
            result += Parser.pack_labels(answer.name)
            result += struct.pack('>2HI', answer.type, 1, answer.ttl)
            if question.qtype == 2:
                rdata = Parser.pack_labels(answer.rdata[0])
                result += struct.pack('>H', len(rdata))
                result += struct.pack(f'>{len(rdata)}s', rdata)
            else:
                result += struct.pack('>H', len(answer.rdata[0]))
                result += struct.pack(
                    f'>{len(answer.rdata[0])}s', answer.rdata[0])
        return result

    def create_header(self, id, flags, qdcount, ancount, nscount, arcount):
        counts = [qdcount, ancount, nscount, arcount]
        result = struct.pack('>2H', id, flags)
        for i in range(4):
            result += struct.pack('>H', counts[i])
        return result

    def create_response(self, question, answers, id, flags):
        return self.create_message(question, answers, id, flags)

    def load_cache(self):
        if not os.path.isfile('cache'):
            return defaultdict(list)
        with open('cache', 'rb') as f:
            cache = pickle.load(f)
        return cache

    def save_cache(self):
        with open('cache', 'wb') as f:
            pickle.dump(self.cache, f)


def main():
    global FORWARDER
    FORWARDER = parse_args().forwarder
    server = Server()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(('127.0.0.1', 53))
        s.settimeout(1)
        while True:
            try:
                try:
                    data, addr = s.recvfrom(65536)
                except (socket.timeout, ConnectionResetError):
                    continue
            except KeyboardInterrupt:
                server.save_cache()
                break
            try:
                request = Message.from_bytes(data)
            except Exception:
                continue
            message = server.handle_request(request)
            response = server.create_response(
                request.questions[0], message.answers,
                request.id, message.flags)
            s.sendto(response, addr)


def parse_args():
    parser = argparse.ArgumentParser(
        description='Caching DNS server')
    parser.add_argument('forwarder', metavar='FORWARDER', nargs='?',
                        help='forwarder for our server', default='8.8.8.8')
    return parser.parse_args()


if __name__ == '__main__':
    main()
