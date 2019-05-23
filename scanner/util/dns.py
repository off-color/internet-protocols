import struct


def create_message():
    result = create_header(1, 2**8, 1, 0, 0, 0)
    result += struct.pack('>b', 2)
    result += b'ru'
    result += struct.pack('>b', 0)
    result += struct.pack('>2H', 1, 1)
    return result


def create_header(id, flags, qdcount, ancount, nscount, arcount):
    counts = [qdcount, ancount, nscount, arcount]
    result = struct.pack('>2H', id, flags)
    for i in range(4):
        result += struct.pack('>H', counts[i])
    return result
