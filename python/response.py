from main import build_query, DNSQuestion, DNSHeader
from dataclasses import dataclass
from io import BytesIO
from typing import List
import struct
import socket

TYPE_A = 1

@dataclass
class DNSRecord:
    name: bytes
    type_: int
    class_: int
    ttl: int
    data: bytes

@dataclass
class DNSPacket:
    header: DNSHeader
    questions: List[DNSQuestion]
    answers: List[DNSRecord]
    authorities: List[DNSRecord]
    additionals: List[DNSRecord]

def parse_header(reader):
    items = struct.unpack("!HHHHHH", reader.read(12))
    return DNSHeader(*items)

def parse_question(reader):
    name = decode_name(reader)
    print(name)
    data = reader.read(4)
    type, class_ = struct.unpack("!HH", data)
    return DNSQuestion(name, type, class_)

def parse_record(reader):
    name = decode_name(reader)
    # The type, class, TTL, and data length together are 10 bytes
    data = reader.read(10)
    # HHIH means 2 byte int, 2 byte int, 4 byte int, 2 byte int
    type_, class_, ttl, data_len = struct.unpack("!HHIH", data)
    data = reader.read(data_len)
    return DNSRecord(name, type_, class_, ttl, data)

def parse_dns_packet(data):
    reader = BytesIO(data)
    header = parse_header(reader)
    questions = [parse_question(reader) for _ in range(header.num_questions)]
    answers = [parse_record(reader) for _ in range(header.num_answers)]
    authorities = [parse_record(reader) for _ in range(header.num_authorities)]
    additionals = [parse_record(reader) for _ in range(header.num_additionals)]

    return DNSPacket(header, questions, answers, authorities, additionals)

def ip_to_string(ip):
    return ".".join([str(x) for x in ip])

# def decode_name_simple(reader):
#     parts = []
#     while (length := reader.read(1)[0]) != 0:
#         parts.append(reader.read(length))
#     return b".".join(parts)

def decode_name(reader):
    parts = []
    while (length := reader.read(1)[0]) != 0:
        if length & 0b1100_0000:
            parts.append(decode_compressed_name(length, reader))
            break
        else:
            parts.append(reader.read(length))
    return b".".join(parts)

def decode_compressed_name(length, reader):
    pointer_bytes = bytes([length & 0b0011_1111]) + reader.read(1)
    pointer = struct.unpack("!H", pointer_bytes)[0]
    current_pos = reader.tell()
    reader.seek(pointer)
    result = decode_name(reader)
    reader.seek(current_pos)
    return result

def lookup_domain(domain_name, type=TYPE_A):
    print(type)
    query = build_query(domain_name, type)
    # create a UDP socket
    # `socket.AF_INET` means that we're connecting to the internet
    # (as opposed to a Unix domain socket `AF_UNIX` for example)
    # `socket.SOCK_DGRAM` means "UDP"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(query, ("8.8.8.8", 53))

    # Get the response
    data, _ = sock.recvfrom(1024)
    response = parse_dns_packet(data)
    return ip_to_string(response.answers[0].data)

print(lookup_domain("google.com"))
print(lookup_domain("www.runtimerundown.com", 5))
