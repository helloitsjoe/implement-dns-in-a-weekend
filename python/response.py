from classes import DNSQuestion, DNSHeader, DNSRecord, DNSPacket, TYPE_A, TYPE_NS
from dataclasses import dataclass
import dataclasses
from io import BytesIO
import struct
import socket

def header_to_bytes(header):
    fields = dataclasses.astuple(header)
    # There are 6 Hs because there are 6 fields
    return struct.pack("!HHHHHH", *fields)

def ip_to_string(ip):
    return ".".join([str(x) for x in ip])

def question_to_bytes(question):
    return question.name + struct.pack("!HH", question.type_, question.class_)

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
    if type_ == TYPE_NS:
        data = decode_name(reader)
    elif type_ == TYPE_A:
        data = ip_to_string(reader.read(data_len))
    else:
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

def encode_dns_name(domain_name):
    encoded = b""
    for part in domain_name.encode("ascii").split(b"."):
        encoded += bytes([len(part)]) + part
    return encoded + b"\x00"

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

