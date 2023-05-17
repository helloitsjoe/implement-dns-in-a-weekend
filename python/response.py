from main import build_query, DNSQuestion, DNSHeader
from dataclasses import dataclass
from io import BytesIO
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

def parse_header(reader):
    items = struct.unpack("!HHHHHH", reader.read(12))
    return DNSHeader(*items)

def parse_question(reader):
    name = decode_name_simple(reader)
    print(name)
    data = reader.read(4)
    type, class_ = struct.unpack("!HH", data)
    return DNSQuestion(name, type, class_)

def decode_name_simple(reader):
    parts = []
    while (length := reader.read(1)[0]) != 0:
        parts.append(reader.read(length))
    return b".".join(parts)

query = build_query("www.example.com", TYPE_A)

# create a UDP socket
# `socket.AF_INET` means that we're connecting to the internet
# (as opposed to a Unix domain socket `AF_UNIX` for example)
# `socket.SOCK_DGRAM` means "UDP"
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

sock.sendto(query, ("8.8.8.8", 53))

response, _ = sock.recvfrom(1024)

reader = BytesIO(response)
header = parse_header(reader)
# question = reader.read(19)
print(parse_question(reader))