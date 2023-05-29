from classes import DNSHeader, DNSQuestion, DNSRecord, DNSPacket, TYPE_A, CLASS_IN
from response import parse_dns_packet, header_to_bytes, question_to_bytes, encode_dns_name
import struct
import random
import socket

random.seed(1)

def build_query(domain_name, record_type):
    name = encode_dns_name(domain_name)
    id = random.randint(0, 65535)
    # Recursion Desired bit is the 9th bit from the left in the flags field
    RECURSION_DESIRED = 1 << 8
    header = DNSHeader(id=id, num_questions=1, flags=0)
    question = DNSQuestion(name=name, type_=record_type, class_=CLASS_IN)
    return header_to_bytes(header) + question_to_bytes(question)

def send_query(ip_address, domain_name, record_type):
    query = build_query(domain_name, record_type)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(query, (ip_address, 53))

    data, _ = sock.recvfrom(1024)
    return parse_dns_packet(data)

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

