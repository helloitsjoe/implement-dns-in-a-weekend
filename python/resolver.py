from main import DNSRecord, DNSPacket, DNSQuestion, DNSHeader, header_to_bytes, question_to_bytes, encode_dns_name, build_query
from response import decode_name, parse_header, parse_question, parse_dns_packet, ip_to_string, TYPE_A
import socket

def send_query(ip_address, domain_name, record_type):
    query = build_query(domain_name, record_type)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(query, (ip_address, 53))

    data, _ = sock.recvfrom(1024)
    return parse_dns_packet(data)

response = send_query("198.41.0.4", "runtimerundown.com", TYPE_A)
print(response.answers)
print(response.authorities)
