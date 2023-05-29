from main import DNSRecord, DNSPacket, DNSQuestion, DNSHeader, header_to_bytes, question_to_bytes, encode_dns_name, build_query
from classes import TYPE_A, TYPE_NS
from main import send_query
import socket

def get_answer(packet):
    for x in packet.answers:
        if x.type_ == TYPE_A:
            return x.data

def get_nameserver(packet):
    for x in packet.authorities:
        if x.type_ == TYPE_NS:
            return x.data.decode('utf-8')

def get_nameserver_ip(packet):
    for x in packet.additionals:
        if x.type_ == TYPE_A:
            return x.data

def resolve(domain_name, record_type):
    nameserver = "198.41.0.4"
    while True:
        print(f"Querying {nameserver} for {domain_name}")
        response = send_query(nameserver, domain_name, record_type)
        if ip := get_answer(response):
            return ip
        elif nsIP := get_nameserver_ip(response):
            nameserver = nsIP
        elif ns_domain := get_nameserver(response):
            nameserver = resolve(ns_domain, TYPE_A)
        else:
            raise Exception("Something went wrong")


print(resolve("twitter.com", TYPE_A))

