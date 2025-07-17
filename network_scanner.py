#!/usr/bin/env python

import scapy.all as scapy
import argparse

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="target ip")
    option = parser.parse_args()
    if not option.target:
        parser.error("[-] Specify a valid Target IP.. See --help for info...")
    return option

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    client = []

    for elements in answered_list:
        client_dict = {"ip" : elements[1].psrc, "mac" : elements[1].hwsrc}
        client.append(client_dict)
    return client


def print_result(result_list):
    print("mac address\t\t\tip\n------------------------------------------")
    for clients in result_list:
        print(clients["ip"] + "\t\t" + clients["mac"])

options = get_args()
scanner = scan(options.target)
print_result(scanner)