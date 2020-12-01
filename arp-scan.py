#!/usr/bin/env python3


from re import search
from sys import argv
from netaddr import IPNetwork
from scapy.all import *
from subprocess import run


def print_help():
	print("Local area network host discovery tool\n")
	print("Usage: ./arp-scan.py [Network/CIDR]\n")
	print("Examples:")
	print("\t./arp-scan.py")
	print("\t./arp-scan.py 192.168.1.0/24")


def check_uid():
	output = run(["id", "-u"], capture_output = True)

	if int(output.stdout.decode()) != 0:
		return False

	return True


def get_up_interface():
	output = run(["ip", 'l'], capture_output = True)

	for i in output.stdout.decode().split('\n'):
		if search("state UP", i):
			return i.split()[1].strip(':')


def get_local_address(up_interface):
	output = run(["ip", "addr", "show", up_interface], capture_output = True)

	r = search("([0-9]{1,3}\\.){3}[0-9]{1,3}/[0-9]{1,2}", output.stdout.decode())

	return r.group()


def gen_ip_list(address_cidr):
	ip_list = []

	ipnet = IPNetwork(address_cidr)

	for i in ipnet[1:-1]:
		ip_list.append(str(i))

	return ip_list


def arp_scan(targets, up_interface):
	p = Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = targets)

	ans, unans = srp(p, verbose = 0, timeout = 2)

	print("%s:" %(up_interface))

	for i in ans:
		print("%s\t%s" %(i[1][ARP].psrc, i[1][Ether].src))


if __name__ == "__main__":
	if "-h" in argv or "--help" in argv:
		print_help()

		exit()

	if not check_uid():
		print("Error: arp-scan.py requires super-user privileges.")

		exit()

	if len(argv) < 2:
		up_interface = get_up_interface()

		local_address = get_local_address(up_interface)

		ip_list = gen_ip_list(local_address)
	else:
		ip_list = gen_ip_list(argv[1])

	arp_scan(ip_list, up_interface)
