#!/usr/bin/env python
# Test ticket against SMB 







import argparse
import os
import socket
from impacket.smbconnection import SMBConnection

print("\t\t\t-=[ Stupid Test ]=-\n\n")

parser = argparse.ArgumentParser(add_help = True, description = "Stupid test to verify if a test is valid")
parser.add_argument("-target-ip", action="store", help="Target IP")
parser.add_argument("-target-name", action="store", help="Target FQDN")
parser.add_argument("-domain", action="store", help="Domain")
parser.add_argument("-dc-ip", action="store", help="Domain Controller IP")
parser.add_argument("-ticket", action="store", help="CCache file location")
options = parser.parse_args() 

os.environ["KRB5CCNAME"] = options.ticket

try:
	smb = SMBConnection(options.target_name, options.target_ip)
	smb.kerberosLogin(user='', password='', domain=options.domain, kdcHost=options.dc_ip, useCache=True)
	print("[*] Ticket worked:\n")
	files = smb.listPath("C$", "*")
	for file in files:
		print("\t\t[+] " + file.get_longname())
except Exception as e:
	print("[-] Error: ")
	print(e)
