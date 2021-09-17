#!/usr/bin/python3

#Menu driven network scanning tool:
import nmap
import os
import sys
#import pprint as pp

def menu():
    print(f"{'_'*20}MENU{'_'*20}")
    print("1. Scan single host")
    print("2. Scan range")
    print("3. Scan network")
    print("4. Agressive scan")
    print("5. Scan ARP packet")
    print("6. Scan All port only")
    print("7. Scan in verbose mode")
    print("8. Exit")


def scan_hosts(ip_r = "192.168.0.1-106", port_r = "1-10000", args = ""):
    nm = nmap.PortScanner()
    print("Wait.......................")
    try:
        if args:
            args = f"-sS -O -Pn --host-timeout 20s {args}"

        scan = nm.scan(hosts = ip_r, ports = port_r, arguments = args) #Returns Dictionary
        #pp.pprint(scan)
        print(nm.command_line())

        for host in nm.all_hosts():
            print("----------------------------------------------------")
            print("Host : %s (%s)" % (host, nm[host].hostname()))
            print("State : %s" % nm[host].state())
            try:
                print("OS Detect : %s" % nm[host]["osmatch"][0]["name"])
            except:
                 print("OS Detect : None")
            for proto in nm[host].all_protocols():
                print("----------")
                print("Protocol : %s" % proto)
                lport = list(nm[host][proto].keys())
                lport.sort()
                for port in lport:
                    print ("port : %s\tstate : %s\tname : %s\treason : %s" % (port, nm[host][proto][port]["state"], 
                                                                             nm[host][proto][port]["name"], 
                                                                             nm[host][proto][port]["reason"]))
    except nmap.PortScannerError:
        print("ERROR: Use root privilege")
    except Exception as err:
        print(sys.exc_info())


def scan_range_ip_port():
    ip_r = input("Enter the IP range (192.168.0.1-106): ")
    port_r = input("Enter the port range (1-10000): ")
    scan_hosts(ip_r, port_r)


def scan_single_host():
    ip = input("Enter the IP (192.168.0.106): ")
    scan_hosts(ip)


def scan_network():
    ip = input("Enter the IP network (192.168.0.106/24): ")
    scan_hosts(ip)

def aggressive_scan():
    ip = input("Enter the IP (192.168.0.106): ")
    scan_hosts(ip_r = ip, args = "-T4")


def scan_arp_pkt():
    ip = input("Enter the IP network (192.168.0.106/24): ")
    scan_hosts(ip_r = ip, args = "-PR")


def scan_all_port():
    ip = input("Enter the IP (192.168.0.106): ")
    scan_hosts(ip_r = ip, port_r = "1-65535")
        

def scan_verbose_mode():
    ip = input("Enter the IP (192.168.0.106): ")
    scan_hosts(ip_r = ip, args = "-v")
  

if __name__ == "__main__":

    while True:
        menu()
        ch =  input("Enter choice: ")
        if ch == '1':
            scan_single_host()

        elif ch == '2':
            scan_range_ip_port()

        elif ch == '3':
            scan_network()

        elif ch == '4':
            aggressive_scan()

        elif ch == '5':
            scan_arp_pkt()

        elif ch == '6':
            scan_all_port()

        elif ch == '7':
            scan_verbose_mode()
            
        elif ch == '8':
            break;
        else:
            print("Wrong Choice")
    
