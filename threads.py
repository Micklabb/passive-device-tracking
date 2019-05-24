from scapy.all import *
import threads
import logging
import time

from signature import display_probe_assoc, generate_signature, performance_characteristics
from dhcp import display_dhcp, dhcp_fingerprint

logging.basicConfig(level=logging.DEBUG, format='(%(threadName)-9s) %(message)s',)
logging.getLogger("urllib3").setLevel(logging.WARNING)

mac_blacklist = [
    "ff:ff:ff:ff:ff:ff",
    "00:00:00:00:00:00",
]

# Thread that receives probe and assoc packets from wlan0
def monitor():
    logging.info("Starting...")

    def handle_probe_assoc(pkt):
        display_probe_assoc(pkt)
        signature = generate_signature(pkt)

    blacklist = " and ".join(["not ether src {}".format(mac) for mac in mac_blacklist])
    sniff(
        iface="wlan0",
        filter="{} and type mgt subtype probe-req or type mgt subtype assoc-req".format(blacklist),
        prn=handle_probe_assoc,
    )

# Thread that listens for broadcasted DHCP requests
def dhcp():
    logging.info("Starting...")

    def handle_dhcp(pkt):
        display_dhcp(pkt)
        device_name = dhcp_fingerprint(pkt)

    sniff(
        iface="eth0",
        filter="((udp port 67) and (udp[8:1] = 0x1))",
        prn=handle_dhcp,
    )


if __name__ == '__main__':
    d = threading.Thread(name="monitor-thread", target=monitor)
    d2 = threading.Thread(name="dhcp-thread", target=dhcp)
    
    d.start()
    d2.start()

