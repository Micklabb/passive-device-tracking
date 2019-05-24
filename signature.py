"""
Some of the code I used is rewritten to work with python 3 from:
https://github.com/NetworkDeviceTaxonomy/wifi_taxonomy/blob/master/taxonomy/wifi.py
"""

from scapy.all import *
import re
import datetime


def display_probe_assoc(pkt):
    """ This function displays debug packet information """
    now = datetime.datetime.now()
    logging.debug("{} - {} ({}) -> '{}'".format(
        "{}:{}:{}.{}".format(now.hour, now.minute, now.second, now.microsecond),
        pkt.addr2,
        pkt.dBm_AntSignal,
        pkt.info.decode("utf-8"),
    ))


def generate_signature(pkt):
    """
    This function will generate a signature for a *single* packet.

    Input: A probe or assoc pkt object from scapy
    Output: A signature in the format "probe:abcdefg" or "assoc:abcdefg"

    If you want to use taxonomy, you will need a signature with a probe
    *and* an assoc packet in the format "wifi4|probe:abcdefg|assoc:abcdefg"
    """
    elt = None
    eltcount = 1

    pkt_subtype = ""
    elt_ids = []
    ht_settings = ""
    vht_settings = ""
    extcap_settings = ""
    pow_settings = ""
    wps_settings = ""

    if pkt.subtype == 4:
        pkt_subtype = "probe:"
    elif pkt.subtype == 0:
        pkt_subtype = "assoc:"

    # Iterate through all Information Elements in pkt
    while elt != pkt.lastlayer(Dot11Elt):
        elt = pkt.getlayer(Dot11Elt, nb=eltcount)
        eltcount += 1

        # Add all Information Element IDs to elt_ids in the order they appear
        if elt.ID == 221:
            vendor_info = "221({0:0{1}x},{2})".format(elt.oui, 6, elt.info[0])
            elt_ids.append(vendor_info)
        else:
            elt_ids.append(str(elt.ID))

        # HT Capabilities Information Element
        if elt.ID == 45:
            htcap = elt.info[0:2][::-1].hex()
            htagg = hex(elt.info[2])[2:]
            htmcs = elt.info[3:6][::-1].hex()

            ht_settings = "htcap:{},htagg:{},htmcs:{}".format(htcap, htagg, htmcs)

        # VHT Capabilities Information Element
        elif elt.ID == 191:
            info = elt.info.hex()
            vhtcap = elt.info[0:4][::-1].hex()
            vhtrxmcs = elt.info[4:8][::-1].hex()
            vhttxmcs = elt.info[8:12][::-1].hex()

            vht_settings = "vhtcap:{},vhtrxmcs:{},vhttxmcs:{}".format(vhtcap, vhtrxmcs, vhttxmcs)

        # Power Capability Information Element
        elif elt.ID == 33:
            pow_settings = "txpow:{}".format(elt.info[::-1].hex())

        # Extended Capabilities Information Element
        elif elt.ID == 127:
            extcap_settings = "extcap:{}".format(elt.info[::-1].hex())

        # Vendor WPS Information Element
        elif elt.ID == 221 and elt.oui == 20722 and elt.info[0] == 4:
            idx = elt.info.find(b'\x10\x23')
            model_name_len = int.from_bytes(elt.info[idx+2:idx+4], byteorder='big')
            model_name = elt.info[idx+4:idx+4+model_name_len].decode("utf-8", "ignore")
            
            wps_settings = "wps:{}".format(re.sub(r'\W+', '_', model_name))

    return pkt_subtype + ",".join(filter(None, [
        ",".join(elt_ids),
        ht_settings,
        vht_settings,
        pow_settings,
        extcap_settings,
        wps_settings,
    ]))


def performance_characteristics(signature):
    """
    This function gets the performance characteristics from a signature.
    
    Input: An assoc packet signature in the format "assoc:abcdefg"
    Output: A performance characteristic string "802.11a/b/g', n:1, w:20"
    """
    # Make dictionary from signature
    fields = filter(lambda s: s[0].isalpha(), signature.split(','))
    caps = dict([i.split(":") for i in fields])

    # VHT Characteristics
    if "vhtcap" and "vhtrxmcs" in caps:
        try:
            bitmap = int(caps["vhtcap"], base=16)
            scw = (bitmap >> 2) & 0x3
            widths = {0: '80', 1: '160', 2: '80+80'}
            vht_width = widths.get(scw, '??')

            mcs = int(caps["vhtrxmcs"], base=16)
            vht_nss = ((mcs & 0x0003 != 0x0003) + (mcs & 0x000c != 0x000c) +
                       (mcs & 0x0030 != 0x0030) + (mcs & 0x00c0 != 0x00c0) +
                       (mcs & 0x0300 != 0x0300) + (mcs & 0x0c00 != 0x0c00) +
                       (mcs & 0x3000 != 0x3000) + (mcs & 0xc000 != 0xc000))

            return "{}, n:{}, w:{}".format('802.11ac', vht_nss, vht_width)

        except ValueError:
            return "??"

    # HT Characteristics
    if "htcap" and "htmcs" in caps:
        try:
            bitmap = int(caps["htcap"], base=16)
            ht_width = '40' if bitmap & 0x2 else '20'

            mcs = int(caps["htmcs"], base=16)
            ht_nss = ((mcs & 0x000000ff != 0) + (mcs & 0x0000ff00 != 0) +
                      (mcs & 0x00ff0000 != 0) + (mcs & 0xff000000 != 0))

            return "{}, n:{}, w:{}".format('802.11n', ht_nss, ht_width)

        except ValueError:
            return "??"
    
    # Return Generic characteristics
    return "{}, n:{}, w:{}".format('802.11a/b/g', 1, '20')


def lookup_signature():
    pass

def sniff_200_packets(interface="wlan0"):
    p = sniff(
        iface=interface,
        filter="type mgt subtype probe-req or type mgt subtype assoc-req",
        count=200,
    )

    wrpcap('/home/pi/monitor/probes.pcap', p)

if __name__ == "__main__":
    #sniff_200_packets()
    pkts = rdpcap("/home/pi/monitor/probes.pcap")

    for pkt in pkts:
        if Dot11Elt in pkt:
            signature = generate_signature(pkt)
            perf = performance_characteristics(signature)
            print(perf)