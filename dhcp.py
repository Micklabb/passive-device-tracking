from scapy.all import *
import requests
import datetime


API_KEY = ""
try:
    with open("api_key.txt", 'r') as f:
        API_KEY = f.read().strip()
except FileNotFoundError:
    print("API Key file not found")


def display_dhcp(pkt):
    """ This function displays debug packet information """
    now = datetime.datetime.now()
    logging.debug("{} - {} -> ff:ff:ff:ff:ff:ff (broadcast)".format(
        "{}:{}:{}.{}".format(now.hour, now.minute, now.second, now.microsecond),
        pkt.src,
    ))


def dhcp_fingerprint(pkt):
    """
    This function determines a device model for a dhcp request packet.
    It uses dhcp fingerprinting and the fingerbank API.

    Input: A scapy dhcp packet
    Output: The name from the device that send the dhcp packet
    """
    options = pkt[DHCP].options
    options_dict = dict(filter(lambda x: isinstance(x, tuple), options))

    # Reading packet info
    if options_dict["message-type"] == 3:
        dhcp_info = {
            "mac":pkt.src,
            "fingerprint":options_dict.get("param_req_list", ""),
            "vendor":options_dict.get("vendor_class_id", ""),
            "hostname":options_dict.get("hostname", ""),
        }

        # Sending a request to fingerbank with dhcp_info
        fingerprint = ",".join(map(str, dhcp_info["fingerprint"]))
        data = {
            "key": API_KEY,
            "dhcp_fingerprint": fingerprint,
            "dhcp_vendor": dhcp_info["vendor"],
            "mac": dhcp_info["mac"],
            "hostname": dhcp_info["hostname"],
        }

        r = requests.get('https://api.fingerbank.org/api/v2/combinations/interrogate', data=data)
        resp = r.json()

        if 'errors' in resp:
            logging.info("{} Error: Fingerprint not recognized, not enough information".format(dhcp_info["mac"]))
        else:
            logging.info("Device name: {} - Score: {}".format(resp["device_name"], resp["score"]))
            simple = simplify_os(resp["device_name"])


def simplify_os(device_name):
    if "Android" in device_name:
        return "android"
    elif "Apple" in device_name:
        return "apple"

if __name__ == "__main__":
    pkts = rdpcap("/home/pi/monitor/dhcp4.pcap")
    for pkt in pkts:
        dhcp_fingerprint(pkt)