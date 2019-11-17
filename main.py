from scapy.all import *
import scapy.layers.http as http
import json
from user import User

def processLoad(load):
    try:
        data = json.loads(load[2:-1], encoding="utf-8")
        # print(data)
        users = data['result']['userlist']
        result = []
        for user in users:
            u = User()
            u.userid = user['user']['userid']
            u.gender = user['user']['gender']
            result.append(u)

        return result
    except Exception as err:
        return None

def parse_header(packet):
    packet.show()
    if packet.haslayer(http.HTTPResponse):
        if 'Raw' in packet:
            load = packet['Raw'].load
            users = processLoad(str(load))
            print(users)

    print("*** RECEIVED PACKET ***\n")

if __name__ == "__main__":
    print("Start")
    # show_interfaces()
    sniff(iface="802.11n USB Wireless LAN Card", prn=parse_header, session=TCPSession, filter="ip src api.changba.com")
