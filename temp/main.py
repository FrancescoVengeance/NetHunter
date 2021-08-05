import os
import sys
import socket
if os.geteuid() != 0:
    print("You need to run as root!", end="\n")
    exit()
from Naspy import Naspy


def validateIP(ip: str) -> bool:
    try:
        socket.inet_aton(ip)
        return True
    except OSError:
        return False


def usage() -> str:
    return f"usage: {sys.argv[0]} [-a | --auto] [-i | --interface]:\n" \
           f"trying to sniff a LLDP or CDP packet on selected interface and waits until\n" \
           f"it receives the packet\n\n" \
           f"Example: {sys.argv[0]} -a -i eth0\n" \
           f"{sys.argv[0]} [-m | --manual] IP:\n" \
           f"Example {sys.argv[0]} -m 10.0.0.1  " \
           f"connect directly to the specified IP address without sniffing anything\n"


if __name__ == "__main__":
    if len(sys.argv) == 4 and ((sys.argv[1] == "-a" or sys.argv[1] == "--auto") and (sys.argv[2] == "-i" or sys.argv[2] == "--interface")):
        naspy = Naspy()
        naspy.sniff(sys.argv[3])
    elif len(sys.argv) == 3 and (sys.argv[1] == "-m" or sys.argv[1] == "--manual"):
        if validateIP(sys.argv[2]):
            naspy = Naspy()
           # naspy.manualConnection(sys.argv[2])
        else:
            print("Invalid IP address\n")
            print(usage())
    else:
        print(usage())
