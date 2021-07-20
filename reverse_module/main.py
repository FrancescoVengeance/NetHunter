import os
import sys
import socket
from Inspector import Inspector
if os.geteuid() != 0:
    print("You need to run as root!", end="\n")
    exit()


def validateIP(ip: str) -> bool:
    try:
        socket.inet_aton(ip)
        return True
    except OSError:
        return False

def usage() -> str:
    return f"usage: {sys.argv[0]} [-a | --auto]:\n" \
           f"trying to sniff a LLDP or CDP packet and waits until\n" \
           f"it receives the packet\n\n" \
           f"{sys.argv[0]} [-m | --manual] IP:\n" \
           f"connect directly to the specified IP address without sniffing anything\n"


if __name__ == "__main__":
    if len(sys.argv) > 1:
        if len(sys.argv) == 2 and (sys.argv[1] == "-a" or sys.argv[1] == "--auto"):
            inspector = Inspector()
            inspector.sniff("eth0")
        elif len(sys.argv) == 3 and (sys.argv[1] == "-m" or sys.argv[1] == "--manual") and validateIP(sys.argv[2]):
            inspector = Inspector()
            inspector.manualConnection(sys.argv[2])
        else:
            print(usage())
    else:
        print(usage())
