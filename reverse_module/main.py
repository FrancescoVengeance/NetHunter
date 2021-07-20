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
    except Exception:
        return False


if __name__ == "__main__":
    if len(sys.argv):
        if len(sys.argv) == 2 and (sys.argv[1] == "-a" or sys.argv[1] == "--auto"):
            inspector = Inspector()
            inspector.sniff("eth0")
        elif len(sys.argv) == 3 and (sys.argv[1] == "-m" or sys.argv[1] == "--manual") and validateIP(sys.argv[2]):
            inspector = Inspector()
            inspector.manualConnection(sys.argv[2])
