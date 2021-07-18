import os
from Inspector import Inspector
if os.geteuid() != 0:
    print("You need to run as root!", end="\n")
    exit()

if __name__ == "__main__":
    inspector = Inspector()
    inspector.sniff("eth0")