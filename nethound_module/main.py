import concurrent.futures
from NetInterface import *
from Monitors import *
from datetime import datetime
import sys
import pyshark


def print_help():
    return "Usage: -i [interface], [-m [mode]], [-p [password]], [-h [help]]\n" \
           "mode options: \n" \
           "arp: IDS system for ARP protocol.\n" \
           "dhcp: IDS system for Rogue DHCP Attack\n" \
           "dns: IDS system for DNS Hijack Attack\n" \
           "stp: Monitoring STP Status and eventually failure\n" \
           "default: When no other options are chosen this script will perform all modality\n" \
           "password: is the password use for decrypting switch credentials"


def parse_args():
    if os.geteuid() != 0:
        print("You need to run as a root")
        print(print_help())
        sys.exit(0)

    if len(sys.argv) < 3:
        print("[ERROR] you must enter an interface and a modality")
        print(print_help())
        sys.exit(0)

    modalities = ["arp", "dhcp", "vlan", "stp", "dns"]

    interface = None
    if "-i" in sys.argv:
        interface = sys.argv[sys.argv.index("-i") + 1]
        print(f"interface {interface}")
    elif "-h" in sys.argv:
        print(print_help())
        sys.exit(0)

    mode = "all"
    if len(sys.argv) > 4 and "-m" in sys.argv:
        mode = sys.argv[sys.argv.index("-m") + 1] if sys.argv[sys.argv.index("-m") + 1] in modalities else "all"
    print(f"mode setted to {mode}")

    password = None
    if len(sys.argv) > 4 and "-p" in sys.argv:
        password = sys.argv[sys.argv.index("-p") + 1]
        print(f"password {password}")

    return interface, mode, password


if __name__ == "__main__":
    interface, mode, password = parse_args()