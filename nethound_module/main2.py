from spanning_tree_monitor import SpanningTreeMonitor
from safe_print import SafePrint
import sys

if __name__ == '__main__':
    interface = sys.argv[1]
    # packets = PacketsBuffer()
    safe_print = SafePrint()

    # sniffer = Sniffer(interface, packets)
    # dhcp = DHCPMonitor(interface, packets, safe_print)
    # dns = DNSMonitor(interface, packets, safe_print)
    # arp = ARPMonitor(packets, safe_print)
    stp = SpanningTreeMonitor(safe_print, interface)

    # arp.start()
    # sniffer.start()
    # dhcp.start()
    # dns.start()
    stp.start()

    # dhcp.join()
    # sniffer.join()
    # dns.join()
    # arp.join()
    stp.join()
