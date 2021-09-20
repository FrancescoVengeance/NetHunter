from monitors.dhcp_monitor import DHCPMonitor
from monitors.dns_monitor import DNSMonitor
from safe_print import SafePrint
from packets_buffer import PacketsBuffer
import sys
from sniffer import Sniffer

if __name__ == '__main__':
    interface = sys.argv[1]
    packets = PacketsBuffer()
    safe_print = SafePrint()
    sniffer = Sniffer(interface, packets)
    dhcp = DHCPMonitor(interface, packets, safe_print)
    dns = DNSMonitor(interface, packets, safe_print)
    sniffer.start()
    dhcp.start()
    dns.start()
    dhcp.join()
    sniffer.join()
    dns.join()
