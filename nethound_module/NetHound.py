import concurrent.futures

from NetInterface import *
from Monitors import *
from LogSender import LogSender
from datetime import datetime
import sys
import pyshark

usage = "Usage: -i [interface], [-m [mode]], [-p [password]], [-h [help]]"
full_usage = "mode options: \n" \
             "arp: IDS system for ARP protocol." \
             "dhcp: IDS system for Rogue DHCP Attack" \
             "dns: IDS system for DNS Hijack Attack" \
             "stp: Monitoring STP Status and eventually failure" \
             "default: When no other options are chosen this script will perform all modality\n" \
             "password: is the password use for decrypting switch credentials"

print("Welcome to NetHound - a NASPy tool")

password = None
if os.geteuid() != 0:
    print("You need to run as root!")
    sys.exit(0)

if len(sys.argv) < 3:
    print("Error, you must enter an Interface name and a modality")
    print(usage)
    sys.exit(0)

else:
    if sys.argv[1] == '-i':
        interface = sys.argv[2]
    else:
        if sys.argv[1] == '-h':
            print('%s \n %s' % (usage, full_usage))
        else:
            print(usage)
        sys.exit(0)

    mode = 'all'
    if len(sys.argv) > 4 and '-m' in sys.argv:
        index = (sys.argv.index('-m') + 1)
        if index < len(sys.argv):
            if sys.argv[index] == 'arp':
                mode = 'arp'
            if sys.argv[index] == 'dhcp':
                mode = 'dhcp'
            if sys.argv[index] == 'vlan':
                mode = 'vlan'
            if sys.argv[index] == 'stp':
                mode = 'stp'
            if sys.argv[index] == 'dns':
                mode = 'dns'

    if len(sys.argv) > 4 and '-p' in sys.argv:
        index = (sys.argv.index('-p')+1)
        if index < len(sys.argv):
            password = sys.argv[index]


if mode is None:
    print('%s \n %s' % (usage, full_usage))
    sys.exit(0)

log = open('log.naspy', 'w')
log.write("NASPY -- Buffer94\n")

tc_body_message = "Hi,\n You are receiving this report because there was a Topology Change " \
                  "in the topology, please check it!"
daily_body_message = "Hi,\n This is the daily report sent every day at 00:00!"

net_interface = NetInterface(interface, "Buff96")
net_interface.timeout = 35

stp_monitor = STPMonitor(log)
arp_monitor = ArpMonitor(log)
dhcp_monitor = RogueDHCPMonitor(log)
dns_monitor = RogueDNSMonitor(log)


def update_callback(pkt):
    if mode == 'all':
        if pkt.highest_layer.upper() == 'ARP':
            sender_port = None
            target_port = None
            for switch in stp_monitor.switches_table:
                if switch.contains(pkt.arp.src_hw_mac):
                    sender_port = switch.get_port(pkt.arp.src_hw_mac)

                if switch.contains(pkt.arp.dst_hw_mac):
                    target_port = switch.get_port(pkt.arp.dst_hw_mac)

            arp_monitor.update_arp_table(pkt, sender_port, target_port)
        if pkt.highest_layer.upper() == 'BOOTP':
            dhcp_monitor.update_dhcp_servers(pkt)
        if pkt.highest_layer.upper() == 'DNS':
            dns_monitor.update_dns_servers(pkt)
        stp_monitor.update_switches_table(pkt)
        stp_monitor.discover_vlan_hopping(pkt, log)

    if mode == 'dns' and pkt.highest_layer.upper() == 'DNS':
        dns_monitor.update_dns_servers(pkt)

    if mode == 'stp':
        stp_monitor.update_switches_table(pkt)
        stp_monitor.discover_vlan_hopping(pkt, log)

    if mode == 'dhcp' and pkt.highest_layer.upper() == 'BOOTP':
        dhcp_monitor.update_dhcp_servers(pkt)

    if mode == 'arp' and pkt.highest_layer.upper() == 'ARP':
        arp_monitor.update_arp_table(pkt)


topology_cng_pkg = None
capture = pyshark.LiveCapture(interface=net_interface.interface)

try:
    if mode == 'stp' or mode == 'all':
        net_interface.wait_for_initial_information()
        if net_interface.ssh_no_credential_connection():
            stp_monitor.add_switch(net_interface.take_interfaces())
            net_interface.enable_monitor_mode()

        print('start sniffing...')
        # capture = pyshark.LiveCapture(interface=net_interface.interface)
        try:
            capture.apply_on_packets(update_callback, timeout=net_interface.timeout)
        except concurrent.futures.TimeoutError:
            capture.close()
            print('Capture finished!')

        stp_monitor.set_connected_interface_status(interface)
        stp_monitor.find_root_port(interface)

        stp_monitor.print_switches_status()

    while True:
        if log.closed:
            log = open('log.naspy', 'a')
        time.sleep(30)

        if mode == 'dhcp' or mode == 'all':
            threading.Thread(target=net_interface.send_dhcp_discover).start()

        if mode == 'dns' or mode == 'all':
            threading.Thread(target=net_interface.send_dns_query).start()

        print('start sniffing...')
        capture = pyshark.LiveCapture(interface=net_interface.interface)
        try:
            capture.apply_on_packets(update_callback, timeout=net_interface.timeout)
        except concurrent.futures.TimeoutError:
            capture.close()
            print('Capture finished!')

        dhcp_monitor.print_dhcp_servers()
        dhcp_monitor.increase_counter()
        dns_monitor.print_dns_servers()
        dns_monitor.increase_counter()
        arp_monitor.print_ip_arp_table()

        if mode == 'stp' or mode == 'all':
            time.sleep(stp_monitor.waiting_timer/2)
            print("Finding topology changes...")
            topology_cng_pkg = pyshark.LiveCapture(interface=interface, display_filter="stp.flags.tc == 1")
            topology_cng_pkg.sniff(packet_count=1, timeout=180)

            if topology_cng_pkg:
                print("Found topology changes!")
                log.write("%s - Found topology changes!\n" % datetime.now().strftime("%H:%M:%S"))
                stp_monitor.discover_topology_changes(interface, password)
                stp_monitor.print_switches_status()
                log.close()
                time.sleep(stp_monitor.waiting_timer)
                print("Sending log by email")
                # sender = LogSender()
                # sender.send(tc_body_message, 'Topology Change Report!', attachment='log.naspy', att_type='filename')
            else:
                print('No changes in Topology!')
                log.write('%s - No changes in Topology!\n' % datetime.now().strftime("%H:%M:%S"))
                stp_monitor.print_switches_status()

        log.close()
        current_time = datetime.now().strftime("%H:%M")
        if current_time == "00:00":
            #sender = LogSender()
            #sender.send(daily_body_message, 'Daily Report!', attachment='log.naspy', att_type='filename')
except (KeyboardInterrupt, RuntimeError, TypeError):
    if topology_cng_pkg is not None:
        topology_cng_pkg.eventloop.close()
    capture.eventloop.close()
    log.close()
    print("Bye!!")

