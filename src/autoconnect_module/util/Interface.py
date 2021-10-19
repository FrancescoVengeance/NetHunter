import os


# Sets IP address and subnet mask using ifconfig command
def setup_interface(interface, ip_address, subnet_mask):
    # os.system("sudo ifconfig %s down" % interface)
    os.system("sudo ifconfig %s %s netmask %s" % (interface, ip_address, subnet_mask))
    # os.system("sudo ifconfig %s up" % interface)


# Writes DNS servers in the etc/resolv.conf file
def setup_dns(dns_servers):
    dns = dns_servers.split(",")
    echo_str = ""
    for server in dns:
        echo_str += "nameserver " + server + "\n"
    os.system('sudo bash -c \'echo "%s" > /etc/resolv.conf\'' % echo_str)


# Adds default gateway through route command
def setup_default_gateway(router):
    os.system("sudo route add default gw %s" % router)
