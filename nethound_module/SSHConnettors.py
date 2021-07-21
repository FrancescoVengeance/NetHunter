from builtins import print

import pexpect
import re
from NetworkElements import Switch
from NetworkElements import Port
import os


class CiscoSSH:

    def __init__(self, c_interface, m_timeout):
        self.connected_interface = c_interface
        self.monitor_timeout = m_timeout
        self.switch_interfaces = list()
        self.child = None
        self.switch = None

    def connect(self, ip, name, pwd, en_pwd, max_attempts=1):
        attempts = 0
        while attempts < max_attempts:
            try:
                self.child = pexpect.spawn("ssh %s@%s" % (name, ip))
                self.child.timeout = 15
                self.child.expect('Password:')
                self.child.sendline(pwd)
                self.child.expect('>')
                self.child.sendline('terminal length 0')
                self.child.expect('>')
                self.child.sendline('enable')
                self.child.expect('Password:')
                self.child.sendline(en_pwd)
                self.child.expect('%s#' % name)
                print("Connected!")
                self.switch = Switch(name, ip, pwd, en_pwd, self.connected_interface)
                return True
            except (pexpect.EOF, pexpect.TIMEOUT):
                if "Password" in str(self.child.before):
                    print("Wrong Credentials..")
                    return False
                if "Host key verification failed." in str(self.child.before):
                    print("Host key verification failed. Retring!")
                    os.system('ssh-keygen -f "/root/.ssh/known_hosts" -R %s' % ip)
                    return self.connect_with_no_host_auth(ip, name, pwd, en_pwd)
                if "The authenticity of host" in str(self.child.before):
                    return self.connect_with_no_host_auth(ip, name, pwd, en_pwd)
                if attempts < max_attempts:
                    print("Attempt #%s failed! i'm triyng again!" % attempts)
                else:
                    print("\n\n>>>>>>>>>>>CONNECTION ERROR<<<<<<<<<<<\n\n")
                    return False
                self.child.close()
                attempts += 1

    def connect_with_no_host_auth(self, ip, name, pwd, en_pwd):
        print("I'm trying to acknowledge the authenticity of the new host")
        try:
            self.child = pexpect.spawn("ssh %s@%s" % (name, ip))
            self.child.expect('The authenticity of host')
            self.child.sendline('yes')
            self.child.expect('Password:')
            self.child.sendline(pwd)
            self.child.expect('>')
            self.child.sendline('terminal length 0')
            self.child.expect('>')
            self.child.sendline('enable')
            self.child.expect('Password:')
            self.child.sendline(en_pwd)
            self.child.expect('%s#' % name)
            print("Connected!")
            self.switch = Switch(name, ip, pwd, en_pwd, self.connected_interface)
            return True
        except (pexpect.EOF, pexpect.TIMEOUT):
            print("\n\n>>>>>>>>>>>CONNECTION ERROR<<<<<<<<<<<\n\n")
            self.child.close()
            return False

    def reconnect(self, ip, name, pwd, en_pwd, c_interface, m_timeout):
        self.connected_interface = c_interface
        self.monitor_timeout = m_timeout
        self.connect(ip, name, pwd, en_pwd, 20)

    def take_interfaces(self):
        self.child.sendline('show interfaces | i (.* line protocol is )|(.* address is)')
        self.child.expect('%s#' % self.switch.name)
        output = str(self.child.before)
        raw_port_name = re.findall('([^\\n]\w*[^0-9]\d\/\d\.*\d*)', output)
        raw_port_mac = re.findall('([a-fA-F0-9]{4}[.][a-fA-F0-9]{4}[.][a-fA-F0-9]{4})[^\)]', output)

        if len(raw_port_mac) == len(raw_port_name):
            dim = len(raw_port_name)
        else:
            if len(raw_port_mac) < len(raw_port_name):
                dim = len(raw_port_mac)
            else:
                dim = len(raw_port_name)

        for i in range(dim):
            name = raw_port_name[i].lstrip('\\n')
            mac_parts = raw_port_mac[i].split('.')
            mac = mac_parts[0][:2] + ':' + mac_parts[0][2:4] + ':' + mac_parts[1][:2] + ':' + \
                  mac_parts[1][2:4] + ':' + mac_parts[2][:2] + ':' + mac_parts[2][2:4]
            self.switch.add_ports(Port(name, mac))
            if name not in self.switch_interfaces:
                self.switch_interfaces.append(name)
        return self.switch

    def put_callback(self):
        print("I'm trying to enable the callback")
        self.child.sendline('configure terminal')
        self.child.expect('\(config\)#')
        self.child.sendline('event manager applet no-monitor-session')
        self.child.expect('\(config-applet\)#')
        self.child.sendline('event timer countdown time %s' % self.monitor_timeout)
        self.child.expect('\(config-applet\)#')
        self.child.sendline('action 01 cli command "enable"')
        self.child.expect('\(config-applet\)#')
        self.child.sendline('action 02 cli command "configure terminal"')
        self.child.expect('\(config-applet\)#')
        self.child.sendline('action 03 cli command "no monitor session 27"')
        self.child.expect('\(config-applet\)#')
        self.child.sendline('action 04 cli command "end"')
        self.child.expect('\(config-applet\)#')
        self.child.sendline('action 05 cli command "exit"')
        self.child.expect('\(config-applet\)#')
        self.child.sendline('end')
        self.child.expect('%s#' % self.switch.name)
        print("Finished!")

    def enable_monitor_mode(self):
        try:
            self.clear_vty_line()
            self.put_callback()
            print("Enabling monitor mode...")
            self.child.sendline('configure terminal')
            self.child.expect('\(config\)#')

            for interface in self.switch_interfaces:
                if self.connected_interface[-3:] not in interface:
                    self.child.sendline('monitor session 27 source interface %s' % interface)
                    self.child.expect('\(config\)#')

            self.child.sendline(
                'monitor session 27 destination interface %s encapsulation replicate' % self.connected_interface)
            self.child.expect('\(config\)#')
            self.child.close()
        except (pexpect.EOF, pexpect.TIMEOUT):
            print("Connection Closed!")

    def enable_monitor_mode_on_interface_range(self, interfaces):
        try:
            self.clear_vty_line()
            self.put_callback()
            print("Enabling monitor mode...")
            self.child.sendline('configure terminal')
            self.child.expect('\(config\)#')

            for interface in interfaces:
                if self.connected_interface[-3:] not in interface:
                    self.child.sendline('monitor session 27 source interface %s' % interface)
                    self.child.expect('\(config\)#')

            self.child.sendline(
                'monitor session 27 destination interface %s encapsulation replicate' % self.connected_interface)
            self.child.expect('\(config\)#')
        except (pexpect.EOF, pexpect.TIMEOUT):
            print("Connection Closed!")
        self.child.close()

    def enable_monitor_mode_on_specific_port(self, port_name):
        try:
            self.clear_vty_line()
            self.put_callback()
            print("Enabling monitor mode...")
            self.child.timeout = 5
            self.child.sendline('configure terminal')
            self.child.expect('\(config\)#')
            self.child.sendline('monitor session 27 source interface %s' % port_name)
            self.child.expect('\(config\)#')
            self.child.sendline(
                'monitor session 27 destination interface %s encapsulation replicate' % self.connected_interface)
            self.child.expect('\(config\)#')
        except (pexpect.EOF, pexpect.TIMEOUT):
            print("Connection Closed!")
        self.child.close()

    def clear_vty_line(self):
        print("Clearing vty lines")
        for i in range(5):
            self.child.sendline('clear line vty %s' % i)
            self.child.expect('[confirm]')
            self.child.sendline('\n')
            self.child.expect('%s#' % self.switch.name)
        print("Done!")


class ExtremeSSH:
    def __init__(self, c_interface, m_timeout, switch_mac):
        self.connected_interface = c_interface
        self.vlan = 3
        self.switch_mac = switch_mac
        self.monitor_timeout = m_timeout
        self.switch_interfaces = list()
        self.child = None
        self.switch = None

    def connect(self, ip, name, pwd, en_pwd, max_attempts=1):
        attempts = 0
        while attempts < max_attempts:
            try:
                self.child = pexpect.spawn("ssh %s@%s" % (name, ip))
                self.child.timeout = 15
                self.child.expect('password:')
                self.child.sendline(pwd)
                self.child.expect('#')
                self.child.sendline('disable clipaging')
                self.child.expect('#')
                self.switch = Switch(name, ip, pwd, en_pwd, self.connected_interface)
                print("Connected!")
                return True
            except (pexpect.EOF, pexpect.TIMEOUT):
                attempts += 1
                if "password" in str(self.child.before):
                    print("Wrong Credentials..")
                    return False
                if "Host key verification failed." in str(self.child.before):
                    print("Host key verification failed. Retring!")
                    os.system('ssh-keygen -f "/root/.ssh/known_hosts" -R %s' % ip)
                    return self.connect_with_no_host_auth(ip, name, pwd)
                if "The authenticity of host" in str(self.child.before):
                    return self.connect_with_no_host_auth(ip, name, pwd)
                if attempts < max_attempts:
                    print("Attempt #%s failed! i'm triyng again!" % attempts)
                else:
                    print("\n\n>>>>>>>>>>>CONNECTION ERROR<<<<<<<<<<<\n\n")
                    return False

    def connect_with_no_host_auth(self, ip, name, pwd):
        print("I'm trying to acknowledge the authenticity of the new host")
        try:
            self.child = pexpect.spawn("ssh %s@%s" % (name, ip))
            self.child.expect('The authenticity of host')
            self.child.sendline('yes')
            self.child.expect('password:')
            self.child.sendline(pwd)
            self.child.expect('#')
            self.child.sendline('disable clipaging')
            self.child.expect('#')
            print("Connected!")
            self.switch = Switch(name, ip, pwd, pwd, self.connected_interface)
            return True
        except (pexpect.EOF, pexpect.TIMEOUT):
            print("\n\n>>>>>>>>>>>CONNECTION ERROR<<<<<<<<<<<\n\n")
            self.child.close()
            return False

    def take_interfaces(self):
        self.child.sendline('show ports vid')
        self.child.expect('#')
        output = str(self.child.before)
        raw_ports = re.findall('((\d+)\s+(Unt|T)*agged\s+(\d+([,]\s\d+)*|None)'
                               '(....\s+(Unt|T)*agged\s+(\d+([,]\s\d+)*|None))*)', output)

        for raw_port in raw_ports:
            if raw_port[1] != '':
                p_number = raw_port[1]
                vlans = list()
                if raw_port[3] != 'None':
                    if ',' in raw_port[3]:
                        for vlan in raw_port[3].split(', '):
                            vlans.append(vlan)
                    else:
                        vlans.append(raw_port[3])
                if raw_port[7] != 'None' and raw_port[7] != '':
                    if ',' in raw_port[7]:
                        for vlan in raw_port[7].split(', '):
                            vlans.append(vlan)
                    else:
                        vlans.append(raw_port[7])
                mac_parts = self.switch_mac.split(':')
                raw_mac = ''
                for part in mac_parts:
                    raw_mac += part
                num_mac = hex(int(raw_mac, 16) + int(p_number))[2:].zfill(12)
                mac = ''
                for index in range(0, len(num_mac)):
                    if index > 0 and (index % 2) == 0:
                        mac += ':'
                    mac += num_mac[index]

                port = Port(p_number, mac)
                if p_number not in self.switch_interfaces:
                    self.switch_interfaces.append(p_number)

                self.switch.add_ports(port)
                for vlan in vlans:
                    self.switch.set_blocked_port(mac, vlan, initialization=True)
        return self.switch

    def enable_monitor_mode(self):
        try:
            print("Enabling monitor mode...")
            self.put_callback()
            self.child.sendline('create mirror M1')
            self.child.expect('#')
            self.child.sendline('configure mirror M1 to port %s' % self.connected_interface)
            self.child.expect('#')

            for interface in self.switch_interfaces:
                if interface != self.connected_interface:
                    self.child.sendline('configure mirror M1 add port %s' % interface)
                    self.child.expect('#')

            self.child.sendline('enable mirror M1')
            self.child.expect('(y/N)')
            self.child.sendline('yes')
            self.child.expect('#')
            self.child.close()
        except (pexpect.EOF, pexpect.TIMEOUT):
            print("Connection Closed!")

    def enable_monitor_mode_on_interface_range(self, interfaces):
        try:
            print("Enabling monitor mode...")
            self.put_callback()
            self.child.sendline('create mirror M1')
            self.child.expect('#')
            self.child.sendline('configure mirror M1 to port %s' % self.connected_interface)
            self.child.expect('#')

            for interface in interfaces:
                if interface != self.connected_interface:
                    self.child.sendline('configure mirror M1 add port %s' % interface)
                    self.child.expect('#')

            self.child.sendline('enable mirror M1')
            self.child.expect('(y/N)')
            self.child.sendline('yes')
            self.child.expect('#')
            self.child.close()
        except (pexpect.EOF, pexpect.TIMEOUT):
            print("Connection Closed!")

    def enable_monitor_mode_on_specific_port(self, port_name):
        try:
            print("Enabling monitor mode...")
            self.put_callback()
            self.child.sendline('create mirror M1')
            self.child.expect('#')
            self.child.sendline('configure mirror M1 to port %s' % self.connected_interface)
            self.child.expect('#')
            self.child.sendline('configure mirror M1 add port %s' % port_name)
            self.child.expect('#')
            self.child.sendline('enable mirror M1')
            self.child.expect('(y/N)')
            self.child.sendline('yes')
            self.child.expect('#')
            self.child.close()
        except (pexpect.EOF, pexpect.TIMEOUT):
            print("Connection Closed!")
        self.child.close()

    def put_callback(self):
        self.clear_upm_profile()
        self.child.sendline('create upm profile disable_mirror')
        self.child.expect('\n')
        self.child.sendline('disable mirror M1')
        self.child.expect('\r')
        self.child.sendline('delete mirror M1')
        self.child.expect('\r')
        self.child.sendline('configure vlan %s add ports %s untagged' % (self.vlan, self.connected_interface))
        self.child.expect('\r')
        self.child.sendline('delete upm timer t')
        self.child.expect('\r')
        self.child.sendline('.')
        self.child.expect('#')
        self.child.sendline('create upm timer t')
        self.child.expect('#')
        self.child.sendline('configure upm timer t after %s' % self.monitor_timeout)
        self.child.expect('#')
        self.child.sendline('configure upm timer t profile disable_mirror')
        self.child.expect('#')
        self.child.sendline('enable upm timer t')
        self.child.expect('#')
        print("Finished!")

    def clear_upm_profile(self):
        print("Clearing UPM Profile")
        self.child.sendline('delete upm profile disable_mirror')
        self.child.expect('#')
        print("Done")
