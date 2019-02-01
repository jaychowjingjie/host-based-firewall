import csv
import ipaddress
import unittest
"""
Given a set of firewall rules, a network packet will be accepted 
by the firewall if and only if the direction, protocol, port, and 
IP address match at least one of the input rules. If a rule contains
a port range, it will match all packets whose port falls within the range. 
If a rule contains an IP address range, it will match all packets whose 
IP address falls within the range.
"""

class Firewall:
    '''
    Constructor takes in the firewall rules from the input file and 
    stores the each rule in the rules list. 

    Note: Can assume that the input CSV file contains only valid, well-­
    formed entries.
    '''
    def __init__(self, file_path):
        self.rules = []
        with open(file_path) as input_file:
            csv_reader = csv.reader(input_file)
            for line in csv_reader:
                #print(line)
                self.rules.append(line)
        #print(self.rules)
                
                
    """
    A function, accept_packet, that takes exactly four arguments and returns a 
    boolean: true, if there exists a rule in the file that this object was 
    initialized with that allows traffic with these particular properties, and 
    false otherwise. direction, protocol, port and ip_address are strings from 
    each test function
    """
    def accept_packet(self, direction, protocol, port, ip_address):
        print(self.rules)
        # each rule is a ['inbound', 'tcp', '80', '192.168.1.2'] list from csv
        # rule[0] is 'inbound', rule[1] is 'tcp',...
        for rule in self.rules:
            if not self.check_direction(rule[0], direction):
                continue
            elif not self.check_protocol(rule[1], protocol):
                continue
            elif not self.check_port(rule[2], port):
                continue
            elif not self.check_ip_address(rule[3], ip_address):
                continue
            # if ALL self functions return true, means exact match, means fail
            # all if/elif checks, doesn't go into a single continue state
            return True
        return False
    
    """
    direction: Either “inbound” or “outbound”, corresponding to whether
    traffic is entering or leaving the machine. rule is from csv, direction is
    from test function.
    """
    def check_direction(self, rule, direction):
        if direction == rule:
            return True
        else:
            return False

    """
    protocol: Either “tcp” or “udp”, all lowercase – we will just
    implement two the most common protocols. rule is from csv, direction is
    from test function.
    """
    def check_protocol(self, rule, protocol):
        if protocol == rule:
            return True
        else:
            return False
    
    """
    port: Either (a) an integer in the range [1, 65535] or (b) a port
    range, containing two integers in the range [1, 65535] separated by a
    dash (no spaces). Port ranges are inclusive, i.e. the port range “80-­85”
    contains ports 80 and 85. Given a port range, you may assume that the
    range is well-­formed i.e. the start of the range is strictly less than
    the end. port is an int, so we need str(port) to compare string with string.
    rule is from csv, direction is from test function.
    """
    def check_port(self, rule, port):
        if "-" in rule:
            ports = rule.split("-")
            return ports[0] <= str(port) and str(port) <= ports[1]
        else:
            return str(port) == rule
    
    """
    IP address: Either (a) an IPv4 address in dotted notation, consisting of 4
    octets, each an integer in the range [0, 255], separated by periods
    or (b) an IP range containing two IPv4 addresses, separated by a
    dash (no spaces). Like port ranges, IP ranges are inclusive. Given an IP
    range, you may assume that the range is well-formed i.e. when viewed as a
    number, the starting address is strictly less than the ending address.
    rule is from csv, direction is from test function.
    """
    def check_ip_address(self, rule, ip_address):
        if "-" in rule:
            ip_range = rule.split("-")
            ip = ipaddress.ip_address(ip_address)
            ip_lower_range = ipaddress.ip_address(ip_range[0])
            ip_upper_range = ipaddress.ip_address(ip_range[1])
            return ip_lower_range <= ip and ip <= ip_upper_range
        else:
            return ip_address == rule


# unit testing of host-based firewall initialized from firewall.csv
class Firewall_Test(unittest.TestCase):

    def test_sample(self):
        print("test_sample")
        self.assertTrue(firewall.accept_packet("inbound", "tcp", 80, "192.168.1.2"))
        self.assertTrue(firewall.accept_packet("outbound", "tcp", 10000, "192.168.10.11"))
        self.assertTrue(firewall.accept_packet("outbound", "tcp", 15000, "192.168.10.11"))
        self.assertTrue(firewall.accept_packet("outbound", "tcp", 20000, "192.168.10.11"))
        self.assertTrue(firewall.accept_packet("inbound", "udp", 53, "192.168.1.1"))
        self.assertTrue(firewall.accept_packet("inbound", "udp", 53, "192.168.2.0"))
        self.assertTrue(firewall.accept_packet("inbound", "udp", 53, "192.168.2.5"))
        self.assertTrue(firewall.accept_packet("outbound", "udp", 1000, "52.12.48.92"))
        self.assertTrue(firewall.accept_packet("outbound", "udp", 2000, "52.12.48.92"))

    def test_edge_cases(self):
        print("test_edge_cases")
        self.assertTrue(firewall.accept_packet("inbound", "tcp", 1, "192.168.1.2"))
        self.assertTrue(firewall.accept_packet("outbound", "tcp", 65535, "192.168.10.11"))
        self.assertTrue(firewall.accept_packet("inbound", "udp", 1, "0.0.0.0"))
        self.assertTrue(firewall.accept_packet("inbound", "udp", 1, "0.0.0.1"))
        self.assertTrue(firewall.accept_packet("inbound", "udp", 2, "0.0.0.0"))
        self.assertTrue(firewall.accept_packet("inbound", "udp", 1, "0.0.0.1"))
        self.assertTrue(firewall.accept_packet("outbound", "tcp", 65534, "255.255.255.254"))
        self.assertTrue(firewall.accept_packet("outbound", "tcp", 65534, "255.255.255.255"))
        self.assertTrue(firewall.accept_packet("outbound", "tcp", 65535, "255.255.255.254"))
        self.assertTrue(firewall.accept_packet("outbound", "tcp", 65534, "255.255.255.255"))
        self.assertTrue(firewall.accept_packet("outbound", "udp", 30000, "123.123.123.123"))
        self.assertTrue(firewall.accept_packet("inbound", "udp", 2, "0.255.0.255"))
        self.assertTrue(firewall.accept_packet("outbound", "tcp", 65534, "255.0.255.0"))

    def test_bad_rules(self):
        print("test_bad_rules")
        self.assertFalse(firewall.accept_packet("inbound", "tcp", 80, "192.168.10.11"))
        self.assertFalse(firewall.accept_packet("inbound", "tcp", 53, "192.168.1.0"))
        self.assertFalse(firewall.accept_packet("outbound", "udp", 999, "52.12.48.92"))
        self.assertFalse(firewall.accept_packet("inbound", "tcp", 1, "192.168.1.1"))
        self.assertFalse(firewall.accept_packet("inbound", "udp", 65336, "192.168.10.11"))
        self.assertFalse(firewall.accept_packet("inbound", "udp", 1, "0.0.0.2"))
        self.assertFalse(firewall.accept_packet("inbound", "udp", 123, "192.168.1.2"))


if __name__ == "__main__":
    # please change and use the correct file path on your machine to the csv input file 
    firewall = Firewall("/Users/jaychow/Documents/summer_internships/illumio/illumio-host-based-firewall/firewall.csv")
    unittest.main()
