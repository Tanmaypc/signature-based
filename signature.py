from scapy.layers.inet import IP, ICMP, TCP
from scapy.layers.l2 import Ether

from helper import switch_directions, equality_check


class Signature:
    """
    Represents a network traffic signature or rule.
    """

    def __init__(self, obj):
        """
        Initialize a Signature object.

        Args:
            obj: An Ethernet packet (Ether object) or a string representation of a signature.
        """
        if isinstance(obj, Ether):
            # Initialize from Ethernet packet
            direction = '->'
            s_id = '-1'
            if IP in obj:
                try:
                    proto = obj[2].name
                    src_ip = str(obj[1].src)
                    src_port = str(obj[1].sport)
                    dst_ip = str(obj[1].dst)
                    dst_port = str(obj[1].dport)
                    payload = '*'
                except (AttributeError, IndexError):
                    raise ValueError("Invalid Ethernet packet format")
            else:
                raise ValueError("Ethernet packet does not contain IP layer")
        elif isinstance(obj, str):
            # Initialize from string representation
            string = obj.split(' ')
            if len(string) == 5:
                s_id = ''
                proto = string[0]
                src_ip, src_port = string[1].split(':')
                direction = string[2]
                dst_ip, dst_port = string[3].split(':')
                payload = string[4]
            elif len(string) == 6:
                s_id = string[0].split(':')[0]
                proto = string[1]
                src_ip, src_port = string[2].split(':')
                direction = string[3]
                dst_ip, dst_port = string[4].split(':')
                payload = string[5]
            else:
                raise ValueError("Invalid string representation format")
        else:
            raise ValueError("Invalid object type")

        # Set object attributes
        self.s_id = s_id
        self.proto = proto
        self.src_ip = src_ip
        self.src_port = src_port
        self.dir = direction
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.payload = payload

    def __str__(self):
        """
        Return a string representation of the Signature object.
        """
        return f"{self.proto} {self.src_ip}:{self.src_port} {self.dir} {self.dst_ip}:{self.dst_port} {self.payload}"

    def __repr__(self):
        """
        Return a representation of the Signature object.
        """
        return f"rule {self.s_id}: {self.__str__()}"

    def __eq__(self, other):
        """
        Compare two Signature objects for equality.

        Args:
            other: Another Signature object.

        Returns:
            bool: True if the objects are equal, False otherwise.
        """
        if isinstance(self, other.__class__):
            if other.dir == '<>':
                dir_a, dir_b = switch_directions(other)
                return self.__eq__(dir_a) or self.__eq__(dir_b)

            # Check equality for each attribute
            if other.proto != 'any' and equality_check(other.proto, self.proto):
                return False
            if other.src_ip != 'any' and equality_check(other.src_ip, self.src_ip):
                return False
            if other.src_port != 'any' and equality_check(other.src_port, self.src_port, False):
                return False
            if other.dst_ip != 'any' and equality_check(other.dst_ip, self.dst_ip):
                return False
            if other.dst_port != 'any' and equality_check(other.dst_port, self.dst_port, False):
                return False
            if other.payload != 'any' and self.payload != other.payload:
                return False
            return True
        else:
            return False


if __name__ == "__main__":
    # Define an Ethernet packet

    # Define an Ethernet packet with TCP
    eth_packet = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:AA:BB") / IP(src="192.168.1.1", dst="8.8.8.8") / TCP(
        sport=12345, dport=80)

    # Create a Signature object from the Ethernet packet
    signature_from_packet = Signature(eth_packet)
    print("Signature from packet:", signature_from_packet)

    # Define a string representation of a signature
    signature_str = "TCP 192.168.1.2:8080 -> 10.0.0.1:80 *"

    # Create a Signature object from the string representation
    signature_from_str = Signature(signature_str)
    print("Signature from string:", signature_from_str)

    # Compare two Signature objects for equality
    signature1 = Signature("UDP 192.168.1.1:any -> 8.8.8.8:53 *")
    signature2 = Signature("UDP 192.168.1.1:any -> 8.8.8.8:53 *")
    signature3 = Signature("UDP 192.168.1.1:any -> 8.8.8.8:80 *")

    print("Equality check 1:", signature1 == signature_from_packet)  # Output: True (signatures are equivalent)
    print("Equality check 2:", signature1 == signature3)  # Output: False (signatures are not equivalent)
