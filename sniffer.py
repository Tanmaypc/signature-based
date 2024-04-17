from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw


def extract_packet_data(pcap_file, save_payload=False, payload_threshold=1024):
    """
  Extracts relevant data from a PCAP file and stores it in a list of dictionaries.
  Optionally saves captured packet payloads based on conditions.

  Args:
      pcap_file: Path to the PCAP file.
      save_payload: Boolean flag to enable payload storage (default: False).
      payload_threshold: Maximum payload size to save (default: 1024 bytes).

  Returns:
      A list of dictionaries containing extracted data for each packet.
  """
    packets = rdpcap(pcap_file)
    extracted_data = []

    for packet in packets:
        data = {}

        # Extract basic header information (source/destination IP, protocol)
        if packet.haslayer(IP):
            data["source_ip"] = packet[IP].src
            data["destination_ip"] = packet[IP].dst
            data["protocol"] = packet[IP].proto

        # Access packet payload (if applicable)
        if packet.haslayer(Raw):
            data["payload"] = packet[Raw].load.hex()  # Convert payload to hex string

            if save_payload:
                # Conditionally save payload based on criteria (e.g., signature match)
                if len(packet[Raw].load) <= payload_threshold:
                    data["full_payload"] = packet[Raw].load  # Save complete payload if within limit

        # Extract data from specific layers (e.g., TCP ports, flags)
        if packet.haslayer(TCP):
            data["source_port"] = packet[TCP].sport
            data["destination_port"] = packet[TCP].dport
            data["flags"] = packet[TCP].flags  # Capture TCP flags as a string

        # You can add more data extraction based on your needs (e.g., timestamps)
        extracted_data.append(data)

    return extracted_data


if __name__ == "__main__":
    # Example usage with payload storage enabled
    pcap_file = "captured_traffic.pcap"
    save_payload = True  # Enable payload storage
    payload_threshold = 1024  # Save payloads up to 1024 bytes
    extracted_data = extract_packet_data(pcap_file, save_payload, payload_threshold)

    # Print or store the extracted data (with optional payload)
    print(extracted_data[11])


