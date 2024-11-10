import pyshark
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import json
import httpx

class PcapAnalyzer:
    TCP_FLAG_MAP = {
        0x0001: 'URG',
        0x0002: 'ACK',
        0x0004: 'PSH',
        0x0010: 'RST',
        0x0020: 'SYN',
        0x0040: 'FIN',
        0x0080: 'ECE',
        0x0100: 'CWR',
        0x0200: 'NS'
    }

    def __init__(self, pcap_file,osN='',arch='',hostname='',id=''):
        self.pcap_file = pcap_file
        self.packet_count = 0
        self.ip_addresses = set()
        self.protocols = Counter()
        self.tcp_flags = Counter()
        self.ports = Counter()
        self.packet_sizes = []
        self.src_ip_counter = Counter()
        self.dst_ip_counter = Counter()
        self.application_protocols = Counter()
        self.osN = osN
        self.arch = arch
        self.hostname = hostname
        self.id = id
        self.analyze()

    def decode_tcp_flags(self, flag_value):
        """
        Decode the TCP flag value into a list of human-readable flag names.
        """
        flags = []
        for flag_mask, flag_name in self.TCP_FLAG_MAP.items():
            if flag_value & flag_mask:
                flags.append(flag_name)
        return flags

    def analyze_packet(self, packet):
        """ Analyze a single packet. """
        self.packet_count += 1
        self.packet_sizes.append(len(packet))

        if 'IP' in packet:
            self.src_ip_counter[packet.ip.src] += 1
            self.dst_ip_counter[packet.ip.dst] += 1
            self.ip_addresses.add(packet.ip.src)
            self.ip_addresses.add(packet.ip.dst)

        if hasattr(packet, 'transport_layer'):
            self.protocols[packet.transport_layer] += 1

        if 'TCP' in packet:
            self.ports[packet.tcp.srcport] += 1
            self.ports[packet.tcp.dstport] += 1
            flag_value = int(packet.tcp.flags, 16)
            flags = self.decode_tcp_flags(flag_value)
            for flag in flags:
                self.tcp_flags[flag] += 1
        elif 'UDP' in packet:
            self.ports[packet.udp.srcport] += 1
            self.ports[packet.udp.dstport] += 1
        elif 'ICMP' in packet:
            self.ports[packet.icmp.type] += 1
            self.ports[packet.icmp.code] += 1

        if 'HTTP' in packet:
            self.application_protocols['HTTP'] += 1
        elif 'DNS' in packet:
            self.application_protocols['DNS'] += 1
        elif 'SSL' in packet:
            self.application_protocols['SSL'] += 1
        elif 'SSH' in packet:
            self.application_protocols['SSH'] += 1
        elif 'FTP' in packet:
            self.application_protocols['FTP'] += 1
        elif 'SMTP' in packet:
            self.application_protocols['SMTP'] += 1
        elif 'POP' in packet:
            self.application_protocols['POP'] += 1
        elif 'IMAP' in packet:
            self.application_protocols['IMAP'] += 1
        elif 'TELNET' in packet:
            self.application_protocols['TELNET'] += 1
        elif 'SMB' in packet:
            self.application_protocols['SMB'] += 1
        elif 'DHCP' in packet:
            self.application_protocols['DHCP'] += 1
        elif 'ARP' in packet:
            self.application_protocols['ARP'] += 1
        elif 'NTP' in packet:
            self.application_protocols['NTP'] += 1
        elif 'SNMP' in packet:
            self.application_protocols['SNMP'] += 1
        elif 'LDAP' in packet:
            self.application_protocols['LDAP'] += 1
        elif 'RDP' in packet:
            self.application_protocols['RDP'] += 1
        elif 'RTP' in packet:
            self.application_protocols['RTP'] += 1
        elif 'RTCP' in packet:
            self.application_protocols['RTCP'] += 1
        elif 'QUIC' in packet:
            self.application_protocols['QUIC'] += 1

    def analyze(self):
        """ Analyze the PCAP file and gather statistics. """
        cap = pyshark.FileCapture(self.pcap_file, keep_packets=False)

        with ThreadPoolExecutor(max_workers=12) as executor:
            # Process each packet concurrently
            executor.map(self.analyze_packet, cap)

    def get_packet_count(self):
        return self.packet_count

    def get_unique_ip_count(self):
        return len(self.ip_addresses)

    def get_protocol_stats(self):
        return self.protocols

    def get_packet_size_stats(self):
        total_size = sum(self.packet_sizes)
        average_size = total_size / len(self.packet_sizes) if len(self.packet_sizes) > 0 else 0
        return total_size, average_size

    def get_top_ips(self, top_n=5):
        return {
            'source_ips': self.src_ip_counter.most_common(top_n),
            'destination_ips': self.dst_ip_counter.most_common(top_n)
        }

    def get_top_ports(self, top_n=5):
        return self.ports.most_common(top_n)

    def get_tcp_flags(self):
        return self.tcp_flags

    def get_application_protocols(self):
        return self.application_protocols

    def display_stats(self):
        print(f"Total Packets: {self.get_packet_count()}")
        print(f"Unique IP Addresses: {self.get_unique_ip_count()}")
        total_size, average_size = self.get_packet_size_stats()
        print(f"Total Data Size: {total_size} bytes")
        print(f"Average Packet Size: {average_size:.2f} bytes")

        print("\nTop 5 Source IPs:")
        for ip, count in self.get_top_ips()['source_ips']:
            print(f"{ip}: {count} packets")

        print("\nTop 5 Destination IPs:")
        for ip, count in self.get_top_ips()['destination_ips']:
            print(f"{ip}: {count} packets")

        print("\nProtocol Counts:")
        for protocol, count in self.get_protocol_stats().items():
            print(f"{protocol}: {count} packets")
        
        print("\nApplication Protocol Counts:")
        for protocol, count in self.get_application_protocols().items():
            print(f"{protocol}: {count} packets")

        print("\nTop 5 Ports:")
        for port, count in self.get_top_ports():
            print(f"Port {port}: {count} packets")

        print("\nTCP Flag Counts:")
        for flag, count in self.get_tcp_flags().items():
            print(f"Flag {flag}: {count} packets")
    
    def get_json(self):
        total_size, average_size = self.get_packet_size_stats()
        json_data = {
            "agent":{
                "os": self.osN,
                "arch": self.arch,
                "hostname": self.hostname,
                "id": self.id
            },
            "total_packets": self.get_packet_count(),
            "unique_ip_addresses": self.get_unique_ip_count(),
            "total_data_size": total_size,
            "average_packet_size": average_size,
            "top_source_ips": [{"ip": ip, "count": count} for ip, count in self.get_top_ips()['source_ips']],
            "top_destination_ips": [{"ip": ip, "count": count} for ip, count in self.get_top_ips()['destination_ips']],
            "protocol_counts": {protocol: count for protocol, count in self.get_protocol_stats().items()},
            "application_protocol_counts": {protocol: count for protocol, count in self.get_application_protocols().items()},
            "top_ports": [{"port": port, "count": count} for port, count in self.get_top_ports()],
            "tcp_flag_counts": {flag: count for flag, count in self.get_tcp_flags().items()}
        }
        return json.dumps(json_data, indent=4)

    async def send_to_elastic(self):
        json = self.get_json()
        async with httpx.AsyncClient() as client:
            response = await client.post("http://elasticsearch:9200/packets_v2/_doc", data=json, headers={"Content-Type": "application/json"})
            print(response.text)


if __name__ == "__main__":
    pcap_file = "data.pcap"
    
    analyzer = PcapAnalyzer(pcap_file)
    analyzer.display_stats()
    json_data = analyzer.get_json()
