import asyncio
import pyshark
from analyzer.packet import Packet


class PacketSniffer:
    """
    Captures live network packets using PyShark/TShark
    and converts them into our Packet model.
    """

    def __init__(self, interface="wlo1"):
        self.interface = interface
        self.capture = None
        self.packet_count = 0
        self.running = False

        self.setup_event_loop()

    # ---------------------------------------------------------
    # EVENT LOOP
    # ---------------------------------------------------------

    def setup_event_loop(self):
        """
        Create and register an asyncio event loop.

        Python 3.13 may not automatically create a current
        event loop, so we create one explicitly.
        """

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        self.event_loop = loop

    # ---------------------------------------------------------
    # START CAPTURE
    # ---------------------------------------------------------

    def start(self):
        """
        Start live packet capture.
        """

        print("=" * 60)
        print("NETWORK PACKET ANALYZER")
        print("=" * 60)
        print(f"Interface : {self.interface}")
        print("Status    : Capturing")
        print("Press Ctrl+C to stop.")
        print("=" * 60)

        self.running = True

        try:
            self.capture = pyshark.LiveCapture(
                interface=self.interface
            )

            for packet in self.capture.sniff_continuously():

                if not self.running:
                    break

                try:
                    parsed_packet = self.parse_packet(packet)

                    if parsed_packet:
                        self.packet_count += 1
                        self.display_packet(parsed_packet)

                except Exception as error:
                    print(
                        f"Packet parsing error: {error}"
                    )

        except KeyboardInterrupt:
            print("\n")
            print("Capture interrupted by user.")

        except asyncio.CancelledError:
            # PyShark can raise this while its internal async
            # task is being cancelled during shutdown.
            pass

        except Exception as error:
            print("\nCapture error:")
            print(error)

        finally:
            self.stop()

    # ---------------------------------------------------------
    # PARSE PACKET
    # ---------------------------------------------------------

    def parse_packet(self, packet):
        """
        Convert a PyShark packet into our Packet object.
        """

        timestamp = self.get_timestamp(packet)
        length = self.get_packet_length(packet)

        source = self.get_source(packet)
        destination = self.get_destination(packet)

        protocol = self.detect_protocol(packet)

        source_port = self.get_source_port(packet)
        destination_port = self.get_destination_port(packet)

        info = self.get_packet_info(packet)

        details = self.extract_details(packet)

        return Packet(
            number=self.packet_count + 1,
            timestamp=timestamp,
            length=length,
            protocol=protocol,
            source=source,
            destination=destination,
            source_port=source_port,
            destination_port=destination_port,
            info=info,
            details=details
        )

    # ---------------------------------------------------------
    # TIMESTAMP
    # ---------------------------------------------------------

    def get_timestamp(self, packet):
        """
        Extract packet timestamp.
        """

        try:
            return str(packet.sniff_time)

        except Exception:
            return ""

    # ---------------------------------------------------------
    # PACKET LENGTH
    # ---------------------------------------------------------

    def get_packet_length(self, packet):
        """
        Extract packet length in bytes.
        """

        try:
            return int(packet.length)

        except Exception:
            try:
                return int(packet.frame_info.len)

            except Exception:
                return 0

    # ---------------------------------------------------------
    # SOURCE IP
    # ---------------------------------------------------------

    def get_source(self, packet):
        """
        Extract source IPv4/IPv6 address.
        """

        try:
            if hasattr(packet, "ip"):
                return packet.ip.src

        except Exception:
            pass

        try:
            if hasattr(packet, "ipv6"):
                return packet.ipv6.src

        except Exception:
            pass

        try:
            if hasattr(packet, "arp"):
                return packet.arp.src_proto_ipv4

        except Exception:
            pass

        try:
            if hasattr(packet, "eth"):
                return packet.eth.src

        except Exception:
            pass

        return "Unknown"

    # ---------------------------------------------------------
    # DESTINATION IP
    # ---------------------------------------------------------

    def get_destination(self, packet):
        """
        Extract destination IPv4/IPv6 address.
        """

        try:
            if hasattr(packet, "ip"):
                return packet.ip.dst

        except Exception:
            pass

        try:
            if hasattr(packet, "ipv6"):
                return packet.ipv6.dst

        except Exception:
            pass

        try:
            if hasattr(packet, "arp"):
                return packet.arp.dst_proto_ipv4

        except Exception:
            pass

        try:
            if hasattr(packet, "eth"):
                return packet.eth.dst

        except Exception:
            pass

        return "Unknown"

    # ---------------------------------------------------------
    # PROTOCOL DETECTION
    # ---------------------------------------------------------

    def detect_protocol(self, packet):
        """
        Detect the most useful protocol represented by
        the captured packet.
        """

        # Application protocols first
        try:
            if hasattr(packet, "dns"):
                return "DNS"
        except Exception:
            pass

        try:
            if hasattr(packet, "http"):
                return "HTTP"
        except Exception:
            pass

        try:
            if hasattr(packet, "tls"):
                return "TLS"
        except Exception:
            pass

        try:
            if hasattr(packet, "ssh"):
                return "SSH"
        except Exception:
            pass

        try:
            if hasattr(packet, "dhcp"):
                return "DHCP"
        except Exception:
            pass

        try:
            if hasattr(packet, "bootp"):
                return "DHCP"
        except Exception:
            pass

        # Network protocols
        try:
            if hasattr(packet, "icmp"):
                return "ICMP"
        except Exception:
            pass

        try:
            if hasattr(packet, "icmpv6"):
                return "ICMPv6"
        except Exception:
            pass

        try:
            if hasattr(packet, "arp"):
                return "ARP"
        except Exception:
            pass

        # Transport protocols
        try:
            if hasattr(packet, "tcp"):
                return "TCP"
        except Exception:
            pass

        try:
            if hasattr(packet, "udp"):
                return "UDP"
        except Exception:
            pass

        # IP
        try:
            if hasattr(packet, "ipv6"):
                return "IPv6"
        except Exception:
            pass

        try:
            if hasattr(packet, "ip"):
                return "IPv4"
        except Exception:
            pass

        # Ethernet fallback
        try:
            if hasattr(packet, "eth"):
                return "Ethernet"
        except Exception:
            pass

        return "Unknown"

    # ---------------------------------------------------------
    # SOURCE PORT
    # ---------------------------------------------------------

    def get_source_port(self, packet):
        """
        Extract TCP/UDP source port.
        """

        try:
            if hasattr(packet, "tcp"):
                return self.safe_int(packet.tcp.srcport)

        except Exception:
            pass

        try:
            if hasattr(packet, "udp"):
                return self.safe_int(packet.udp.srcport)

        except Exception:
            pass

        return None

    # ---------------------------------------------------------
    # DESTINATION PORT
    # ---------------------------------------------------------

    def get_destination_port(self, packet):
        """
        Extract TCP/UDP destination port.
        """

        try:
            if hasattr(packet, "tcp"):
                return self.safe_int(packet.tcp.dstport)

        except Exception:
            pass

        try:
            if hasattr(packet, "udp"):
                return self.safe_int(packet.udp.dstport)

        except Exception:
            pass

        return None

    # ---------------------------------------------------------
    # PACKET INFORMATION
    # ---------------------------------------------------------

    def get_packet_info(self, packet):
        """
        Generate a human-readable packet description.
        """

        protocol = self.detect_protocol(packet)

        # DNS
        try:
            if hasattr(packet, "dns"):

                if hasattr(packet.dns, "qry_name"):
                    return f"DNS query: {packet.dns.qry_name}"

                return "DNS packet"

        except Exception:
            pass

        # HTTP
        try:
            if hasattr(packet, "http"):

                if hasattr(packet.http, "request_method"):

                    method = packet.http.request_method

                    if hasattr(packet.http, "host"):
                        return (
                            f"HTTP {method} "
                            f"{packet.http.host}"
                        )

                    return f"HTTP {method}"

                return "HTTP packet"

        except Exception:
            pass

        # TLS
        try:
            if hasattr(packet, "tls"):
                return "TLS encrypted traffic"

        except Exception:
            pass

        # SSH
        try:
            if hasattr(packet, "ssh"):
                return "SSH traffic"

        except Exception:
            pass

        # DHCP
        try:
            if hasattr(packet, "dhcp") or hasattr(packet, "bootp"):
                return "DHCP packet"

        except Exception:
            pass

        # TCP
        if protocol == "TCP":
            flags = self.get_tcp_flags(packet)

            if flags:
                return f"TCP [{flags}]"

            return "TCP packet"

        # UDP
        if protocol == "UDP":
            return "UDP packet"

        # ICMP
        if protocol in ("ICMP", "ICMPv6"):
            return f"{protocol} packet"

        # ARP
        if protocol == "ARP":
            return "ARP packet"

        return f"{protocol} packet"

    # ---------------------------------------------------------
    # TCP FLAGS
    # ---------------------------------------------------------

    def get_tcp_flags(self, packet):
        """
        Extract TCP flags.
        """

        try:
            tcp = packet.tcp

            flags = []

            if hasattr(tcp, "flags_syn") and tcp.flags_syn == "1":
                flags.append("SYN")

            if hasattr(tcp, "flags_ack") and tcp.flags_ack == "1":
                flags.append("ACK")

            if hasattr(tcp, "flags_fin") and tcp.flags_fin == "1":
                flags.append("FIN")

            if hasattr(tcp, "flags_rst") and tcp.flags_rst == "1":
                flags.append("RST")

            if hasattr(tcp, "flags_psh") and tcp.flags_psh == "1":
                flags.append("PSH")

            if hasattr(tcp, "flags_urg") and tcp.flags_urg == "1":
                flags.append("URG")

            return ", ".join(flags)

        except Exception:
            return ""

    # ---------------------------------------------------------
    # PACKET DETAILS
    # ---------------------------------------------------------

    def extract_details(self, packet):
        """
        Extract detailed information from all available
        protocol layers.
        """

        details = {}

        try:
            details["layers"] = [
                layer.layer_name
                for layer in packet.layers
            ]

        except Exception:
            details["layers"] = []

        # Ethernet
        try:
            if hasattr(packet, "eth"):

                details["ethernet"] = {
                    "source": getattr(
                        packet.eth,
                        "src",
                        "Unknown"
                    ),
                    "destination": getattr(
                        packet.eth,
                        "dst",
                        "Unknown"
                    ),
                    "type": getattr(
                        packet.eth,
                        "type",
                        "Unknown"
                    )
                }

        except Exception:
            pass

        # IPv4
        try:
            if hasattr(packet, "ip"):

                details["ipv4"] = {
                    "source": packet.ip.src,
                    "destination": packet.ip.dst,
                    "ttl": getattr(
                        packet.ip,
                        "ttl",
                        "Unknown"
                    ),
                    "protocol": getattr(
                        packet.ip,
                        "proto",
                        "Unknown"
                    )
                }

        except Exception:
            pass

        # IPv6
        try:
            if hasattr(packet, "ipv6"):

                details["ipv6"] = {
                    "source": packet.ipv6.src,
                    "destination": packet.ipv6.dst,
                    "hop_limit": getattr(
                        packet.ipv6,
                        "hlim",
                        "Unknown"
                    )
                }

        except Exception:
            pass

        # TCP
        try:
            if hasattr(packet, "tcp"):

                details["tcp"] = {
                    "source_port": getattr(
                        packet.tcp,
                        "srcport",
                        "Unknown"
                    ),
                    "destination_port": getattr(
                        packet.tcp,
                        "dstport",
                        "Unknown"
                    ),
                    "sequence": getattr(
                        packet.tcp,
                        "seq",
                        "Unknown"
                    ),
                    "acknowledgment": getattr(
                        packet.tcp,
                        "ack",
                        "Unknown"
                    ),
                    "flags": self.get_tcp_flags(packet)
                }

        except Exception:
            pass

        # UDP
        try:
            if hasattr(packet, "udp"):

                details["udp"] = {
                    "source_port": getattr(
                        packet.udp,
                        "srcport",
                        "Unknown"
                    ),
                    "destination_port": getattr(
                        packet.udp,
                        "dstport",
                        "Unknown"
                    ),
                    "length": getattr(
                        packet.udp,
                        "length",
                        "Unknown"
                    )
                }

        except Exception:
            pass

        # ICMP
        try:
            if hasattr(packet, "icmp"):

                details["icmp"] = {
                    "type": getattr(
                        packet.icmp,
                        "type",
                        "Unknown"
                    ),
                    "code": getattr(
                        packet.icmp,
                        "code",
                        "Unknown"
                    )
                }

        except Exception:
            pass

        return details

    # ---------------------------------------------------------
    # SAFE INTEGER
    # ---------------------------------------------------------

    def safe_int(self, value):
        """
        Safely convert a value to integer.
        """

        try:
            return int(value)

        except (ValueError, TypeError):
            return None

    # ---------------------------------------------------------
    # DISPLAY PACKET
    # ---------------------------------------------------------

    def display_packet(self, packet):
        """
        Display a packet in the terminal.
        """

        source = packet.source

        if packet.has_ports():
            source = (
                f"{packet.source}:"
                f"{packet.source_port}"
            )

        destination = packet.destination

        if packet.has_ports():
            destination = (
                f"{packet.destination}:"
                f"{packet.destination_port}"
            )

        print(
            f"{packet.number:>3} | "
            f"{packet.timestamp} | "
            f"{source:<25} → "
            f"{destination:<25} | "
            f"{packet.protocol:<8} | "
            f"{packet.length:>5} bytes | "
            f"{packet.info}"
        )

    # ---------------------------------------------------------
    # STOP CAPTURE
    # ---------------------------------------------------------

    def stop(self):
        """
        Stop packet capture and clean up PyShark/TShark.
        """

        if not self.running and self.capture is None:
            return

        self.running = False

        if self.capture is not None:

            try:
                self.capture.close()

            except Exception:
                pass

            self.capture = None

        print("\nCapture stopped.")
        print(
            f"Total packets captured: "
            f"{self.packet_count}"
        )


# =============================================================
# MAIN
# =============================================================

if __name__ == "__main__":

    INTERFACE = "wlo1"

    sniffer = PacketSniffer(
        interface=INTERFACE
    )

    sniffer.start()