import asyncio
import time

import pyshark

from PySide6.QtCore import QThread, Signal


class CaptureWorker(QThread):
    """
    Background worker responsible for live packet capture.

    Packet capture runs in a separate QThread so the GUI
    remains responsive.
    """

    packet_received = Signal(dict)
    capture_started = Signal(str)
    capture_stopped = Signal()
    capture_error = Signal(str)

    def __init__(self, interface):
        super().__init__()

        self.interface = interface
        self.capture = None
        self._stop_requested = False

    # =========================================================
    # CAPTURE
    # =========================================================

    def run(self):

        self._stop_requested = False

        try:

            self.capture = pyshark.LiveCapture(
                interface=self.interface
            )

            self.capture_started.emit(
                self.interface
            )

            for packet in self.capture.sniff_continuously():

                if self._stop_requested:
                    break

                try:

                    parsed_packet = self.parse_packet(packet)

                    if parsed_packet:
                        self.packet_received.emit(
                            parsed_packet
                        )

                except Exception as error:

                    print(
                        f"Packet parsing error: {error}"
                    )

        except asyncio.CancelledError:
            pass

        except KeyboardInterrupt:
            pass

        except Exception as error:

            if not self._stop_requested:

                self.capture_error.emit(
                    str(error)
                )

        finally:

            self.close_capture()

            self.capture_stopped.emit()

    # =========================================================
    # STOP CAPTURE
    # =========================================================

    def stop_capture(self):

        self._stop_requested = True

        self.close_capture()

    def close_capture(self):

        if self.capture is not None:

            try:
                self.capture.close()

            except Exception:
                pass

            self.capture = None

    # =========================================================
    # PACKET PARSING
    # =========================================================

    def parse_packet(self, packet):

        try:

            # -------------------------------------------------
            # PACKET NUMBER
            # -------------------------------------------------

            number = self.get_frame_value(
                packet,
                "number",
                "-"
            )

            # -------------------------------------------------
            # TIMESTAMP
            # -------------------------------------------------

            timestamp = self.get_timestamp(
                packet
            )

            # -------------------------------------------------
            # PACKET LENGTH
            # -------------------------------------------------

            length = self.get_frame_value(
                packet,
                "len",
                "0"
            )

            # -------------------------------------------------
            # SOURCE / DESTINATION
            # -------------------------------------------------

            source = "-"
            destination = "-"

            # IPv4
            if hasattr(packet, "ip"):

                source = self.safe_get(
                    packet,
                    "ip",
                    "src",
                    "-"
                )

                destination = self.safe_get(
                    packet,
                    "ip",
                    "dst",
                    "-"
                )

            # IPv6
            elif hasattr(packet, "ipv6"):

                source = self.safe_get(
                    packet,
                    "ipv6",
                    "src",
                    "-"
                )

                destination = self.safe_get(
                    packet,
                    "ipv6",
                    "dst",
                    "-"
                )

            # ARP
            elif hasattr(packet, "arp"):

                source = self.safe_get(
                    packet,
                    "arp",
                    "src_proto_ipv4",
                    "-"
                )

                destination = self.safe_get(
                    packet,
                    "arp",
                    "dst_proto_ipv4",
                    "-"
                )

            # -------------------------------------------------
            # PORTS
            # -------------------------------------------------

            source_port = "-"
            destination_port = "-"

            # TCP
            if hasattr(packet, "tcp"):

                source_port = self.safe_get(
                    packet,
                    "tcp",
                    "srcport",
                    "-"
                )

                destination_port = self.safe_get(
                    packet,
                    "tcp",
                    "dstport",
                    "-"
                )

            # UDP
            elif hasattr(packet, "udp"):

                source_port = self.safe_get(
                    packet,
                    "udp",
                    "srcport",
                    "-"
                )

                destination_port = self.safe_get(
                    packet,
                    "udp",
                    "dstport",
                    "-"
                )

            # -------------------------------------------------
            # PROTOCOL
            # -------------------------------------------------

            protocol = self.detect_protocol(
                packet
            )

            # -------------------------------------------------
            # INFORMATION
            # -------------------------------------------------

            info = self.get_packet_info(
                packet,
                protocol
            )

            return {

                "number": str(number),

                "time": timestamp,

                "source": str(source),

                "destination": str(destination),

                "protocol": protocol,

                "length": str(length),

                "source_port": str(source_port),

                "destination_port": str(destination_port),

                "info": info,

                "raw_packet": packet,
            }

        except Exception as error:

            print(
                f"Unable to parse packet: {error}"
            )

            return None

    # =========================================================
    # PROTOCOL DETECTION
    # =========================================================

    def detect_protocol(self, packet):

        if hasattr(packet, "dns"):
            return "DNS"

        if hasattr(packet, "http"):
            return "HTTP"

        if hasattr(packet, "tls"):
            return "TLS"

        if hasattr(packet, "ssh"):
            return "SSH"

        if hasattr(packet, "dhcp"):
            return "DHCP"

        if hasattr(packet, "bootp"):
            return "DHCP"

        if hasattr(packet, "arp"):
            return "ARP"

        if hasattr(packet, "icmp"):
            return "ICMP"

        if hasattr(packet, "icmpv6"):
            return "ICMPv6"

        if hasattr(packet, "tcp"):
            return "TCP"

        if hasattr(packet, "udp"):
            return "UDP"

        if hasattr(packet, "ipv6"):
            return "IPv6"

        if hasattr(packet, "ip"):
            return "IPv4"

        if hasattr(packet, "eth"):
            return "Ethernet"

        return "Other"

    # =========================================================
    # PACKET INFORMATION
    # =========================================================

    def get_packet_info(
        self,
        packet,
        protocol
    ):

        try:

            # -------------------------------------------------
            # DNS
            # -------------------------------------------------

            if protocol == "DNS":

                query_name = self.safe_get(
                    packet,
                    "dns",
                    "qry_name",
                    ""
                )

                if query_name:
                    return f"DNS query: {query_name}"

                response_name = self.safe_get(
                    packet,
                    "dns",
                    "resp_name",
                    ""
                )

                if response_name:
                    return f"DNS response: {response_name}"

                return "DNS traffic"

            # -------------------------------------------------
            # HTTP
            # -------------------------------------------------

            if protocol == "HTTP":

                host = self.safe_get(
                    packet,
                    "http",
                    "host",
                    ""
                )

                request_uri = self.safe_get(
                    packet,
                    "http",
                    "request_uri",
                    ""
                )

                if host:

                    return (
                        f"HTTP {host}"
                        f"{request_uri}"
                    )

                return "HTTP traffic"

            # -------------------------------------------------
            # TLS / HTTPS
            # -------------------------------------------------

            if protocol == "TLS":

                server_name = self.safe_get(
                    packet,
                    "tls",
                    "handshake_extensions_server_name",
                    ""
                )

                if server_name:

                    return (
                        f"TLS → {server_name}"
                    )

                return "TLS traffic"

            # -------------------------------------------------
            # SSH
            # -------------------------------------------------

            if protocol == "SSH":

                return "SSH traffic"

            # -------------------------------------------------
            # DHCP
            # -------------------------------------------------

            if protocol == "DHCP":

                return "DHCP traffic"

            # -------------------------------------------------
            # ARP
            # -------------------------------------------------

            if protocol == "ARP":

                operation = self.safe_get(
                    packet,
                    "arp",
                    "opcode",
                    ""
                )

                if operation == "1":
                    return "ARP request"

                if operation == "2":
                    return "ARP reply"

                return "ARP traffic"

            # -------------------------------------------------
            # ICMP
            # -------------------------------------------------

            if protocol == "ICMP":

                icmp_type = self.safe_get(
                    packet,
                    "icmp",
                    "type",
                    ""
                )

                if icmp_type == "8":
                    return "Echo request"

                if icmp_type == "0":
                    return "Echo reply"

                if icmp_type:

                    return (
                        f"ICMP type {icmp_type}"
                    )

                return "ICMP traffic"

            # -------------------------------------------------
            # ICMPv6
            # -------------------------------------------------

            if protocol == "ICMPv6":

                return "ICMPv6 traffic"

            # -------------------------------------------------
            # TCP
            # -------------------------------------------------

            if protocol == "TCP":

                flags = self.safe_get(
                    packet,
                    "tcp",
                    "flags",
                    ""
                )

                if flags:

                    return (
                        f"TCP flags: {flags}"
                    )

                return "TCP traffic"

            # -------------------------------------------------
            # UDP
            # -------------------------------------------------

            if protocol == "UDP":

                return "UDP traffic"

            return protocol

        except Exception:

            return protocol

    # =========================================================
    # SAFE FIELD ACCESS
    # =========================================================

    @staticmethod
    def safe_get(
        packet,
        layer_name,
        field_name,
        default="-"
    ):

        try:

            layer = getattr(
                packet,
                layer_name
            )

            value = getattr(
                layer,
                field_name
            )

            if value is None:
                return default

            return str(value)

        except Exception:

            return default

    # =========================================================
    # FRAME INFORMATION
    # =========================================================

    @staticmethod
    def get_frame_value(
        packet,
        field_name,
        default="-"
    ):
        """
        Retrieve frame information from PyShark.

        Different TShark/PyShark versions may expose
        frame fields slightly differently, so we try
        multiple locations.
        """

        # -----------------------------------------------------
        # Try frame_info
        # -----------------------------------------------------

        try:

            frame_info = packet.frame_info

            value = getattr(
                frame_info,
                field_name
            )

            if value is not None:

                return str(value)

        except Exception:
            pass

        # -----------------------------------------------------
        # Try frame
        # -----------------------------------------------------

        try:

            frame = packet.frame

            value = getattr(
                frame,
                field_name
            )

            if value is not None:

                return str(value)

        except Exception:
            pass

        # -----------------------------------------------------
        # Try packet directly
        # -----------------------------------------------------

        try:

            value = getattr(
                packet,
                field_name
            )

            if value is not None:

                return str(value)

        except Exception:
            pass

        return default

    # =========================================================
    # TIMESTAMP
    # =========================================================

    @staticmethod
    def get_timestamp(packet):

        try:

            timestamp = packet.sniff_time

            return timestamp.strftime(
                "%H:%M:%S.%f"
            )[:-3]

        except Exception:

            return time.strftime(
                "%H:%M:%S"
            )