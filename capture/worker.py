import multiprocessing as mp
import os
import queue
import signal
import time

import pyshark

from PySide6.QtCore import QThread, Signal


def _capture_process(interface, output_queue, stop_event):
    """Run PyShark in an isolated OS process.

    The process gets its own process group, so the GUI can terminate the
    entire dumpcap/tshark tree deterministically without touching PyShark's
    asyncio cleanup from the Qt thread.
    """
    try:
        if os.name == "posix":
            os.setsid()

        parser = PacketParser()
        capture = pyshark.LiveCapture(interface=interface)
        batch = []
        last_emit = time.monotonic()

        try:
            for packet in capture.sniff_continuously():
                if stop_event.is_set():
                    break

                parsed = parser.parse_packet(packet)
                if parsed:
                    batch.append(parsed)

                now = time.monotonic()
                if batch and (len(batch) >= 25 or now - last_emit >= 0.05):
                    output_queue.put(("batch", batch))
                    batch = []
                    last_emit = now

            if batch:
                output_queue.put(("batch", batch))
        finally:
            # This is deliberately best-effort. The parent process owns
            # deterministic shutdown by terminating this whole process
            # group, so we never depend on PyShark.close() returning.
            try:
                for process in list(getattr(capture, "_running_processes", set())):
                    try:
                        if process.returncode is None:
                            process.kill()
                    except Exception:
                        pass
            except Exception:
                pass

    except Exception as error:
        try:
            output_queue.put(("error", str(error)))
        except Exception:
            pass
    finally:
        try:
            output_queue.cancel_join_thread()
        except Exception:
            pass


class CaptureWorker(QThread):
    """Qt-side controller for an isolated packet-capture process."""

    packet_received = Signal(list)
    capture_started = Signal(str)
    capture_stopped = Signal()
    capture_error = Signal(str)

    def __init__(self, interface):
        super().__init__()
        self.interface = interface
        self.process = None
        self.output_queue = None
        self.stop_event = None
        self._stop_requested = False

    def run(self):
        self._stop_requested = False
        self.output_queue = mp.Queue(maxsize=100)
        self.stop_event = mp.Event()

        self.process = mp.Process(
            target=_capture_process,
            args=(self.interface, self.output_queue, self.stop_event),
            daemon=True,
        )
        self.process.start()
        self.capture_started.emit(self.interface)

        try:
            while True:
                try:
                    kind, payload = self.output_queue.get(timeout=0.1)
                    if kind == "batch":
                        self.packet_received.emit(payload)
                    elif kind == "error" and not self._stop_requested:
                        self.capture_error.emit(payload)
                except queue.Empty:
                    if self.process is None or not self.process.is_alive():
                        break

            # Drain messages that were already queued before the process died.
            while True:
                try:
                    kind, payload = self.output_queue.get_nowait()
                    if kind == "batch":
                        self.packet_received.emit(payload)
                    elif kind == "error" and not self._stop_requested:
                        self.capture_error.emit(payload)
                except queue.Empty:
                    break
        finally:
            self._terminate_process()
            try:
                if self.output_queue is not None:
                    self.output_queue.close()
            except Exception:
                pass
            self.output_queue = None
            self.stop_event = None
            self.process = None
            self.capture_stopped.emit()

    def stop_capture(self):
        self._stop_requested = True
        if self.stop_event is not None:
            self.stop_event.set()
        self._terminate_process()

    def _terminate_process(self):
        process = self.process
        if process is None:
            return

        try:
            if process.is_alive():
                pid = process.pid
                if os.name == "posix" and pid:
                    try:
                        os.killpg(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    except PermissionError:
                        process.terminate()
                else:
                    process.terminate()

                process.join(timeout=1.0)

                if process.is_alive():
                    process.kill()
                    process.join(timeout=1.0)
            else:
                process.join(timeout=0.1)
        except Exception:
            try:
                process.terminate()
            except Exception:
                pass


class PacketParser:
    """Pure packet parser used inside the capture subprocess."""

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

                # These are serializable representations of the PyShark
                # packet. The GUI process must never receive the live
                # PyShark object itself because it cannot be pickled.
                "layers": self.get_packet_layers(packet),
                "raw_details": self.get_raw_details(packet),
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

    @staticmethod
    def get_packet_layers(packet):
        layers = []
        try:
            for layer in packet.layers:
                name = getattr(layer, "layer_name", None)
                if name:
                    name = str(name).upper()
                    if name not in layers:
                        layers.append(name)
        except Exception:
            pass
        return layers

    @staticmethod
    def get_raw_details(packet):
        try:
            return str(packet.show())
        except Exception:
            return ""

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