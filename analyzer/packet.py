from dataclasses import dataclass, field
from typing import Optional, Dict, Any


@dataclass
class Packet:
    """
    Represents a single captured network packet.

    This is the internal packet model used by our application.
    PyShark packets will be converted into this structure so that
    the rest of the application does not depend directly on PyShark.
    """

    # ---------------------------------------------------------
    # Basic packet information
    # ---------------------------------------------------------

    number: int
    timestamp: str
    length: int

    # ---------------------------------------------------------
    # Network information
    # ---------------------------------------------------------

    protocol: str

    source: str
    destination: str

    # ---------------------------------------------------------
    # Transport layer information
    # ---------------------------------------------------------

    source_port: Optional[int] = None
    destination_port: Optional[int] = None

    # ---------------------------------------------------------
    # Human-readable packet information
    # ---------------------------------------------------------

    info: str = ""

    # ---------------------------------------------------------
    # Additional packet information
    # ---------------------------------------------------------

    details: Dict[str, Any] = field(default_factory=dict)

    # ---------------------------------------------------------
    # Utility methods
    # ---------------------------------------------------------

    def has_ports(self) -> bool:
        """
        Returns True if the packet contains source and
        destination port information.
        """

        return (
            self.source_port is not None
            and self.destination_port is not None
        )

    def is_tcp(self) -> bool:
        """Return True if the packet uses TCP."""

        return self.protocol.upper() == "TCP"

    def is_udp(self) -> bool:
        """Return True if the packet uses UDP."""

        return self.protocol.upper() == "UDP"

    def is_icmp(self) -> bool:
        """Return True if the packet uses ICMP."""

        return self.protocol.upper() == "ICMP"

    def is_dns(self) -> bool:
        """Return True if the packet is DNS traffic."""

        return self.protocol.upper() == "DNS"

    def is_http(self) -> bool:
        """Return True if the packet is HTTP traffic."""

        return self.protocol.upper() == "HTTP"

    def is_https(self) -> bool:
        """
        Return True if the packet is HTTPS/TLS traffic.
        """

        return self.protocol.upper() in {
            "HTTPS",
            "TLS",
        }

    def is_arp(self) -> bool:
        """Return True if the packet is ARP traffic."""

        return self.protocol.upper() == "ARP"

    # ---------------------------------------------------------
    # Display helpers
    # ---------------------------------------------------------

    def get_connection(self) -> str:
        """
        Return a human-readable source → destination connection.
        """

        if self.has_ports():
            return (
                f"{self.source}:{self.source_port} "
                f"→ "
                f"{self.destination}:{self.destination_port}"
            )

        return f"{self.source} → {self.destination}"

    def get_summary(self) -> str:
        """
        Return a short human-readable packet summary.
        """

        return (
            f"{self.protocol} | "
            f"{self.source} → {self.destination} | "
            f"{self.length} bytes"
        )

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the Packet object into a dictionary.

        This will be useful later for:
        - CSV export
        - JSON storage
        - GUI tables
        - Searching/filtering
        """

        return {
            "number": self.number,
            "timestamp": self.timestamp,
            "length": self.length,
            "protocol": self.protocol,
            "source": self.source,
            "destination": self.destination,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "info": self.info,
            "details": self.details,
        }

    def __str__(self) -> str:
        """
        Define how the packet is displayed when using print(packet).
        """

        return (
            f"[{self.number}] "
            f"{self.timestamp} | "
            f"{self.protocol:<8} | "
            f"{self.source} → {self.destination} | "
            f"{self.length} bytes"
        )