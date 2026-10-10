class PacketFilter:
    """
    Handles packet filtering for NetScope.

    Supported searches:
    - IP address
    - protocol
    - port
    - source
    - destination
    - information text
    """

    def __init__(self, query=""):
        self.query = query.strip().lower()

    def set_query(self, query):
        self.query = query.strip().lower()

    def matches(self, packet):
        """
        Return True if the packet matches the current filter.
        """

        if not self.query:
            return True

        values = [
            self.get_value(packet, "number"),
            self.get_value(packet, "time"),
            self.get_value(packet, "source"),
            self.get_value(packet, "destination"),
            self.get_value(packet, "protocol"),
            self.get_value(packet, "length"),
            self.get_value(packet, "source_port"),
            self.get_value(packet, "destination_port"),
            self.get_value(packet, "info"),
        ]

        search_text = " ".join(values).lower()

        # ------------------------------------------------------
        # Direct text search
        # ------------------------------------------------------

        if self.query in search_text:
            return True

        # ------------------------------------------------------
        # protocol:tcp
        # protocol:dns
        # protocol:udp
        # ------------------------------------------------------

        if self.query.startswith("protocol:"):

            protocol = self.query.split(
                ":", 1
            )[1].strip()

            return (
                self.get_value(
                    packet,
                    "protocol"
                ).lower()
                == protocol
            )

        # ------------------------------------------------------
        # ip:192.168.1.10
        # ------------------------------------------------------

        if self.query.startswith("ip:"):

            ip = self.query.split(
                ":", 1
            )[1].strip()

            source = self.get_value(
                packet,
                "source"
            ).lower()

            destination = self.get_value(
                packet,
                "destination"
            ).lower()

            return (
                ip in source
                or ip in destination
            )

        # ------------------------------------------------------
        # src:192.168.1.10
        # ------------------------------------------------------

        if self.query.startswith("src:"):

            source = self.query.split(
                ":",
                1
            )[1].strip()

            return source in self.get_value(
                packet,
                "source"
            ).lower()

        # ------------------------------------------------------
        # dst:8.8.8.8
        # ------------------------------------------------------

        if self.query.startswith("dst:"):

            destination = self.query.split(
                ":",
                1
            )[1].strip()

            return destination in self.get_value(
                packet,
                "destination"
            ).lower()

        # ------------------------------------------------------
        # port:443
        # ------------------------------------------------------

        if self.query.startswith("port:"):

            port = self.query.split(
                ":",
                1
            )[1].strip()

            source_port = self.get_value(
                packet,
                "source_port"
            )

            destination_port = self.get_value(
                packet,
                "destination_port"
            )

            return (
                port == source_port
                or port == destination_port
            )

        return False

    @staticmethod
    def get_value(packet, key):
        """
        Safely retrieve a packet field.
        """

        if isinstance(packet, dict):

            value = packet.get(
                key,
                ""
            )

        else:

            value = getattr(
                packet,
                key,
                ""
            )

        if value is None:
            return ""

        return str(value)

    @staticmethod
    def filter_packets(
        packets,
        query
    ):
        """
        Filter a complete packet collection.
        """

        packet_filter = PacketFilter(
            query
        )

        return [
            packet
            for packet in packets
            if packet_filter.matches(packet)
        ]