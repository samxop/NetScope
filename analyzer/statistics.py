from collections import Counter


class PacketStatistics:
    """
    Calculates statistics from captured packets.
    """

    def __init__(self):

        self.reset()

    # ==========================================================
    # RESET
    # ==========================================================

    def reset(self):

        self.total_packets = 0
        self.total_bytes = 0

        self.protocol_counts = Counter()
        self.source_counts = Counter()
        self.destination_counts = Counter()

        self.source_port_counts = Counter()
        self.destination_port_counts = Counter()

    # ==========================================================
    # ADD PACKET
    # ==========================================================

    def add_packet(self, packet):

        self.total_packets += 1

        # ------------------------------------------------------
        # Bytes
        # ------------------------------------------------------

        try:

            self.total_bytes += int(
                self.get_value(
                    packet,
                    "length"
                )
            )

        except (
            ValueError,
            TypeError
        ):

            pass

        # ------------------------------------------------------
        # Protocol
        # ------------------------------------------------------

        protocol = self.get_value(
            packet,
            "protocol"
        )

        if protocol:

            self.protocol_counts[
                protocol.upper()
            ] += 1

        # ------------------------------------------------------
        # Source IP
        # ------------------------------------------------------

        source = self.get_value(
            packet,
            "source"
        )

        if source and source != "-":

            self.source_counts[
                source
            ] += 1

        # ------------------------------------------------------
        # Destination IP
        # ------------------------------------------------------

        destination = self.get_value(
            packet,
            "destination"
        )

        if destination and destination != "-":

            self.destination_counts[
                destination
            ] += 1

        # ------------------------------------------------------
        # Source port
        # ------------------------------------------------------

        source_port = self.get_value(
            packet,
            "source_port"
        )

        if source_port and source_port != "-":

            self.source_port_counts[
                source_port
            ] += 1

        # ------------------------------------------------------
        # Destination port
        # ------------------------------------------------------

        destination_port = self.get_value(
            packet,
            "destination_port"
        )

        if (
            destination_port
            and destination_port != "-"
        ):

            self.destination_port_counts[
                destination_port
            ] += 1

    # ==========================================================
    # ADD MANY
    # ==========================================================

    def add_packets(self, packets):

        for packet in packets:

            self.add_packet(packet)

    # ==========================================================
    # PROTOCOL DISTRIBUTION
    # ==========================================================

    def protocol_distribution(self):

        return dict(
            self.protocol_counts
        )

    # ==========================================================
    # TOP SOURCE IPS
    # ==========================================================

    def top_sources(self, limit=10):

        return self.source_counts.most_common(
            limit
        )

    # ==========================================================
    # TOP DESTINATION IPS
    # ==========================================================

    def top_destinations(self, limit=10):

        return self.destination_counts.most_common(
            limit
        )

    # ==========================================================
    # TOP SOURCE PORTS
    # ==========================================================

    def top_source_ports(self, limit=10):

        return self.source_port_counts.most_common(
            limit
        )

    # ==========================================================
    # TOP DESTINATION PORTS
    # ==========================================================

    def top_destination_ports(self, limit=10):

        return self.destination_port_counts.most_common(
            limit
        )

    # ==========================================================
    # PACKETS PER SECOND
    # ==========================================================

    def packets_per_second(
        self,
        duration
    ):

        if duration <= 0:

            return 0.0

        return (
            self.total_packets
            / duration
        )

    # ==========================================================
    # BYTES PER SECOND
    # ==========================================================

    def bytes_per_second(
        self,
        duration
    ):

        if duration <= 0:

            return 0.0

        return (
            self.total_bytes
            / duration
        )

    # ==========================================================
    # SUMMARY
    # ==========================================================

    def summary(self):

        return {

            "total_packets":
                self.total_packets,

            "total_bytes":
                self.total_bytes,

            "protocols":
                self.protocol_distribution(),

            "top_sources":
                self.top_sources(),

            "top_destinations":
                self.top_destinations(),

            "top_source_ports":
                self.top_source_ports(),

            "top_destination_ports":
                self.top_destination_ports(),
        }

    # ==========================================================
    # SAFE VALUE
    # ==========================================================

    @staticmethod
    def get_value(
        packet,
        key
    ):

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