from analyzer.filters import PacketFilter
from analyzer.statistics import PacketStatistics


class PacketStore:
    """
    Central storage for packets captured by NetScope.

    The GUI should not be responsible for managing
    the application's packet data.
    """

    def __init__(self):

        self.packets = []

        self.statistics = PacketStatistics()

        self.filter = PacketFilter()

    # ==========================================================
    # ADD PACKET
    # ==========================================================

    def add(self, packet):

        self.packets.append(
            packet
        )

        self.statistics.add_packet(
            packet
        )

    # ==========================================================
    # ADD MANY
    # ==========================================================

    def add_many(self, packets):

        for packet in packets:

            self.add(packet)

    # ==========================================================
    # GET ALL
    # ==========================================================

    def all(self):

        return list(
            self.packets
        )

    # ==========================================================
    # FILTER
    # ==========================================================

    def search(self, query):

        self.filter.set_query(
            query
        )

        return [
            packet
            for packet in self.packets
            if self.filter.matches(packet)
        ]

    # ==========================================================
    # GET STATISTICS
    # ==========================================================

    def get_statistics(self):

        return self.statistics

    # ==========================================================
    # COUNT
    # ==========================================================

    def count(self):

        return len(
            self.packets
        )

    # ==========================================================
    # CLEAR
    # ==========================================================

    def clear(self):

        self.packets.clear()

        self.statistics.reset()

        self.filter.set_query("")

    # ==========================================================
    # GET PACKET
    # ==========================================================

    def get(self, index):

        if (
            index < 0
            or index >= len(self.packets)
        ):

            return None

        return self.packets[index]

    # ==========================================================
    # EXPORT DATA
    # ==========================================================

    def as_dicts(self):

        result = []

        for packet in self.packets:

            if isinstance(
                packet,
                dict
            ):

                clean_packet = dict(
                    packet
                )

                # Raw PyShark packet should
                # never be exported directly.
                clean_packet.pop(
                    "raw_packet",
                    None
                )

                result.append(
                    clean_packet
                )

        return result