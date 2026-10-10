import re
import socket
import time

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
    QHeaderView,
)

from analyzer.packet_store import PacketStore
from capture.worker import CaptureWorker


class MainWindow(QMainWindow):

    def __init__(self):
        super().__init__()

        self.setWindowTitle(
            "NetScope — Network Packet Analyzer"
        )

        self.resize(1650, 950)

        # -----------------------------------------------------
        # APPLICATION DATA
        # -----------------------------------------------------

        self.packet_store = PacketStore()
        self.worker = None

        self.capture_start_time = None

        # -----------------------------------------------------
        # BUILD UI
        # -----------------------------------------------------

        self.build_ui()
        self.apply_styles()
        self.load_interfaces()

    # =========================================================
    # BUILD USER INTERFACE
    # =========================================================

    def build_ui(self):

        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        main_layout = QVBoxLayout(
            central_widget
        )

        main_layout.setContentsMargins(
            25,
            22,
            25,
            10
        )

        main_layout.setSpacing(14)

        # =====================================================
        # HEADER
        # =====================================================

        header_layout = QHBoxLayout()

        title_layout = QVBoxLayout()

        title = QLabel("NetScope")

        title.setObjectName(
            "titleLabel"
        )

        subtitle = QLabel(
            "Real-time network packet analyzer"
        )

        subtitle.setObjectName(
            "subtitleLabel"
        )

        title_layout.addWidget(title)
        title_layout.addWidget(subtitle)

        header_layout.addLayout(
            title_layout
        )

        header_layout.addStretch()

        self.status_indicator = QLabel(
            "● READY"
        )

        self.status_indicator.setObjectName(
            "readyStatus"
        )

        header_layout.addWidget(
            self.status_indicator
        )

        main_layout.addLayout(
            header_layout
        )

        # =====================================================
        # CONTROL BAR
        # =====================================================

        control_frame = QFrame()

        control_frame.setObjectName(
            "controlFrame"
        )

        control_layout = QHBoxLayout(
            control_frame
        )

        control_layout.setContentsMargins(
            14,
            12,
            14,
            12
        )

        # -----------------------------------------------------
        # INTERFACE
        # -----------------------------------------------------

        interface_label = QLabel(
            "Interface"
        )

        interface_label.setObjectName(
            "controlLabel"
        )

        self.interface_combo = QComboBox()

        self.interface_combo.setMinimumWidth(
            190
        )

        control_layout.addWidget(
            interface_label
        )

        control_layout.addWidget(
            self.interface_combo
        )

        # -----------------------------------------------------
        # START
        # -----------------------------------------------------

        self.start_button = QPushButton(
            "▶  Start Capture"
        )

        self.start_button.setObjectName(
            "startButton"
        )

        self.start_button.clicked.connect(
            self.start_capture
        )

        control_layout.addWidget(
            self.start_button
        )

        # -----------------------------------------------------
        # STOP
        # -----------------------------------------------------

        self.stop_button = QPushButton(
            "■  Stop"
        )

        self.stop_button.setObjectName(
            "stopButton"
        )

        self.stop_button.clicked.connect(
            self.stop_capture
        )

        self.stop_button.setEnabled(
            False
        )

        control_layout.addWidget(
            self.stop_button
        )

        # -----------------------------------------------------
        # CLEAR
        # -----------------------------------------------------

        self.clear_button = QPushButton(
            "Clear"
        )

        self.clear_button.clicked.connect(
            self.clear_packets
        )

        control_layout.addWidget(
            self.clear_button
        )

        # -----------------------------------------------------
        # SEARCH
        # -----------------------------------------------------

        control_layout.addStretch()

        search_label = QLabel(
            "Search"
        )

        search_label.setObjectName(
            "controlLabel"
        )

        self.search_box = QLineEdit()

        self.search_box.setPlaceholderText(
            "IP, protocol, port, source, destination..."
        )

        self.search_box.setMinimumWidth(
            440
        )

        self.search_box.textChanged.connect(
            self.filter_packets
        )

        control_layout.addWidget(
            search_label
        )

        control_layout.addWidget(
            self.search_box
        )

        main_layout.addWidget(
            control_frame
        )

        # =====================================================
        # STATISTICS CARDS
        # =====================================================

        stats_layout = QGridLayout()

        stats_layout.setSpacing(12)

        self.packet_card = self.create_stat_card(
            "PACKETS",
            "0"
        )

        self.data_card = self.create_stat_card(
            "DATA",
            "0 B"
        )

        self.tcp_card = self.create_stat_card(
            "TCP",
            "0"
        )

        self.udp_card = self.create_stat_card(
            "UDP",
            "0"
        )

        self.dns_card = self.create_stat_card(
            "DNS",
            "0"
        )

        self.other_card = self.create_stat_card(
            "OTHER",
            "0"
        )

        stats_layout.addWidget(
            self.packet_card,
            0,
            0
        )

        stats_layout.addWidget(
            self.data_card,
            0,
            1
        )

        stats_layout.addWidget(
            self.tcp_card,
            0,
            2
        )

        stats_layout.addWidget(
            self.udp_card,
            0,
            3
        )

        stats_layout.addWidget(
            self.dns_card,
            0,
            4
        )

        stats_layout.addWidget(
            self.other_card,
            0,
            5
        )

        main_layout.addLayout(
            stats_layout
        )

        # =====================================================
        # PACKET TABLE
        # =====================================================

        self.packet_table = QTableWidget()

        self.packet_table.setColumnCount(
            9
        )

        self.packet_table.setHorizontalHeaderLabels(
            [
                "#",
                "Time",
                "Source",
                "Destination",
                "Protocol",
                "Length",
                "Source Port",
                "Destination Port",
                "Info",
            ]
        )

        self.packet_table.setSelectionBehavior(
            QTableWidget.SelectRows
        )

        self.packet_table.setSelectionMode(
            QTableWidget.SingleSelection
        )

        self.packet_table.setEditTriggers(
            QTableWidget.NoEditTriggers
        )

        self.packet_table.setAlternatingRowColors(
            False
        )

        self.packet_table.verticalHeader().setVisible(
            False
        )

        self.packet_table.setSortingEnabled(
            False
        )

        self.packet_table.itemSelectionChanged.connect(
            self.show_packet_details
        )

        header = (
            self.packet_table.horizontalHeader()
        )

        header.setSectionResizeMode(
            0,
            QHeaderView.ResizeToContents
        )

        header.setSectionResizeMode(
            1,
            QHeaderView.ResizeToContents
        )

        header.setSectionResizeMode(
            2,
            QHeaderView.Stretch
        )

        header.setSectionResizeMode(
            3,
            QHeaderView.Stretch
        )

        header.setSectionResizeMode(
            4,
            QHeaderView.ResizeToContents
        )

        header.setSectionResizeMode(
            5,
            QHeaderView.ResizeToContents
        )

        header.setSectionResizeMode(
            6,
            QHeaderView.ResizeToContents
        )

        header.setSectionResizeMode(
            7,
            QHeaderView.ResizeToContents
        )

        header.setSectionResizeMode(
            8,
            QHeaderView.Stretch
        )

        main_layout.addWidget(
            self.packet_table,
            6
        )

        # =====================================================
        # PACKET DETAILS
        # =====================================================

        self.details_box = QTextEdit()

        self.details_box.setReadOnly(
            True
        )

        self.details_box.setPlaceholderText(
            "Select a packet to view its details."
        )

        self.details_box.setMinimumHeight(
            220
        )

        main_layout.addWidget(
            self.details_box,
            2
        )

        # =====================================================
        # STATUS BAR
        # =====================================================

        self.statusBar().showMessage(
            "Ready."
        )

    # =========================================================
    # STATISTICS CARD
    # =========================================================

    def create_stat_card(
        self,
        title,
        value
    ):

        frame = QFrame()

        frame.setObjectName(
            "statCard"
        )

        layout = QVBoxLayout(
            frame
        )

        layout.setContentsMargins(
            16,
            12,
            16,
            12
        )

        label = QLabel(
            title
        )

        label.setObjectName(
            "statTitle"
        )

        value_label = QLabel(
            value
        )

        value_label.setObjectName(
            "statValue"
        )

        layout.addWidget(
            label
        )

        layout.addWidget(
            value_label
        )

        frame.value_label = value_label

        return frame

    # =========================================================
    # INTERFACE DISCOVERY
    # =========================================================

    def load_interfaces(self):

        self.interface_combo.clear()

        try:

            interfaces = socket.if_nameindex()

            for _, name in interfaces:

                self.interface_combo.addItem(
                    name
                )

        except Exception as error:

            self.interface_combo.addItem(
                "wlo1"
            )

            self.statusBar().showMessage(
                f"Could not detect interfaces: {error}"
            )

        # Prefer Wi-Fi interface
        for index in range(
            self.interface_combo.count()
        ):

            name = (
                self.interface_combo
                .itemText(index)
            )

            if name.startswith("wl"):

                self.interface_combo.setCurrentIndex(
                    index
                )

                break

    # =========================================================
    # START CAPTURE
    # =========================================================

    def start_capture(self):

        if self.worker is not None:

            if self.worker.isRunning():

                return

        interface = (
            self.interface_combo
            .currentText()
            .strip()
        )

        if not interface:

            QMessageBox.warning(
                self,
                "No Interface",
                "Please select a network interface."
            )

            return

        # -----------------------------------------------------
        # Clear previous packets
        # -----------------------------------------------------

        self.packet_store.clear()

        self.packet_table.setRowCount(
            0
        )

        self.details_box.clear()

        self.capture_start_time = time.time()

        # -----------------------------------------------------
        # Create worker
        # -----------------------------------------------------

        self.worker = CaptureWorker(
            interface
        )

        self.worker.packet_received.connect(
            self.add_packet
        )

        self.worker.capture_started.connect(
            self.capture_started
        )

        self.worker.capture_stopped.connect(
            self.capture_stopped
        )

        self.worker.capture_error.connect(
            self.capture_error
        )

        # -----------------------------------------------------
        # Update UI
        # -----------------------------------------------------

        self.start_button.setEnabled(
            False
        )

        self.stop_button.setEnabled(
            True
        )

        self.interface_combo.setEnabled(
            False
        )

        self.status_indicator.setText(
            "● CAPTURING"
        )

        self.status_indicator.setObjectName(
            "capturingStatus"
        )

        self.status_indicator.style().unpolish(
            self.status_indicator
        )

        self.status_indicator.style().polish(
            self.status_indicator
        )

        self.statusBar().showMessage(
            f"Starting capture on {interface}..."
        )

        self.worker.start()

    # =========================================================
    # CAPTURE STARTED
    # =========================================================

    def capture_started(
        self,
        interface
    ):

        self.statusBar().showMessage(
            f"Capturing packets on {interface}..."
        )

    # =========================================================
    # ADD PACKET
    # =========================================================

    def add_packet(
        self,
        packet
    ):

        if not packet:
            return

        # -----------------------------------------------------
        # Store packet centrally
        # -----------------------------------------------------

        self.packet_store.add(
            packet
        )

        # -----------------------------------------------------
        # Check current search
        # -----------------------------------------------------

        query = (
            self.search_box
            .text()
            .strip()
        )

        if query:

            if not self.packet_store.filter.matches(
                packet
            ):

                self.update_statistics()

                return

        # -----------------------------------------------------
        # Add packet to table
        # -----------------------------------------------------

        self.insert_packet_into_table(
            packet
        )

        # -----------------------------------------------------
        # Statistics
        # -----------------------------------------------------

        self.update_statistics()

        # -----------------------------------------------------
        # Keep newest packet visible
        # -----------------------------------------------------

        self.packet_table.scrollToBottom()

    # =========================================================
    # INSERT PACKET
    # =========================================================

    def insert_packet_into_table(
        self,
        packet
    ):

        row = self.packet_table.rowCount()

        self.packet_table.insertRow(
            row
        )

        values = [
            packet.get(
                "number",
                "-"
            ),

            packet.get(
                "time",
                "-"
            ),

            packet.get(
                "source",
                "-"
            ),

            packet.get(
                "destination",
                "-"
            ),

            packet.get(
                "protocol",
                "Other"
            ),

            packet.get(
                "length",
                "0"
            ),

            packet.get(
                "source_port",
                "-"
            ),

            packet.get(
                "destination_port",
                "-"
            ),

            packet.get(
                "info",
                ""
            ),
        ]

        for column, value in enumerate(
            values
        ):

            item = QTableWidgetItem(
                str(value)
            )

            item.setTextAlignment(
                Qt.AlignVCenter
                | (
                    Qt.AlignRight
                    if column
                    in [0, 5, 6, 7]
                    else Qt.AlignLeft
                )
            )

            self.packet_table.setItem(
                row,
                column,
                item
            )

        # -----------------------------------------------------
        # Store packet on first cell
        # -----------------------------------------------------

        self.packet_table.item(
            row,
            0
        ).setData(
            Qt.UserRole,
            packet
        )

        # -----------------------------------------------------
        # Protocol-based styling
        # -----------------------------------------------------

        protocol = str(
            packet.get(
                "protocol",
                ""
            )
        ).upper()

        if protocol == "TCP":

            self.set_row_text_color(
                row,
                QColor(
                    "#8ab4f8"
                )
            )

        elif protocol == "UDP":

            self.set_row_text_color(
                row,
                QColor(
                    "#81c995"
                )
            )

        elif protocol == "DNS":

            self.set_row_text_color(
                row,
                QColor(
                    "#c58af9"
                )
            )

        elif protocol in [
            "TLS",
            "HTTP"
        ]:

            self.set_row_text_color(
                row,
                QColor(
                    "#f6c344"
                )
            )

    # =========================================================
    # ROW TEXT COLOR
    # =========================================================

    def set_row_text_color(
        self,
        row,
        color
    ):

        for column in range(
            self.packet_table.columnCount()
        ):

            item = self.packet_table.item(
                row,
                column
            )

            if item:

                item.setForeground(
                    color
                )

    # =========================================================
    # SHOW PACKET DETAILS
    # =========================================================

    def show_packet_details(self):

        selected_rows = (
            self.packet_table
            .selectionModel()
            .selectedRows()
        )

        if not selected_rows:

            self.details_box.clear()

            return

        row = selected_rows[0].row()

        item = self.packet_table.item(
            row,
            0
        )

        if item is None:

            return

        packet = item.data(
            Qt.UserRole
        )

        if not isinstance(
            packet,
            dict
        ):

            return

        self.details_box.setPlainText(
            self.format_packet_details(
                packet
            )
        )

    # =========================================================
    # FORMAT PACKET DETAILS
    # =========================================================

    def format_packet_details(
        self,
        packet
    ):

        number = packet.get(
            "number",
            "-"
        )

        timestamp = packet.get(
            "time",
            "-"
        )

        source = packet.get(
            "source",
            "-"
        )

        destination = packet.get(
            "destination",
            "-"
        )

        protocol = packet.get(
            "protocol",
            "Other"
        )

        length = packet.get(
            "length",
            "0"
        )

        source_port = packet.get(
            "source_port",
            "-"
        )

        destination_port = packet.get(
            "destination_port",
            "-"
        )

        info = packet.get(
            "info",
            ""
        )

        try:

            length_text = (
                f"{int(float(length)):,} bytes"
            )

        except Exception:

            length_text = (
                f"{length} bytes"
            )

        lines = []

        lines.append(
            f"PACKET #{number}"
        )

        lines.append(
            "─" * 58
        )

        lines.append(
            f"Time                 {timestamp}"
        )

        lines.append(
            f"Source               {source}"
        )

        lines.append(
            f"Destination          {destination}"
        )

        lines.append(
            f"Protocol             {protocol}"
        )

        lines.append(
            f"Length               {length_text}"
        )

        lines.append(
            f"Source Port          {source_port}"
        )

        lines.append(
            f"Destination Port     {destination_port}"
        )

        lines.append("")

        lines.append(
            "PACKET INFORMATION"
        )

        lines.append(
            "─" * 58
        )

        lines.append(
            info if info else "No additional information."
        )

        # -----------------------------------------------------
        # Protocol layers
        # -----------------------------------------------------

        raw_packet = packet.get(
            "raw_packet"
        )

        if raw_packet is not None:

            layers = self.get_packet_layers(
                raw_packet
            )

            if layers:

                lines.append("")

                lines.append(
                    "NETWORK LAYERS"
                )

                lines.append(
                    "─" * 58
                )

                lines.extend(
                    f"• {layer}"
                    for layer in layers
                )

            # -------------------------------------------------
            # Clean TShark packet details
            # -------------------------------------------------

            try:

                raw_details = raw_packet.show()

                raw_details = (
                    self.clean_ansi(
                        raw_details
                    )
                )

                if raw_details.strip():

                    lines.append("")

                    lines.append(
                        "DECODED PACKET"
                    )

                    lines.append(
                        "─" * 58
                    )

                    lines.append(
                        raw_details.strip()
                    )

            except Exception:
                pass

        return "\n".join(
            lines
        )

    # =========================================================
    # GET NETWORK LAYERS
    # =========================================================

    @staticmethod
    def get_packet_layers(
        raw_packet
    ):

        layers = []

        try:

            for layer in raw_packet.layers:

                name = getattr(
                    layer,
                    "layer_name",
                    None
                )

                if name:

                    name = str(
                        name
                    ).upper()

                    if name not in layers:

                        layers.append(
                            name
                        )

        except Exception:
            pass

        return layers

    # =========================================================
    # REMOVE ANSI ESCAPE CODES
    # =========================================================

    @staticmethod
    def clean_ansi(
        text
    ):

        if not text:

            return ""

        # ANSI escape sequences
        ansi_escape = re.compile(
            r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])"
        )

        text = ansi_escape.sub(
            "",
            str(text)
        )

        # Remove common terminal artifacts
        text = text.replace(
            "\x1b",
            ""
        )

        return text

    # =========================================================
    # FILTER PACKETS
    # =========================================================

    def filter_packets(
        self,
        query
    ):

        query = query.strip()

        # -----------------------------------------------------
        # No search → show everything
        # -----------------------------------------------------

        if not query:

            packets = self.packet_store.all()

        else:

            packets = self.packet_store.search(
                query
            )

        # -----------------------------------------------------
        # Rebuild table
        # -----------------------------------------------------

        self.packet_table.setUpdatesEnabled(
            False
        )

        self.packet_table.setRowCount(
            0
        )

        for packet in packets:

            self.insert_packet_into_table(
                packet
            )

        self.packet_table.setUpdatesEnabled(
            True
        )

        self.update_statistics()

        self.statusBar().showMessage(
            f"Showing {len(packets)} of "
            f"{self.packet_store.count()} packets."
        )

    # =========================================================
    # UPDATE STATISTICS
    # =========================================================

    def update_statistics(self):

        stats = (
            self.packet_store
            .get_statistics()
        )

        total_packets = (
            stats.total_packets
        )

        total_bytes = (
            stats.total_bytes
        )

        tcp = (
            stats.protocol_counts
            .get(
                "TCP",
                0
            )
        )

        udp = (
            stats.protocol_counts
            .get(
                "UDP",
                0
            )
        )

        dns = (
            stats.protocol_counts
            .get(
                "DNS",
                0
            )
        )

        other = (
            total_packets
            - tcp
            - udp
            - dns
        )

        if other < 0:

            other = 0

        self.packet_card.value_label.setText(
            f"{total_packets:,}"
        )

        self.data_card.value_label.setText(
            self.format_bytes(
                total_bytes
            )
        )

        self.tcp_card.value_label.setText(
            f"{tcp:,}"
        )

        self.udp_card.value_label.setText(
            f"{udp:,}"
        )

        self.dns_card.value_label.setText(
            f"{dns:,}"
        )

        self.other_card.value_label.setText(
            f"{other:,}"
        )

    # =========================================================
    # FORMAT BYTES
    # =========================================================

    @staticmethod
    def format_bytes(
        value
    ):

        try:

            value = float(
                value
            )

        except Exception:

            return "0 B"

        if value < 1024:

            return f"{int(value)} B"

        if value < 1024 ** 2:

            return f"{value / 1024:.1f} KB"

        if value < 1024 ** 3:

            return f"{value / (1024 ** 2):.1f} MB"

        return f"{value / (1024 ** 3):.2f} GB"

    # =========================================================
    # STOP CAPTURE
    # =========================================================

    def stop_capture(self):

        if self.worker is None:

            return

        if not self.worker.isRunning():

            return

        self.statusBar().showMessage(
            "Stopping capture..."
        )

        self.worker.stop_capture()

        self.start_button.setEnabled(
            True
        )

        self.stop_button.setEnabled(
            False
        )

        self.interface_combo.setEnabled(
            True
        )

    # =========================================================
    # CAPTURE STOPPED
    # =========================================================

    def capture_stopped(self):

        self.start_button.setEnabled(
            True
        )

        self.stop_button.setEnabled(
            False
        )

        self.interface_combo.setEnabled(
            True
        )

        self.status_indicator.setText(
            "● READY"
        )

        self.status_indicator.setObjectName(
            "readyStatus"
        )

        self.status_indicator.style().unpolish(
            self.status_indicator
        )

        self.status_indicator.style().polish(
            self.status_indicator
        )

        count = (
            self.packet_store.count()
        )

        self.statusBar().showMessage(
            f"Capture stopped — "
            f"{count:,} packets captured."
        )

    # =========================================================
    # CAPTURE ERROR
    # =========================================================

    def capture_error(
        self,
        error
    ):

        self.start_button.setEnabled(
            True
        )

        self.stop_button.setEnabled(
            False
        )

        self.interface_combo.setEnabled(
            True
        )

        self.status_indicator.setText(
            "● ERROR"
        )

        self.status_indicator.setObjectName(
            "errorStatus"
        )

        self.status_indicator.style().unpolish(
            self.status_indicator
        )

        self.status_indicator.style().polish(
            self.status_indicator
        )

        QMessageBox.critical(
            self,
            "Capture Error",
            "Unable to capture packets:\n\n"
            f"{error}\n\n"
            "If this is a permission error, "
            "we can fix dumpcap permissions."
        )

        self.statusBar().showMessage(
            "Capture failed."
        )

    # =========================================================
    # CLEAR
    # =========================================================

    def clear_packets(self):

        if self.worker is not None:

            if self.worker.isRunning():

                QMessageBox.information(
                    self,
                    "Capture Running",
                    "Stop the capture before "
                    "clearing the packet list."
                )

                return

        self.packet_store.clear()

        self.packet_table.setRowCount(
            0
        )

        self.details_box.clear()

        self.update_statistics()

        self.statusBar().showMessage(
            "Packet list cleared."
        )

    # =========================================================
    # STYLES
    # =========================================================

    def apply_styles(self):

        self.setStyleSheet(
            """
            QMainWindow {
                background-color: #0b0f14;
            }

            QWidget {
                background-color: #0b0f14;
                color: #e6edf3;
                font-family: "Noto Sans", "DejaVu Sans";
                font-size: 14px;
            }

            #titleLabel {
                font-size: 32px;
                font-weight: 700;
                color: #f5f7fa;
            }

            #subtitleLabel {
                font-size: 14px;
                color: #7890a8;
                margin-top: 2px;
            }

            #readyStatus {
                color: #2ecc71;
                font-weight: 700;
                font-size: 14px;
            }

            #capturingStatus {
                color: #f1c40f;
                font-weight: 700;
                font-size: 14px;
            }

            #errorStatus {
                color: #ff5252;
                font-weight: 700;
                font-size: 14px;
            }

            #controlFrame {
                background-color: #151a21;
                border: 1px solid #29313b;
                border-radius: 10px;
            }

            #controlLabel {
                color: #8fa4b9;
                font-weight: 600;
            }

            QComboBox,
            QLineEdit {
                background-color: #0e1319;
                border: 1px solid #2c3540;
                border-radius: 7px;
                padding: 9px 11px;
                color: #e6edf3;
                selection-background-color: #216eeb;
            }

            QComboBox:hover,
            QLineEdit:hover {
                border: 1px solid #465464;
            }

            QComboBox:focus,
            QLineEdit:focus {
                border: 1px solid #4c9aff;
            }

            QComboBox QAbstractItemView {
                background-color: #151a21;
                color: #e6edf3;
                border: 1px solid #303944;
                selection-background-color: #216eeb;
            }

            QPushButton {
                background-color: #202731;
                border: 1px solid #303944;
                border-radius: 7px;
                padding: 9px 15px;
                font-weight: 600;
                color: #e6edf3;
            }

            QPushButton:hover {
                background-color: #29323e;
            }

            QPushButton:pressed {
                background-color: #171d25;
            }

            QPushButton:disabled {
                color: #596675;
                background-color: #151a20;
            }

            #startButton {
                background-color: #249b45;
                border: 1px solid #2fb953;
                color: white;
            }

            #startButton:hover {
                background-color: #2bb350;
            }

            #stopButton {
                background-color: #e53935;
                border: 1px solid #f04b47;
                color: white;
            }

            #stopButton:hover {
                background-color: #ef403b;
            }

            #statCard {
                background-color: #151a21;
                border: 1px solid #29313b;
                border-radius: 10px;
            }

            #statTitle {
                color: #7e94aa;
                font-size: 12px;
                font-weight: 700;
                letter-spacing: 1px;
            }

            #statValue {
                color: #f4f7fa;
                font-size: 25px;
                font-weight: 700;
            }

            QTableWidget {
                background-color: #0c1117;
                alternate-background-color: #10161d;
                border: 1px solid #29313b;
                border-radius: 8px;
                gridline-color: #202832;
                color: #dce5ee;
                selection-background-color: #216eeb;
                selection-color: white;
            }

            QTableWidget::item {
                padding: 7px;
                border-bottom: 1px solid #1b222b;
            }

            QTableWidget::item:selected {
                background-color: #216eeb;
                color: white;
            }

            QHeaderView::section {
                background-color: #151a21;
                color: #8fa4b9;
                border: none;
                border-bottom: 1px solid #29313b;
                padding: 9px;
                font-weight: 700;
            }

            QTextEdit {
                background-color: #0c1117;
                border: 1px solid #29313b;
                border-radius: 8px;
                color: #cbd6e2;
                padding: 10px;
                selection-background-color: #216eeb;
                font-family: "DejaVu Sans Mono",
                             "Liberation Mono",
                             monospace;
                font-size: 13px;
            }

            QStatusBar {
                background-color: #151a21;
                color: #8fa4b9;
                border-top: 1px solid #29313b;
            }

            QScrollBar:vertical {
                background-color: #0d1218;
                width: 12px;
                margin: 2px;
            }

            QScrollBar::handle:vertical {
                background-color: #39434f;
                border-radius: 6px;
                min-height: 30px;
            }

            QScrollBar::handle:vertical:hover {
                background-color: #4a5868;
            }

            QScrollBar::add-line:vertical,
            QScrollBar::sub-line:vertical {
                height: 0px;
            }

            QScrollBar:horizontal {
                background-color: #0d1218;
                height: 12px;
                margin: 2px;
            }

            QScrollBar::handle:horizontal {
                background-color: #39434f;
                border-radius: 6px;
            }
            """
        )

    # =========================================================
    # WINDOW CLOSE
    # =========================================================

    def closeEvent(
        self,
        event
    ):

        if self.worker is not None:

            if self.worker.isRunning():

                self.worker.stop_capture()

                self.worker.wait(
                    3000
                )

        event.accept()