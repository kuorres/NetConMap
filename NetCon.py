import sys
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QHBoxLayout, QTabWidget, QTextEdit, QPushButton, 
                            QComboBox, QLabel, QFileDialog, QTableWidget, 
                            QTableWidgetItem, QCheckBox, QSpinBox, QStyle,
                            QTreeWidget, QTreeWidgetItem)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QColor, QIcon
import pyshark
import datetime
import json
import os
from collections import defaultdict

class PacketCaptureThread(QThread):
    packet_captured = pyqtSignal(object)

    def __init__(self, interface, keylog_file=None, filter=""):
        super().__init__()
        self.interface = interface
        self.keylog_file = keylog_file
        self.filter = filter
        self.running = True

    def run(self):
        import asyncio
        # Create a new event loop for this thread
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            # Setup capture with TLS decryption if keylog file is provided
            capture = pyshark.LiveCapture(
                interface=self.interface,
                display_filter=self.filter or 'http or ssl or tls',
                override_prefs={
                    'ssl.keylog_file': self.keylog_file,
                    'ssl.debug_file': '',
                    'ssl.desegment_ssl_records': 'TRUE',
                    'ssl.desegment_ssl_application_data': 'TRUE'
                } if self.keylog_file else {}
            )

            for packet in capture.sniff_continuously():
                if not self.running:
                    break
                self.packet_captured.emit(packet)
        finally:
            capture.close()
            loop.close()

    def stop(self):
        self.running = False

class NetworkAnalyzerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Protocol Analyzer")
        self.setGeometry(100, 100, 1200, 800)
        
        # Main widget and layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)

        # Control panel
        control_panel = QHBoxLayout()
        
        # Interface selection
        self.interface_combo = QComboBox()
        self.interface_combo.addItems(self.get_interfaces())
        control_panel.addWidget(QLabel("Interface:"))
        control_panel.addWidget(self.interface_combo)

        # Key log file selection
        self.keylog_button = QPushButton("Select SSL Key Log")
        self.keylog_button.clicked.connect(self.select_keylog_file)
        control_panel.addWidget(self.keylog_button)
        
        # Filter input
        control_panel.addWidget(QLabel("Filter:"))
        self.filter_input = QComboBox()
        self.filter_input.setEditable(True)
        self.filter_input.addItems([
            "http or ssl or tls",
            "tcp port 80 or tcp port 443",
            "dns",
            "smtp",
            "ftp"
        ])
        control_panel.addWidget(self.filter_input)

        # Start/Stop button
        self.start_button = QPushButton("Start Capture")
        self.start_button.clicked.connect(self.toggle_capture)
        control_panel.addWidget(self.start_button)

        # Clear button
        clear_button = QPushButton("Clear")
        clear_button.clicked.connect(self.clear_display)
        control_panel.addWidget(clear_button)

        layout.addLayout(control_panel)

        # Tab widget for different views
        self.tabs = QTabWidget()
        
        # Packet list tab
        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(6)
        self.packet_table.setHorizontalHeaderLabels([
            "Time", "Source", "Destination", "Protocol", "Length", "Info"
        ])
        self.packet_table.currentItemChanged.connect(self.packet_selected)
        self.tabs.addTab(self.packet_table, "Packet List")

        # Packet details tab
        self.detail_tree = QTreeWidget()
        self.detail_tree.setHeaderLabels(["Field", "Value"])
        self.tabs.addTab(self.detail_tree, "Packet Details")

        # Raw data tab
        self.raw_data = QTextEdit()
        self.raw_data.setReadOnly(True)
        self.raw_data.setFont(QFont("Courier", 10))
        self.tabs.addTab(self.raw_data, "Raw Data")

        # Decoded data tab
        self.decoded_data = QTextEdit()
        self.decoded_data.setReadOnly(True)
        self.decoded_data.setFont(QFont("Courier", 10))
        self.tabs.addTab(self.decoded_data, "Decoded Data")

        layout.addWidget(self.tabs)

        # Status bar
        self.statusBar().showMessage("Ready")

        # Initialize variables
        self.capture_thread = None
        self.keylog_file = None
        self.packets = []
        self.running = False

    def get_interfaces(self):
        """Get list of network interfaces"""
        try:
            return [i.name for i in pyshark.capture.capture.get_all_interfaces()]
        except:
            return ["Wi-Fi", "eth0"]  # Fallback interfaces

    def select_keylog_file(self):
        """Open file dialog to select SSL key log file"""
        file_name, _ = QFileDialog.getOpenFileName(
            self,
            "Select SSL Key Log File",
            "C:\\usr\\",
            "Text Files (*.*);;All Files (*)"
        )
        if file_name:
            self.keylog_file = file_name
            self.keylog_button.setText("Key Log: " + os.path.basename(file_name))

    def toggle_capture(self):
        """Start or stop packet capture"""
        if not self.running:
            self.start_capture()
        else:
            self.stop_capture()

    def start_capture(self):
        """Start packet capture"""
        self.running = True
        self.start_button.setText("Stop Capture")
        self.statusBar().showMessage("Capturing...")
        
        # Create and start capture thread
        self.capture_thread = PacketCaptureThread(
            self.interface_combo.currentText(),
            self.keylog_file,
            self.filter_input.currentText()
        )
        self.capture_thread.packet_captured.connect(self.process_packet)
        self.capture_thread.start()

    def stop_capture(self):
        """Stop packet capture"""
        if self.capture_thread:
            self.capture_thread.stop()
            self.capture_thread.wait()
            self.capture_thread = None
            
        self.running = False
        self.start_button.setText("Start Capture")
        self.statusBar().showMessage("Capture stopped")

    def process_packet(self, packet):
        """Process captured packet and update display"""
        try:
            # Extract basic packet info
            time = datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]
            protocol = packet.highest_layer
            length = packet.length
            source = packet.ip.src if hasattr(packet, 'ip') else 'N/A'
            dest = packet.ip.dst if hasattr(packet, 'ip') else 'N/A'
            
            # Get packet info based on protocol
            info = self.get_packet_info(packet)

            # Add to packet list
            row = self.packet_table.rowCount()
            self.packet_table.insertRow(row)
            self.packet_table.setItem(row, 0, QTableWidgetItem(time))
            self.packet_table.setItem(row, 1, QTableWidgetItem(source))
            self.packet_table.setItem(row, 2, QTableWidgetItem(dest))
            self.packet_table.setItem(row, 3, QTableWidgetItem(protocol))
            self.packet_table.setItem(row, 4, QTableWidgetItem(str(length)))
            self.packet_table.setItem(row, 5, QTableWidgetItem(info))

            # Store packet for detailed view
            self.packets.append(packet)
            
            # Auto-scroll to bottom
            self.packet_table.scrollToBottom()
            
        except Exception as e:
            self.statusBar().showMessage(f"Error processing packet: {str(e)}")

    def get_packet_info(self, packet):
        """Extract readable info from packet based on protocol"""
        try:
            if hasattr(packet, 'http'):
                if hasattr(packet.http, 'request'):
                    return f"{packet.http.request_method} {packet.http.request_uri}"
                elif hasattr(packet.http, 'response'):
                    return f"HTTP {packet.http.response_code} {packet.http.response_phrase}"
                elif hasattr(packet.http, 'host'):
                    return packet.http.host
            elif hasattr(packet, 'ssl') or hasattr(packet, 'tls'):
                layer = packet.ssl if hasattr(packet, 'ssl') else packet.tls
                
                if hasattr(packet.tls, 'handshake_extensions_server_name'):
                    return packet.tls.handshake_extensions_server_name
                elif hasattr(layer, 'app_data'):
                    return "Decrypted HTTPS data"
                else:
                    return f"TLS {layer.record_content_type if hasattr(layer, 'record_content_type') else 'message'}"
            elif hasattr(packet, 'dns'):
                return f"DNS {'Query' if packet.dns.qry_name else 'Response'}"
            
            return packet.highest_layer

        except Exception as e:
            return f"Error: {str(e)}"

    def packet_selected(self, current, previous):
        """Handle packet selection in the packet list"""
        if not current:
            return
            
        row = current.row()
        if row < len(self.packets):
            packet = self.packets[row]
            self.show_packet_details(packet)

    def show_packet_details(self, packet):
        """Show detailed packet information in tree view"""
        self.detail_tree.clear()
        self.raw_data.clear()
        self.decoded_data.clear()

        # Add packet layers to tree
        for layer in packet.layers:
            layer_item = QTreeWidgetItem(self.detail_tree, [layer.layer_name.upper(), ""])
            
            # Add layer fields
            for field in layer.field_names:
                attribute_value = getattr(layer, field)
                field_item = QTreeWidgetItem(layer_item, [
                    field,
                    attribute_value
                ])

        # Show raw data
        if hasattr(packet, 'raw'):
            self.raw_data.setText(packet.raw.hex())

        # Show decoded data for HTTP/HTTPS
        if hasattr(packet, 'http'):
            if hasattr(packet.http, 'file_data'):
                self.decoded_data.setText(packet.http.file_data)
        elif hasattr(packet, 'ssl') or hasattr(packet, 'tls'):
            layer = packet.ssl if hasattr(packet, 'ssl') else packet.tls
            if hasattr(layer, 'app_data'):
                self.decoded_data.setText(layer.app_data)

    def clear_display(self):
        """Clear all displays"""
        self.packet_table.setRowCount(0)
        self.detail_tree.clear()
        self.raw_data.clear()
        self.decoded_data.clear()
        self.packets.clear()

    def closeEvent(self, event):
        """Handle application close"""
        self.stop_capture()
        event.accept()

def main():
    app = QApplication(sys.argv)
    window = NetworkAnalyzerGUI()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()