import sys
import threading
import binascii
from PyQt5 import QtWidgets, QtGui, QtCore
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS, Raw
import psutil

class NetScopeGUI(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NetScope - Advanced Packet Analyzer")
        self.setGeometry(100, 100, 1200, 700)

        self.capture_thread = None
        self.sniffing = False

        self.initUI()

    def initUI(self):
        layout = QtWidgets.QVBoxLayout()

        # Interface Dropdown
        self.interface_dropdown = QtWidgets.QComboBox()
        self.interfaces = self.get_interfaces()
        for name, desc in self.interfaces.items():
            self.interface_dropdown.addItem(f"{desc} ({name})", name)
        layout.addWidget(self.interface_dropdown)

        # Start/Stop Buttons
        btn_layout = QtWidgets.QHBoxLayout()
        self.start_btn = QtWidgets.QPushButton("Start Capture")
        self.stop_btn = QtWidgets.QPushButton("Stop Capture")
        self.stop_btn.setEnabled(False)
        self.start_btn.clicked.connect(self.start_capture)
        self.stop_btn.clicked.connect(self.stop_capture)
        btn_layout.addWidget(self.start_btn)
        btn_layout.addWidget(self.stop_btn)
        layout.addLayout(btn_layout)

        # Packet Table
        self.packet_table = QtWidgets.QTableWidget()
        self.packet_table.setColumnCount(9)
        self.packet_table.setHorizontalHeaderLabels(["Time", "Source", "Destination", "Protocol", "Src Port", "Dst Port", "Length", "HTTP Method", "URL"])
        self.packet_table.horizontalHeader().setStretchLastSection(True)
        self.packet_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.packet_table.itemSelectionChanged.connect(self.display_packet_details)
        layout.addWidget(self.packet_table)

        # Tabs for Details and Hex Dump
        self.tabs = QtWidgets.QTabWidget()
        self.detail_view = QtWidgets.QTextEdit()
        self.detail_view.setReadOnly(True)
        self.hex_view = QtWidgets.QTextEdit()
        self.hex_view.setReadOnly(True)
        self.tabs.addTab(self.detail_view, "Details")
        self.tabs.addTab(self.hex_view, "Hex + ASCII")
        layout.addWidget(self.tabs)

        central_widget = QtWidgets.QWidget()
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

        self.packets = []

    def get_interfaces(self):
        interfaces = {}
        addrs = psutil.net_if_addrs()
        for name in addrs:
            description = name
            if sys.platform == 'win32':
                try:
                    import wmi
                    w = wmi.WMI()
                    for nic in w.Win32_NetworkAdapter():
                        if nic.NetConnectionID == name:
                            description = nic.Name
                            break
                except:
                    pass
            interfaces[name] = description
        return interfaces

    def start_capture(self):
        interface_name = self.interface_dropdown.currentData()
        self.sniffing = True
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.capture_thread = threading.Thread(target=self.sniff_packets, args=(interface_name,), daemon=True)
        self.capture_thread.start()

    def stop_capture(self):
        self.sniffing = False
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    def sniff_packets(self, interface):
        sniff(iface=interface, prn=self.handle_packet, store=False, stop_filter=lambda x: not self.sniffing)

    def handle_packet(self, packet):
        timestamp = QtCore.QDateTime.currentDateTime().toString("HH:mm:ss")
        src = packet[IP].src if IP in packet else "N/A"
        dst = packet[IP].dst if IP in packet else "N/A"
        proto = packet.sprintf("%IP.proto%") if IP in packet else ("ARP" if ARP in packet else "Other")
        length = len(packet)

        src_port = dst_port = "-"
        method = url = "-"

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

            if Raw in packet:
                payload = bytes(packet[Raw]).decode('utf-8', errors='ignore')
                lines = payload.split('\r\n')
                if lines and lines[0].startswith(("GET", "POST", "PUT", "DELETE")):
                    method = lines[0].split(' ')[0]
                    url = lines[0].split(' ')[1] if len(lines[0].split(' ')) > 1 else "-"
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        row = self.packet_table.rowCount()
        self.packet_table.insertRow(row)
        self.packet_table.setItem(row, 0, QtWidgets.QTableWidgetItem(timestamp))
        self.packet_table.setItem(row, 1, QtWidgets.QTableWidgetItem(src))
        self.packet_table.setItem(row, 2, QtWidgets.QTableWidgetItem(dst))
        self.packet_table.setItem(row, 3, QtWidgets.QTableWidgetItem(proto))
        self.packet_table.setItem(row, 4, QtWidgets.QTableWidgetItem(str(src_port)))
        self.packet_table.setItem(row, 5, QtWidgets.QTableWidgetItem(str(dst_port)))
        self.packet_table.setItem(row, 6, QtWidgets.QTableWidgetItem(str(length)))
        self.packet_table.setItem(row, 7, QtWidgets.QTableWidgetItem(method))
        self.packet_table.setItem(row, 8, QtWidgets.QTableWidgetItem(url))

        self.packets.append(packet)

    def display_packet_details(self):
        row = self.packet_table.currentRow()
        if row >= 0 and row < len(self.packets):
            packet = self.packets[row]
            details = packet.show(dump=True)
            self.detail_view.setPlainText(details)
            raw = bytes(packet)
            hex_view = binascii.hexlify(raw).decode('utf-8')
            ascii_view = ''.join([chr(b) if 32 <= b <= 126 else '.' for b in raw])
            formatted_hex = '\n'.join([f"{hex_view[i:i+32]}  {ascii_view[i//2:i//2+16]}" for i in range(0, len(hex_view), 32)])
            self.hex_view.setPlainText(formatted_hex)

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    window = NetScopeGUI()
    window.show()
    sys.exit(app.exec_())
