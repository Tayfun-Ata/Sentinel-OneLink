import sys
import subprocess
import threading
import time
from PySide6.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QLabel, QPushButton, QListWidget, QMessageBox
from PySide6.QtCore import Qt
import psutil

# For deep packet inspection
from scapy.all import sniff, IP, TCP, UDP



class AgentManager:
    def __init__(self):
        self.process = None
        self.running = False

    def start_agent(self):
        if not self.running:
            self.process = subprocess.Popen([sys.executable, 'network_agent.py'])
            self.running = True

    def stop_agent(self):
        if self.process and self.running:
            self.process.terminate()
            self.process.wait()
            self.running = False

    def is_running(self):
        return self.running and self.process.poll() is None

class VisionDashboard(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Vision Home Security')
        self.setGeometry(200, 200, 600, 400)
        self.agent = AgentManager()
        self.init_ui()
        self.update_status()

        # For DPI: cache for quick lookup
        self.dpi_cache = {}

    def init_ui(self):
        from PySide6.QtWidgets import QHBoxLayout, QTextEdit, QSizePolicy
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout()
        central.setLayout(main_layout)

        self.status_label = QLabel('Protection is OFF', self)
        self.status_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(self.status_label)

        self.start_btn = QPushButton('Start Protection', self)
        self.start_btn.clicked.connect(self.start_protection)
        main_layout.addWidget(self.start_btn)

        self.stop_btn = QPushButton('Stop Protection', self)
        self.stop_btn.clicked.connect(self.stop_protection)
        main_layout.addWidget(self.stop_btn)

        # Split area for packets and details
        split_layout = QHBoxLayout()
        main_layout.addLayout(split_layout)

        # Packet list (left)
        left_layout = QVBoxLayout()
        split_layout.addLayout(left_layout)
        left_layout.addWidget(QLabel('Recent Network Packets:'))
        self.packet_list = QListWidget(self)
        self.packet_list.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        left_layout.addWidget(self.packet_list)
        self.refresh_btn = QPushButton('Refresh Packets', self)
        self.refresh_btn.clicked.connect(self.load_packets)
        left_layout.addWidget(self.refresh_btn)

        # Packet details (right)
        right_layout = QVBoxLayout()
        split_layout.addLayout(right_layout)
        right_layout.addWidget(QLabel('Packet Details:'))
        self.packet_details = QTextEdit(self)
        self.packet_details.setReadOnly(True)
        self.packet_details.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        right_layout.addWidget(self.packet_details)

        # Connect selection event
        self.packet_list.currentItemChanged.connect(self.show_packet_details)

    def start_protection(self):
        self.agent.start_agent()
        self.update_status()

    def stop_protection(self):
        self.agent.stop_agent()
        self.update_status()

    def update_status(self):
        if self.agent.is_running():
            self.status_label.setText('Protection is ON')
        else:
            self.status_label.setText('Protection is OFF')


    def load_packets(self):
        try:
            with open('packets.log', 'r') as f:
                lines = f.readlines()[-50:]
            self.packet_list.clear()
            for line in lines:
                self.packet_list.addItem(line.strip())
            self.packet_details.clear()
        except Exception:
            self.packet_list.clear()
            self.packet_list.addItem('No packets recorded yet.')

    def show_packet_details(self, current, previous):
        if current:
            line = current.text()
            self.packet_details.setText(line)
            # Try to parse and show more details using scapy
            try:
                # Extract IPs and ports from the line
                import re
                m = re.search(r'(\d+\.\d+\.\d+\.\d+):(\d+) -> (\d+\.\d+\.\d+\.\d+):(\d+)', line)
                if m:
                    src_ip, src_port, dst_ip, dst_port = m.groups()
                    key = (src_ip, int(src_port), dst_ip, int(dst_port))
                    # Check cache first
                    if key in self.dpi_cache:
                        pkt_summary = self.dpi_cache[key]
                    else:
                        # Capture a single matching packet (timeout 2s)
                        def pkt_filter(pkt):
                            if IP in pkt:
                                sip = pkt[IP].src
                                dip = pkt[IP].dst
                                sport = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else None)
                                dport = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else None)
                                return (sip == src_ip and dip == dst_ip and sport == int(src_port) and dport == int(dst_port))
                            return False
                        pkts = sniff(count=1, timeout=2, lfilter=pkt_filter)
                        if pkts:
                            pkt = pkts[0]
                            pkt_summary = pkt.show(dump=True)
                        else:
                            pkt_summary = 'No live packet found for this connection.'
                        self.dpi_cache[key] = pkt_summary
                    self.packet_details.append('\n--- Deep Packet Inspection ---\n' + pkt_summary)
            except Exception as e:
                self.packet_details.append(f'\n[DPI error: {e}]')
        else:
            self.packet_details.clear()

def main():
    app = QApplication(sys.argv)
    win = VisionDashboard()
    win.show()
    sys.exit(app.exec())

if __name__ == '__main__':
    main()
