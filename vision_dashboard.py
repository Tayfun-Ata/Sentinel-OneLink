# Vision Dashboard (modular)
# This dashboard can connect to a local or remote agent for real-time packet monitoring and inspection.

import sys
import subprocess
import time
import csv
import webbrowser
from datetime import datetime
from pathlib import Path

import requests
from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QTextEdit,
    QHBoxLayout,
    QSizePolicy,
    QSpinBox,
    QPushButton,
    QLineEdit,
    QSystemTrayIcon,
    QMenu,
)
from PySide6.QtCore import Qt, QTimer, QSettings
from PySide6.QtGui import QColor, QAction

from ai_insights import analyze_packet, Insight

MAX_VISIBLE_PACKETS = 50
DEFAULT_REFRESH_SECONDS = 50
EXPORT_DIR = Path('exports')
# TODO: point to your public release/updates page before shipping
UPDATE_CHECK_URL = 'https://sentinel-onelink-updates.example.com'
MAX_ALERT_HISTORY = 200
RISK_COLORS = {
    'Low': QColor('#2ecc71'),
    'Medium': QColor('#f1c40f'),
    'High': QColor('#e67e22'),
    'Critical': QColor('#e74c3c'),
}
PACKET_ROLE = Qt.UserRole + 1
INSIGHT_ROLE = Qt.UserRole + 2

class VisionDashboard(QMainWindow):
    def __init__(self, agent_host='localhost', agent_port=5000):
        super().__init__()
        self.setWindowTitle('Vision Home Security Dashboard')
        self.setGeometry(200, 200, 800, 500)
        self.agent_host = agent_host
        self.agent_port = agent_port
        self.agent_url = f'http://{agent_host}:{agent_port}'
        self.agent_process = None
        self.settings = QSettings('SentinelOneLink', 'VisionDashboard')
        self.packet_analysis = {}
        self.visible_packets = []
        self.packet_bundle = []
        self.last_selected_key = None
        self.alert_history_keys = set()
        self.alert_history_queue = []
        self.force_quit = False
        self.tray_icon = None
        self.tray_pause_action = None
        self.tray_message_shown = False
        self.refresh_interval_seconds = int(self.settings.value('refresh_interval', DEFAULT_REFRESH_SECONDS))
        self.paused = self.settings.value('paused', False, type=bool)
        self.saved_geometry = self.settings.value('geometry')
        self.refresh_in_progress = False
        self.init_ui()
        self.ensure_local_agent()
        self.refresh_packets()
        self.timer = QTimer()
        self.timer.timeout.connect(self.refresh_packets)
        if not self.paused:
            self.timer.start(self.refresh_interval_seconds * 1000)
        if self.saved_geometry:
            self.restoreGeometry(self.saved_geometry)
        self.apply_pause_state(update_status=False)
        self.setup_tray_icon()

    def init_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout()
        central.setLayout(main_layout)

        status_row = QHBoxLayout()
        self.status_label = QLabel('Connected to agent', self)
        status_row.addWidget(self.status_label)
        status_row.addStretch()
        self.agent_health_label = QLabel('Agent: unknown', self)
        status_row.addWidget(self.agent_health_label)
        self.health_button = QPushButton('Check Agent', self)
        self.health_button.clicked.connect(self.check_agent_health)
        status_row.addWidget(self.health_button)
        self.update_button = QPushButton('Get Latest Build', self)
        self.update_button.clicked.connect(self.open_update_page)
        status_row.addWidget(self.update_button)
        main_layout.addLayout(status_row)

        split_layout = QHBoxLayout()
        main_layout.addLayout(split_layout)

        left_layout = QVBoxLayout()
        split_layout.addLayout(left_layout)
        packets_header = QHBoxLayout()
        packets_header.addWidget(QLabel('Recent Network Packets:'))
        packets_header.addStretch()
        packets_header.addWidget(QLabel('Refresh (s):'))
        self.refresh_spin = QSpinBox(self)
        self.refresh_spin.setRange(1, 60)
        self.refresh_spin.setValue(self.refresh_interval_seconds)
        self.refresh_spin.setSuffix(' s')
        self.refresh_spin.valueChanged.connect(self.update_refresh_interval)
        packets_header.addWidget(self.refresh_spin)
        self.refresh_button = QPushButton('Refresh Now', self)
        self.refresh_button.clicked.connect(lambda: self.refresh_packets(manual=True))
        packets_header.addWidget(self.refresh_button)
        self.pause_button = QPushButton('Pause Updates', self)
        self.pause_button.setCheckable(True)
        self.pause_button.clicked.connect(self.toggle_pause)
        packets_header.addWidget(self.pause_button)
        self.export_button = QPushButton('Export Packets', self)
        self.export_button.clicked.connect(self.export_packets)
        packets_header.addWidget(self.export_button)
        self.filter_input = QLineEdit(self)
        self.filter_input.setPlaceholderText('Filter packets (IP, protocol, risk, keyword)')
        self.filter_input.textChanged.connect(self.render_packet_list)
        packets_header.addWidget(self.filter_input)
        left_layout.addLayout(packets_header)
        self.packet_list = QListWidget(self)
        self.packet_list.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        left_layout.addWidget(self.packet_list)

        right_layout = QVBoxLayout()
        split_layout.addLayout(right_layout)
        right_layout.addWidget(QLabel('Packet Details:'))
        self.packet_details = QTextEdit(self)
        self.packet_details.setReadOnly(True)
        self.packet_details.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        right_layout.addWidget(self.packet_details)

        right_layout.addWidget(QLabel('AI Insight:'))
        self.ai_summary = QTextEdit(self)
        self.ai_summary.setReadOnly(True)
        self.ai_summary.setMaximumHeight(150)
        right_layout.addWidget(self.ai_summary)

        right_layout.addWidget(QLabel('Live Alerts:'))
        self.alert_list = QListWidget(self)
        self.alert_list.setMaximumHeight(120)
        right_layout.addWidget(self.alert_list)

        history_header = QHBoxLayout()
        history_header.addWidget(QLabel('Alert History:'))
        history_header.addStretch()
        self.clear_history_button = QPushButton('Clear History', self)
        self.clear_history_button.clicked.connect(self.clear_alert_history)
        history_header.addWidget(self.clear_history_button)
        right_layout.addLayout(history_header)
        self.alert_history_list = QListWidget(self)
        self.alert_history_list.setMaximumHeight(150)
        right_layout.addWidget(self.alert_history_list)

        self.packet_list.currentItemChanged.connect(self.show_packet_details)
        self.packet_list.itemClicked.connect(self.on_packet_clicked)
        self.pause_button.setChecked(self.paused)

    def _make_packet_key(self, packet):
        return str(
            packet.get('id')
            or packet.get('timestamp')
            or f"{packet.get('src')}-{packet.get('dst')}-{packet.get('summary')}-{packet.get('proto')}"
        )

    def update_refresh_interval(self, value):
        self.refresh_interval_seconds = value
        if not self.paused:
            self.timer.setInterval(value * 1000)
        self.save_settings()

    def ensure_local_agent(self):
        if self.agent_host not in ('localhost', '127.0.0.1'):
            return
        if self.agent_process and self.agent_process.poll() is None:
            return

        agent_script = Path(__file__).parent / 'network_guardian_agent' / 'agent.py'
        if not agent_script.exists():
            self.status_label.setText('Agent file missing. Please reinstall the app.')
            return

        try:
            self.agent_process = subprocess.Popen([sys.executable, str(agent_script)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.status_label.setText('Starting local agent...')
            time.sleep(1.5)
        except Exception as exc:
            self.status_label.setText(f'Agent failed to start: {exc}')

    def refresh_packets(self, manual: bool = False):
        if self.paused and not manual:
            return
        if self.refresh_in_progress:
            return
        self.refresh_in_progress = True
        if manual:
            self.status_label.setText('Refreshing…')
        if hasattr(self, 'refresh_button'):
            self.refresh_button.setEnabled(False)
        try:
            resp = requests.get(f'{self.agent_url}/packets', timeout=2)
            pkts = resp.json()
            visible_packets = pkts[-MAX_VISIBLE_PACKETS:] if pkts else []
            self.visible_packets = visible_packets
            bundles = []
            for pkt in visible_packets:
                insight = analyze_packet(pkt)
                key = self._make_packet_key(pkt)
                bundles.append({'key': key, 'packet': pkt, 'insight': insight})
                if insight.risk_level in {'High', 'Critical'}:
                    self._record_alert_history(key, pkt, insight)
            self.packet_bundle = bundles
            self.render_packet_list()
            self.status_label.setText('Connected to agent')
            self._set_agent_health(True)
        except Exception as e:
            self.status_label.setText(f'Agent connection error: {e}')
            self._set_agent_health(False, str(e))
            self.ensure_local_agent()
        finally:
            self.refresh_in_progress = False
            if hasattr(self, 'refresh_button'):
                self.refresh_button.setEnabled(True)

    def render_packet_list(self):
        if not hasattr(self, 'packet_list'):
            return
        filter_text = ''
        if hasattr(self, 'filter_input') and self.filter_input:
            filter_text = self.filter_input.text().strip().lower()
        self.packet_list.blockSignals(True)
        self.packet_list.clear()
        self.packet_analysis = {}
        alert_entries = []
        for entry in self.packet_bundle:
            key = entry['key']
            pkt = entry['packet']
            insight = entry['insight']
            if filter_text and not self._entry_matches_filter(entry, filter_text):
                continue
            self.packet_analysis[key] = entry
            label = f"[{insight.risk_level}] {pkt.get('summary', 'Unknown traffic')}"
            item = QListWidgetItem(label)
            item.setData(Qt.UserRole, key)
            item.setData(PACKET_ROLE, pkt)
            item.setData(INSIGHT_ROLE, insight)
            color = RISK_COLORS.get(insight.risk_level)
            if color:
                item.setForeground(color)
            self.packet_list.addItem(item)
            if insight.risk_level in {'High', 'Critical'}:
                alert_entries.append(f"{insight.risk_level}: {pkt.get('summary', 'Unknown traffic')}")
        self.packet_list.blockSignals(False)
        self.alert_list.clear()
        for alert in alert_entries[-5:]:
            alert_item = QListWidgetItem(alert)
            level = alert.split(':', 1)[0]
            color = RISK_COLORS.get(level)
            if color:
                alert_item.setForeground(color)
            self.alert_list.addItem(alert_item)
        self._restore_selection()

    def _entry_matches_filter(self, entry, filter_text: str) -> bool:
        tokens = filter_text.split()
        pkt = entry['packet']
        insight = entry['insight']
        haystack = ' '.join(
            [
                str(pkt.get('src', '')),
                str(pkt.get('dst', '')),
                str(pkt.get('proto', '')),
                str(pkt.get('summary', '')),
                insight.risk_level,
                str(insight.risk_score),
            ]
        ).lower()
        return all(token in haystack for token in tokens)

    def _record_alert_history(self, key: str, pkt: dict, insight: Insight):
        if not hasattr(self, 'alert_history_list'):
            return
        if key in self.alert_history_keys:
            return
        self.alert_history_keys.add(key)
        self.alert_history_queue.append(key)
        timestamp = pkt.get('timestamp') or datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        summary = pkt.get('summary', 'Unknown traffic')
        text = f"{timestamp} - {insight.risk_level}: {summary}"
        item = QListWidgetItem(text)
        color = RISK_COLORS.get(insight.risk_level)
        if color:
            item.setForeground(color)
        self.alert_history_list.addItem(item)
        while len(self.alert_history_queue) > MAX_ALERT_HISTORY and self.alert_history_list.count():
            self.alert_history_queue.pop(0)
            self.alert_history_list.takeItem(0)
        if insight.risk_level == 'Critical' and self.tray_icon:
            self.tray_icon.showMessage('Critical Alert', text, QSystemTrayIcon.Critical, 10000)

    def clear_alert_history(self):
        if hasattr(self, 'alert_history_list'):
            self.alert_history_list.clear()
        self.alert_history_keys.clear()
        self.alert_history_queue.clear()
        self.status_label.setText('Alert history cleared.')

    def _restore_selection(self):
        if not self.last_selected_key:
            self.packet_details.clear()
            self.ai_summary.clear()
            return
        for row in range(self.packet_list.count()):
            item = self.packet_list.item(row)
            if item.data(Qt.UserRole) == self.last_selected_key:
                self.packet_list.blockSignals(True)
                self.packet_list.setCurrentItem(item)
                self.packet_list.blockSignals(False)
                self._display_packet_item(item)
                return
        self.packet_details.clear()
        self.ai_summary.clear()

    def on_packet_clicked(self, item):
        if item:
            self._display_packet_item(item)

    def show_packet_details(self, current, previous):
        if current:
            self._display_packet_item(current)
        else:
            self.packet_details.clear()
            self.ai_summary.clear()
            self.last_selected_key = None

    def _display_packet_item(self, item):
        key = item.data(Qt.UserRole) or item.text()
        pkt = item.data(PACKET_ROLE)
        insight = item.data(INSIGHT_ROLE)
        if pkt is None or insight is None:
            bundle = self.packet_analysis.get(key)
            if bundle:
                pkt = bundle['packet']
                insight = bundle['insight']
        if pkt is None or insight is None:
            self.packet_details.setText('Details unavailable.')
            self.ai_summary.clear()
            self.last_selected_key = None
            return
        self.last_selected_key = key
        details = '\n'.join([f'{k}: {v}' for k, v in pkt.items()])
        self.packet_details.setText(details)
        ai_text = (
            f"Risk Score: {insight.risk_score}/10\n"
            f"Risk Level: {insight.risk_level}\n"
            f"Summary: {insight.summary}\n"
            f"Recommended Action: {insight.recommendation}"
        )
        self.ai_summary.setText(ai_text)

    def toggle_pause(self, checked):
        self.paused = checked
        self.apply_pause_state()
        self.save_settings()

    def apply_pause_state(self, update_status: bool = True):
        if not hasattr(self, 'pause_button'):
            return
        if self.paused:
            if self.timer.isActive():
                self.timer.stop()
            self.pause_button.setText('Resume Updates')
            if update_status:
                self.status_label.setText('Updates paused')
        else:
            self.timer.setInterval(self.refresh_interval_seconds * 1000)
            if not self.timer.isActive():
                self.timer.start()
            self.pause_button.setText('Pause Updates')
            if update_status:
                self.status_label.setText('Connected to agent')
        if self.tray_pause_action:
            self.tray_pause_action.setText('Resume Updates' if self.paused else 'Pause Updates')

    def save_settings(self):
        self.settings.setValue('refresh_interval', self.refresh_interval_seconds)
        self.settings.setValue('paused', self.paused)
        self.settings.setValue('geometry', self.saveGeometry())

    def _set_agent_health(self, online: bool, detail: str | None = None):
        text = 'Agent: Online' if online else 'Agent: Offline'
        if detail:
            text = f"{text} ({detail})"
        color = '#2ecc71' if online else '#e74c3c'
        self.agent_health_label.setText(text)
        self.agent_health_label.setStyleSheet(f'color: {color};')

    def check_agent_health(self):
        try:
            resp = requests.get(f'{self.agent_url}/health', timeout=2)
            resp.raise_for_status()
            detail = ''
            try:
                payload = resp.json()
                detail = payload.get('status') or payload.get('message') or ''
            except ValueError:
                detail = 'ok'
            self._set_agent_health(True, detail)
            self.status_label.setText('Agent heartbeat successful')
        except Exception as exc:
            self._set_agent_health(False, str(exc))
            self.status_label.setText(f'Agent health check failed: {exc}')

    def export_packets(self):
        if not self.packet_list.count():
            self.status_label.setText('No packets to export.')
            return
        EXPORT_DIR.mkdir(exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        file_path = EXPORT_DIR / f'packets_{timestamp}.csv'
        headers = ['timestamp', 'src', 'dst', 'src_port', 'dst_port', 'proto', 'summary', 'risk_level', 'risk_score', 'recommendation']
        count = 0
        with file_path.open('w', newline='', encoding='utf-8') as handle:
            writer = csv.writer(handle)
            writer.writerow(headers)
            for row in range(self.packet_list.count()):
                item = self.packet_list.item(row)
                pkt = item.data(PACKET_ROLE)
                insight = item.data(INSIGHT_ROLE)
                if pkt is None:
                    continue
                if insight is None:
                    insight = analyze_packet(pkt)
                writer.writerow([
                    pkt.get('timestamp', ''),
                    pkt.get('src', ''),
                    pkt.get('dst', ''),
                    pkt.get('src_port', ''),
                    pkt.get('dst_port', ''),
                    pkt.get('proto', ''),
                    pkt.get('summary', ''),
                    insight.risk_level,
                    insight.risk_score,
                    insight.recommendation,
                ])
                count += 1
        self.status_label.setText(f'Exported {count} packets to {file_path.resolve()}')

    def open_update_page(self):
        try:
            webbrowser.open(UPDATE_CHECK_URL, new=1)
            self.status_label.setText('Opening update page…')
        except Exception as exc:
            self.status_label.setText(f'Unable to open browser: {exc}')

    def setup_tray_icon(self):
        if not QSystemTrayIcon.isSystemTrayAvailable():
            self.tray_icon = None
            return
        self.tray_icon = QSystemTrayIcon(self.windowIcon(), self)
        self.tray_icon.setToolTip('Sentinel OneLink')
        menu = QMenu(self)
        show_action = QAction('Show Dashboard', self)
        show_action.triggered.connect(self.show_dashboard)
        menu.addAction(show_action)
        self.tray_pause_action = QAction('Pause Updates', self)
        self.tray_pause_action.triggered.connect(self.toggle_pause_from_tray)
        menu.addAction(self.tray_pause_action)
        exit_action = QAction('Exit', self)
        exit_action.triggered.connect(self.quit_from_tray)
        menu.addAction(exit_action)
        self.tray_icon.setContextMenu(menu)
        self.tray_icon.activated.connect(self.on_tray_icon_activated)
        self.tray_icon.show()
        self.apply_pause_state(update_status=False)

    def show_dashboard(self):
        self.show()
        self.raise_()
        self.activateWindow()
        self.tray_message_shown = False

    def toggle_pause_from_tray(self, checked=False):
        new_state = not self.paused
        if hasattr(self, 'pause_button'):
            self.pause_button.blockSignals(True)
            self.pause_button.setChecked(new_state)
            self.pause_button.blockSignals(False)
        self.toggle_pause(new_state)

    def on_tray_icon_activated(self, reason):
        if reason in (QSystemTrayIcon.Trigger, QSystemTrayIcon.DoubleClick):
            self.show_dashboard()

    def quit_from_tray(self):
        self.force_quit = True
        if self.tray_icon:
            self.tray_icon.hide()
        self.close()

    def closeEvent(self, event):
        if not self.force_quit and self.tray_icon:
            event.ignore()
            self.hide()
            if not self.tray_message_shown:
                self.tray_icon.showMessage('Sentinel OneLink', 'Still running in the tray. Right-click the icon to exit.', QSystemTrayIcon.Information, 5000)
                self.tray_message_shown = True
            return
        try:
            if self.agent_process and self.agent_process.poll() is None:
                self.agent_process.terminate()
                self.agent_process.wait(timeout=2)
        except Exception:
            pass
        if self.tray_icon:
            self.tray_icon.hide()
        self.save_settings()
        super().closeEvent(event)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    win = VisionDashboard()
    win.show()
    sys.exit(app.exec())
