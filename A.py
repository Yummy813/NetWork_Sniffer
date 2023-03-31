import sys
import pyshark
from PyQt5.QtWidgets import QApplication, QMainWindow, QTreeView, QTableView, QSplitter, QVBoxLayout, QWidget, QLineEdit, QAbstractItemView, QHeaderView, QAction, QToolBar, QLabel, QPushButton, QComboBox
from PyQt5.QtCore import Qt, QAbstractTableModel, QModelIndex, QVariant, QThreadPool, QRunnable, QSize, QTimer
from PyQt5.QtGui import QStandardItemModel, QStandardItem, QColor, QFont, QIcon
import threading
from pyshark.tshark.tshark import get_tshark_interfaces
import asyncio
import time
import nest_asyncio
import multiprocessing
import copy
import random
import subprocess
import warnings
import psutil
import os

# 忽略所有警告
warnings.filterwarnings("ignore")

# 重定向标准错误到空设备或文件
if sys.platform == "win32":
    null_device = "nul"
else:
    null_device = "/dev/null"

# 注意：使用 'a' 模式以免覆盖现有内容
with open(null_device, "a") as dev_null:
    sys.stderr = dev_null

PacketNumber = 0

class PacketListModel(QAbstractTableModel):
    def __init__(self, packets=None):
        super().__init__()
        self.packets = packets or []
        self.headers = ["No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"]

    def rowCount(self, parent=None, *args, **kwargs):
        return len(self.packets)

    def columnCount(self, parent=None, *args, **kwargs):
        return len(self.headers)

    def headerData(self, section, orientation, role=None):
        if role == Qt.DisplayRole:
            if orientation == Qt.Horizontal:
                return self.headers[section]

    def data(self, index, role=None):
        if not index.isValid():
            return QVariant()

        if role == Qt.DisplayRole:
            packet = self.packets[index.row()]
            column = index.column()
            if column == 0:
                return str(packet.number)
            elif column == 1:
                return str(packet.sniff_time)
            elif column == 2:
                if hasattr(packet, 'ip'):
                    return str(packet.ip.src)
                elif hasattr(packet, 'ipv6'):
                    return str(packet.ipv6.src)
                elif hasattr(packet, 'dns'):
                    return str(packet.ip.src)
                elif hasattr(packet, 'arp'):
                    return str(packet.arp.src.hw_mac)
                else:
                    return "No IP layer available"
            elif column == 3:
                if hasattr(packet, 'ip'):
                    return str(packet.ip.dst)
                elif hasattr(packet, 'ipv6'):
                    return str(packet.ipv6.dst)
                elif hasattr(packet, 'dns'):
                    return str(packet.ip.dst)
                elif hasattr(packet, 'arp'):
                    return str(packet.arp.dst.hw_mac)
                else:
                    return "No IP layer available"
            elif column == 4:
                if 'DATA' in str(packet.highest_layer[:len(packet.highest_layer)-4]):
                    return str(packet.layers[-2]._layer_name[:-4]).upper()
                else:
                    return str(packet.highest_layer[:len(packet.highest_layer)-4])
            elif column == 5:
                return str(packet.length)
            elif column == 6:
                if hasattr(packet, 'tcp'):
                    return str(packet.tcp.srcport+' -> '+packet.tcp.dstport+' Len='+packet.tcp.len)
                elif hasattr(packet, 'udp'):
                    return str(packet.udp.srcport+' -> '+packet.udp.dstport+' Len='+str(int(packet.udp.length)-8))
                elif hasattr(packet, 'icmpv6'):
                    return str(packet.icmpv6.type)
                elif hasattr(packet, 'oicq'):
                    return str(packet.oicq.flag)
                elif hasattr(packet, 'http'):
                    return str(packet.text)
                elif hasattr(packet, 'tlsv1.2'):
                    return str(packet.tls.record.content_type)
                elif hasattr(packet, 'dns'):
                    return str(packet.dns.qry.name)
                elif hasattr(packet, 'tlsv1.3'):
                    return str(packet.tls.record.content_type)
                elif hasattr(packet, 'icmp'):
                    return str(packet.icmp.type)
                elif hasattr(packet, 'arp'):
                    if 'request' in packet.arp.opcode:
                        return 'Who has '+str(packet.arp.dst.proto_ipv4)+'? Tell '+str(packet.arp.src.proto_ipv4)
                    else:
                        return str(packet.arp.src.proto_ipv4)+' is at '+str(packet.arp.src.hw_mac)
                else:
                    return "No info available"
        elif role == Qt.BackgroundRole:
            packet = self.packets[index.row()]
            protocol = str(packet.highest_layer[:len(packet.highest_layer)-4])
            if 'DATA' in protocol:
                protocol = str(packet.layers[-2]._layer_name[:-4]).upper()
            if protocol == 'TCP':
                return QColor(255, 192, 203)
            elif protocol == 'UDP':
                return QColor(173, 216, 230)
            elif protocol == 'OICQ':
                return QColor(204, 153, 255)
            elif protocol == 'ICMP':
                return QColor(152, 251, 152)
            elif protocol == 'TLS':
                return QColor(255, 255, 153)
            elif protocol == 'HTTP':
                return QColor(255, 182, 193)
            elif protocol == 'DNS':
                return QColor(224, 255, 255)
            elif protocol == 'ICMPV6':
                return QColor(193, 226, 240)
            elif protocol == 'SSDP':
                return QColor(211, 211, 211)
            elif protocol == 'ARP':
                return QColor(245, 245, 220)
            elif protocol == 'MDNS':
                return QColor(224, 255, 255)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Sniffer")
        self.setGeometry(100, 100, 1500, 800)

        self.capture = None
        self.stop = False
        self.packet_list_model = PacketListModel()
        self.packet_list = QTreeView()
        self.packet_list.setModel(self.packet_list_model)
        self.packet_details_model = QStandardItemModel()
        self.packet_details = QTreeView()
        self.packet_details.setModel(self.packet_details_model)
        self.packet_details.setHeaderHidden(True)
        self.capture_thread = None

        self.packet_binary_model = QStandardItemModel()
        self.packet_binary = QTreeView()
        self.packet_binary.setModel(self.packet_binary_model)
        self.packet_binary.setHeaderHidden(True)

        self.packet_list.selectionModel().selectionChanged.connect(self.display_packet_details_and_binary)

        self.packet_list.header().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.packet_details.header().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.packet_binary.header().setSectionResizeMode(QHeaderView.ResizeToContents)

        self.timer = QTimer()
        self.timer.setInterval(5000)  # 设置时间间隔为5秒
        self.timer.timeout.connect(self.enable_button)

         # 创建三个按钮
        self.start_button = QPushButton(QIcon('icons/play.ico'), '开始抓包')
        self.stop_button = QPushButton(QIcon('icons/stop.ico'), '停止抓包')
        self.clear_button = QPushButton(QIcon('icons/clear.ico'), '清空当前')
        self.select_button = QPushButton(QIcon('icons/select.png'), '筛选结果')

        # 将三个按钮添加到工具栏
        toolbar = QToolBar('导航栏')
        toolbar.setIconSize(QSize(32, 32))
        toolbar.setToolButtonStyle(Qt.ToolButtonTextUnderIcon)
        toolbar.addWidget(self.start_button)
        toolbar.addWidget(self.stop_button)
        toolbar.addWidget(self.clear_button)
        toolbar.addWidget(self.select_button)
        self.addToolBar(toolbar)

        # 绑定事件处理函数
        self.start_button.clicked.connect(self.start_capture)
        self.stop_button.clicked.connect(self.stop_capture)
        self.clear_button.clicked.connect(self.clear_capture)
        self.select_button.clicked.connect(self.apply_filter)

        self.init_ui()
        # self.start_capture()

    def enable_button(self):
        self.select_button.setEnabled(True)
        self.timer.stop()

    def run_command_without_console(self, command):
        startupinfo = None
        if sys.platform == "win32":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE

        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE, startupinfo=startupinfo)
        stdout, stderr = process.communicate()

        return stdout, stderr

    def get_tshark_interfaces(self):
        # 调用修改后的函数
        # command = [".\\Wireshark\\tshark", "-D"]
        # stdout, stderr = self.run_command_without_console(command)
        # output = stdout.decode("utf-8")
        output = subprocess.check_output([".\\Wireshark\\tshark", "-D"]).decode("utf-8")
        lines = output.strip().split('\n')
        
        interfaces = []
        for line in lines:
            iface = line.split('. ')[1]
            interfaces.append(iface)
        res = []
        for i in interfaces:
            res.append(i.split('(')[1].split(')')[0].lower())

        return res

    def display_packet_details_and_binary(self, selected, deselected):
        selected_packet_index = selected.indexes()[0]
        packet = self.packet_list_model.packets[selected_packet_index.row()]
        print(packet)

        # 展示包的详细信息
        self.packet_details_model.clear()
        Max = 100
        for layer in packet.layers:
            layer_item = QStandardItem(f"{layer.layer_name}: {layer.layer_name.upper()}")
            layer_item.setEditable(False)
            for field in layer.field_names:
                field_value = getattr(layer, field)
                Max = max(Max, len(f"{field}: {field_value}"))
                field_item = QStandardItem(f"{field}: {field_value}")
                field_item.setEditable(False)
                layer_item.appendRow(field_item)
            self.packet_details_model.appendRow(layer_item)
        self.packet_details.setColumnWidth(0, Max*10)

        # 展示包的二进制形式和ASCII码转储
        self.packet_binary_model.clear()
        hex_packet = packet.frame_raw.value
        byte_offset = 0
        bytes_per_row = 32
        while byte_offset < len(hex_packet):
            hex_data = []
            for i in range(byte_offset, min(byte_offset + 32, len(hex_packet)), 2):
                hex_data.append(f"{hex_packet[i:i+2]}")
            hex_data_str = " ".join(hex_data)
            offset_item = QStandardItem(f"{byte_offset//2:04x}  {hex_data_str}")
            string = QStandardItem(self.hex_to_ascii_dump(hex_data_str.replace(' ','')))
            offset_item.setEditable(False)
            string.setEditable(False)
            self.packet_binary_model.appendRow([offset_item, string])
            byte_offset += bytes_per_row
        self.packet_binary.setColumnWidth(0, 600)
        self.packet_binary.setColumnWidth(1, 600)

    def hex_to_ascii_dump(self, hex_str):
        output = ""
        for i in range(0, len(hex_str), 2):
            decimal_int = int(hex_str[i:i+2], 16)
            if 32 <= decimal_int <= 126:  # 可打印的ASCII字符范围
                character = chr(decimal_int)
            else:
                character = "."  # 使用"."替代非可打印的字符
            output += character
        return output

    def init_ui(self):
        layout = QVBoxLayout()

        # 增加选择接口功能
        # 创建一个QComboBox
        self.combo_box1 = QComboBox()
        self.combo_box1.setEditable(False)  # 设置为可编辑
        self.combo_box1.setPlaceholderText("这里选择你要抓包的接口")

        # 添加下拉选项
        for i in self.get_tshark_interfaces():
            self.combo_box1.addItem(str(i))
        self.combo_box1.setCurrentIndex(0)
        layout.addWidget(self.combo_box1)

        # Add packet filter
        # 创建一个QComboBox
        self.combo_box2 = QComboBox()
        self.combo_box2.setEditable(True)  # 设置为可编辑
        self.combo_box2.setPlaceholderText("Enter filter (e.g., tcp, udp, ip.src == 192.168.0.1)")

        # 添加下拉选项
        self.combo_box2.addItem('tcp')
        self.combo_box2.addItem('udp')
        self.combo_box2.addItem('http')
        self.combo_box2.addItem('arp')
        self.combo_box2.addItem('icmp')
        layout.addWidget(self.combo_box2)

        splitter = QSplitter(Qt.Vertical)
        splitter.addWidget(self.packet_list)
        splitter.addWidget(self.packet_details)
        splitter.addWidget(self.packet_binary)

        layout.addWidget(splitter)

        # 更新头的功能
        self.packet_list.header().setStretchLastSection(False)
        self.packet_list.header().setSectionResizeMode(QHeaderView.Interactive)
        self.packet_details.header().setStretchLastSection(False)
        self.packet_details.header().setSectionResizeMode(QHeaderView.Interactive)
        self.packet_binary.header().setStretchLastSection(False)
        self.packet_binary.header().setSectionResizeMode(QHeaderView.Interactive)


        central_widget = QWidget()
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)


    def start_capture(self, display_filter=None, interface='wlan'):
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        interface = self.combo_box1.currentText()
        display_filter = self.combo_box2.currentText()
        if self.capture_thread == None:
            self.capture_thread = threading.Thread(target=self.capture_packets, args=(display_filter, interface, ))
            self.capture_thread.daemon = True
            self.capture_thread.start()
        self.stop = False


    def stop_capture(self):
        self.stop_button.setEnabled(False)
        self.start_button.setEnabled(True)
        self.stop = True
        try:
            self.capture_thread.join(1)
        except:
            pass
        try:
            self.loop.close()
            asyncio.set_event_loop(None)
        except:
            pass
        self.capture_thread = None
        try:
            self.capture.close()
        except:
            pass
        self.capture = None

    def clear_capture(self):
        self.packet_list_model.beginResetModel()
        self.packet_list_model.packets = []
        self.packet_list_model.layoutChanged.emit()
        self.packet_list_model.endResetModel()
        self.packet_details_model.beginResetModel()
        self.packet_details_model.clear()
        self.packet_details_model.layoutChanged.emit()
        self.packet_details_model.endResetModel()
        self.packet_binary_model.beginResetModel()
        self.packet_binary_model.clear()
        self.packet_binary_model.layoutChanged.emit()
        self.packet_binary_model.endResetModel()


        global PacketNumber
        PacketNumber = 0

    def capture_packets(self, display_filter=None, interface='wlan'):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        while not self.stop:
            if self.capture == None:
                self.capture = pyshark.LiveCapture(display_filter=display_filter, use_json=True, include_raw=True, interface=interface, 
                                                    tshark_path='.\\Wireshark\\tshark.exe')
            global PacketNumber
            for packet in self.capture.sniff_continuously(packet_count=0):
                if self.stop:
                    break
                PacketNumber += 1
                packet.number=PacketNumber
                self.process_packet(packet)

    def process_packet(self, packet):
        self.packet_list_model.packets.append(packet)
        last_index = self.packet_list_model.rowCount() - 1
        self.packet_list_model.beginInsertRows(QModelIndex(), last_index, last_index)
        self.packet_list_model.endInsertRows()

    def apply_filter(self):
        self.select_button.setEnabled(False)
        self.timer.start()
        display_filter = self.combo_box2.currentText()
        self.stop_capture()
        self.clear_capture()
        self.start_capture(display_filter)

    def get_process_id_by_name(self, process_name):
        process_ids = []
        for process in psutil.process_iter(['pid', 'name']):
            if process.info['name'] == process_name:
                process_ids.append(process.info['pid'])
        return process_ids

    def kill_process_by_id(self, pid):
        try:
            process = psutil.Process(pid)
            process.terminate()
            process.wait(timeout=3)
            print(f"进程ID {pid} 已经成功终止。")
        except psutil.NoSuchProcess:
            print(f"找不到进程ID {pid}。")
        except psutil.TimeoutExpired:
            print(f"进程ID {pid} 终止超时，尝试强制结束。")
            try:
                process.kill()
                process.wait(timeout=3)
                print(f"进程ID {pid} 已经成功强制结束。")
            except Exception as e:
                print(f"无法结束进程ID {pid}，错误：{e}")
        except Exception as e:
            print(f"无法结束进程ID {pid}，错误：{e}")

    def closeEvent(self, event):
        # 执行其他关闭操作
        self.start_capture() # 这个函数是为了同时关闭子线程
        self.stop_capture()
        process_ids = self.get_process_id_by_name('dumpcap.exe')
        for i in process_ids:
            self.kill_process_by_id(i)
        event.accept()  # 接受关闭事件，关闭窗口

if __name__ == "__main__":
    app = QApplication(sys.argv)
    main_window = MainWindow()
    main_window.show()
    sys.exit(app.exec_())
