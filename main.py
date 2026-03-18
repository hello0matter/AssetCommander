import sys
import os
import re
import asyncio
import aiohttp
import subprocess
from datetime import datetime
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QTextEdit, QLineEdit, QPushButton, 
                             QLabel, QTableWidget, QTableWidgetItem, QSplitter,
                             QHeaderView, QGroupBox)
from PySide6.QtCore import Qt, QThread, Signal, Slot
from PySide6.QtGui import QTextCursor

# ================= 强力正则：资产提取器 =================
# 匹配 IP:PORT 或 纯IP
RE_IP_PORT = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?::\d+)?\b'
# 匹配 域名
RE_DOMAIN = r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'

# ================= 外部工具异步执行器 =================
class ToolThread(QThread):
    log_signal = Signal(str, str)
    asset_signal = Signal(str)

    def __init__(self, name, cmd):
        super().__init__()
        self.name = name
        self.cmd = cmd

    def run(self):
        self.log_signal.emit("INFO", f"正在调用 {self.name}: {self.cmd}")
        try:
            # 使用 subprocess 管道获取输出
            process = subprocess.Popen(
                self.cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                shell=True, text=True, encoding='utf-8', errors='ignore'
            )
            while True:
                line = process.stdout.readline()
                if not line: break
                if line.strip():
                    self.log_signal.emit("DEBUG", f"[{self.name}] {line.strip()}")
                    self.asset_signal.emit(line.strip())
            process.wait()
            self.log_signal.emit("SUCCESS", f"{self.name} 执行完毕")
        except Exception as e:
            self.log_signal.emit("ERROR", f"执行失败: {str(e)}")

# ================= 高性能异步碰撞引擎 =================
class CollisionThread(QThread):
    log_signal = Signal(str, str)
    result_signal = Signal(dict)

    def __init__(self, ips, domains):
        super().__init__()
        self.ips = ips
        self.domains = domains

    async def worker(self, session, ip, domain):
        url = f"http://{ip}" if "://" not in ip else ip
        try:
            # 1. IP 直接访问
            async with session.get(url, timeout=4, allow_redirects=False) as rb:
                base_len = len(await rb.text())
                base_code = rb.status
            # 2. Host 碰撞访问
            async with session.get(url, headers={"Host": domain}, timeout=4, allow_redirects=False) as rh:
                text = await rh.text()
                hit_len = len(text)
                hit_code = rh.status
                
                # 判定：状态码变了 或 长度变化 > 200字节
                if hit_code != base_code or abs(hit_len - base_len) > 200:
                    title = re.search(r'<title>(.*?)</title>', text, re.I)
                    title = title.group(1).strip() if title else "N/A"
                    self.result_signal.emit({
                        "ip": ip, "host": domain, "code": hit_code, "len": hit_len, "title": title
                    })
                    self.log_signal.emit("SUCCESS", f"🔥 碰撞命中: {ip} -> {domain}")
        except: pass

    def run(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        async def run_all():
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
                tasks = [self.worker(session, ip, dom) for ip in self.ips for dom in self.domains]
                await asyncio.gather(*tasks)
        loop.run_until_complete(run_all())
        self.log_signal.emit("INFO", "碰撞扫描任务已完成")

# ================= 主 GUI 界面 =================
class AssetCommander(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AssetCommander - 资产指挥官 [uv-managed]")
        self.resize(1100, 750)
        self.ips = set()
        self.domains = set()
        self.init_ui()

    def init_ui(self):
        # 黑色系配色
        self.setStyleSheet("""
            QMainWindow { background-color: #0d1117; }
            QWidget { color: #c9d1d9; font-family: 'Segoe UI', 'Consolas'; }
            QLineEdit { background-color: #161b22; border: 1px solid #30363d; padding: 6px; border-radius: 4px; }
            QPushButton { background-color: #238636; color: white; border-radius: 4px; padding: 8px 15px; font-weight: bold; }
            QPushButton:hover { background-color: #2ea043; }
            QTextEdit { background-color: #0d1117; border: 1px solid #30363d; border-radius: 4px; }
            QTableWidget { background-color: #161b22; gridline-color: #30363d; border: 1px solid #30363d; }
            QHeaderView::section { background-color: #21262d; padding: 4px; border: 1px solid #30363d; }
        """)

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)

        # 顶部输入栏
        top = QHBoxLayout()
        self.target_edit = QLineEdit()
        self.target_edit.setPlaceholder_text("输入扫描目标 (如: 192.168.1.0/24 或 example.com)")
        self.btn_scan = QPushButton("一键调用 fscan")
        self.btn_scan.clicked.connect(self.run_fscan)
        top.addWidget(QLabel("Target:"))
        top.addWidget(self.target_edit)
        top.addWidget(self.btn_scan)
        layout.addLayout(top)

        # 中间资产池与结果
        splitter = QSplitter(Qt.Horizontal)
        
        # 左侧资产列表
        left_box = QWidget()
        left_layout = QVBoxLayout(left_box)
        self.ip_pool = QTextEdit()
        self.ip_pool.setPlaceholder_text("IP 资产池 (自动清洗填充)")
        self.dom_pool = QTextEdit()
        self.dom_pool.setPlaceholder_text("域名 资产池 (自动清洗填充)")
        self.btn_collide = QPushButton("开始 Host 碰撞")
        self.btn_collide.setStyleSheet("background-color: #8957e5;")
        self.btn_collide.clicked.connect(self.run_collision)
        
        left_layout.addWidget(QLabel("IP:Port 池:"))
        left_layout.addWidget(self.ip_pool)
        left_layout.addWidget(QLabel("Host 池:"))
        left_layout.addWidget(self.dom_pool)
        left_layout.addWidget(self.btn_collide)

        # 右侧结果表
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["IP Target", "Host", "Code", "Len", "Title"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        
        splitter.addWidget(left_box)
        splitter.addWidget(self.table)
        splitter.setStretchFactor(1, 2)
        layout.addWidget(splitter)

        # 底部日志
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setFixedHeight(150)
        layout.addWidget(QLabel("执行日志:"))
        layout.addWidget(self.log_view)

    @Slot(str, str)
    def update_log(self, level, msg):
        time = datetime.now().strftime("%H:%M:%S")
        colors = {"INFO": "#58a6ff", "SUCCESS": "#3fb950", "ERROR": "#f85149", "DEBUG": "#8b949e"}
        color = colors.get(level, "#c9d1d9")
        self.log_view.append(f'<span style="color:#8b949e">[{time}]</span> <span style="color:{color}">[{level}]</span> {msg}')
        self.log_view.moveCursor(QTextCursor.End)

    @Slot(str)
    def clean_assets(self, text):
        # 实时自动清洗 IP 和 域名
        ips = re.findall(RE_IP_PORT, text)
        doms = re.findall(RE_DOMAIN, text)
        for ip in ips:
            if ip not in self.ips:
                self.ips.add(ip)
                self.ip_pool.append(ip)
        for d in doms:
            if d not in self.domains:
                self.domains.add(d)
                self.dom_pool.append(d)

    def run_fscan(self):
        target = self.target_edit.text().strip()
        if not target: return
        # 假设 fscan.exe 在同一目录下
        cmd = f"fscan.exe -h {target} -p 80,443,8080,8443 -nopoc"
        self.thread = ToolThread("FScan", cmd)
        self.thread.log_signal.connect(self.update_log)
        self.thread.asset_signal.connect(self.clean_assets)
        self.thread.start()

    def run_collision(self):
        ips = [i.strip() for i in self.ip_pool.toPlainText().split('\n') if i.strip()]
        doms = [d.strip() for d in self.dom_pool.toPlainText().split('\n') if d.strip()]
        if not ips or not doms:
            self.update_log("ERROR", "弹药不足，请先填充资产池")
            return
        self.coll_thread = CollisionThread(ips, doms)
        self.coll_thread.log_signal.connect(self.update_log)
        self.coll_thread.result_signal.connect(self.add_result)
        self.coll_thread.start()

    def add_result(self, d):
        row = self.table.rowCount()
        self.table.insertRow(row)
        self.table.setItem(row, 0, QTableWidgetItem(d["ip"]))
        self.table.setItem(row, 1, QTableWidgetItem(d["host"]))
        self.table.setItem(row, 2, QTableWidgetItem(str(d["code"])))
        self.table.setItem(row, 3, QTableWidgetItem(str(d["len"])))
        self.table.setItem(row, 4, QTableWidgetItem(d["title"]))

if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = AssetCommander()
    win.show()
    sys.exit(app.exec())