import json
import os
import ipaddress
import re

from PySide6.QtCore import Qt, Slot
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QHeaderView,
    QLineEdit,
    QMessageBox,
    QSpinBox,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from asset_common import RE_IP
from asset_tasks import DnsResolverTask, FissionTask, ReverseIPTask


class SubdomainDictDialog(QDialog):
    def __init__(self, parent=None, proj_dir=None):
        super().__init__(parent)
        self.setWindowTitle("高级字典配置引擎（动态变体生成）")
        self.resize(600, 500)
        self.proj_dir = proj_dir
        self.setStyleSheet("""
            QDialog { background-color: #0d1117; color: #c9d1d9; font-family: 'Microsoft YaHei'; }
            QTextEdit { background-color: #161b22; border: 1px solid #30363d; color: #c9d1d9; }
            QPushButton { background-color: #238636; color: white; font-weight: bold; padding: 6px; border-radius: 3px; }
            QPushButton:hover { background-color: #2ea043; }
        """)
        self.init_ui()
        self.load_state()

    def init_ui(self):
        root = QVBoxLayout(self)

        path_row = QHBoxLayout()
        self.btn_sel = QPushButton("选择基础字典文件")
        self.btn_sel.clicked.connect(self.select_dict)
        self.lbl_path = QLabel("未加载")
        path_row.addWidget(self.btn_sel)
        path_row.addWidget(self.lbl_path, stretch=1)
        root.addLayout(path_row)

        splitter = QSplitter(Qt.Horizontal)

        prefix_wrap = QWidget()
        prefix_layout = QVBoxLayout(prefix_wrap)
        prefix_layout.setContentsMargins(0, 0, 0, 0)
        prefix_layout.addWidget(QLabel("1. 附加前缀（每行一个，可选）:"))
        self.te_pre = QTextEdit()
        self.te_pre.setPlaceholderText("例如:\ndev-\ntest-\nadmin-\napi-")
        prefix_layout.addWidget(self.te_pre)
        btn_common_pre = QPushButton("加入常用前缀")
        btn_common_pre.setStyleSheet("background-color: #8957e5;")
        btn_common_pre.clicked.connect(
            lambda: self.te_pre.setPlainText(
                "dev-\ntest-\npre-\nuat-\napi-\nadmin-\nbeta-\nstage-\ninternal-"
            )
        )
        prefix_layout.addWidget(btn_common_pre)
        splitter.addWidget(prefix_wrap)

        suffix_wrap = QWidget()
        suffix_layout = QVBoxLayout(suffix_wrap)
        suffix_layout.setContentsMargins(0, 0, 0, 0)
        suffix_layout.addWidget(QLabel("2. 根域名后缀（每行一个，必填）:"))
        self.te_suf = QTextEdit()
        self.te_suf.setPlaceholderText("例如:\ntarget.com\ncorp.local\n.com.cn")
        suffix_layout.addWidget(self.te_suf)
        splitter.addWidget(suffix_wrap)

        root.addWidget(splitter)

        self.cb_enable = QCheckBox("启用外部字典扩展（会显著增加任务量；关闭后只扫描主面板域名）")
        self.cb_enable.setStyleSheet("font-size: 14px; font-weight: bold; color: #e3b341;")
        root.addWidget(self.cb_enable)

        btn_save = QPushButton("保存配置")
        btn_save.clicked.connect(self.save_and_close)
        root.addWidget(btn_save)

    def select_dict(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "选择无差别碰撞字典",
            "",
            "Text Files (*.txt);;All Files (*)",
        )
        if path:
            self.lbl_path.setText(path)
            self.lbl_path.setToolTip(path)
            self.cb_enable.setChecked(True)

    def save_and_close(self):
        if self.cb_enable.isChecked() and not os.path.exists(self.lbl_path.text()):
            return QMessageBox.warning(self, "错误", "已启用字典功能，但字典路径不存在。")
        self.save_state()
        self.accept()

    def save_state(self):
        if not self.proj_dir:
            return
        try:
            with open(os.path.join(self.proj_dir, "dict_config.json"), "w", encoding="utf-8") as handle:
                json.dump(
                    {
                        "enabled": self.cb_enable.isChecked(),
                        "path": self.lbl_path.text(),
                        "prefixes": self.te_pre.toPlainText(),
                        "suffixes": self.te_suf.toPlainText(),
                    },
                    handle,
                    ensure_ascii=False,
                )
        except Exception:
            pass

    def load_state(self):
        if not self.proj_dir:
            return
        path = os.path.join(self.proj_dir, "dict_config.json")
        if not os.path.exists(path):
            return
        try:
            with open(path, "r", encoding="utf-8") as handle:
                state = json.load(handle)
            self.cb_enable.setChecked(state.get("enabled", False))
            self.lbl_path.setText(state.get("path", "未加载"))
            self.te_pre.setPlainText(state.get("prefixes", ""))
            self.te_suf.setPlainText(state.get("suffixes", ""))
        except Exception:
            pass


class CustomBindDialog(QDialog):
    def __init__(self, parent=None, proj_dir=None):
        super().__init__(parent)
        self.setWindowTitle("自定义 Host 绑定（指定内网 IP / 绕过 CDN）")
        self.resize(550, 400)
        self.proj_dir = proj_dir
        self.ips = []
        self.domains = []
        self.setStyleSheet("""
            QDialog { background-color: #0d1117; color: #c9d1d9; font-family: 'Microsoft YaHei'; }
            QTextEdit { background-color: #161b22; border: 1px solid #30363d; color: #c9d1d9; }
            QPushButton { background-color: #238636; color: white; font-weight: bold; padding: 8px; border-radius: 3px; }
            QPushButton:hover { background-color: #2ea043; }
        """)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        form = QHBoxLayout()

        domain_col = QVBoxLayout()
        domain_col.addWidget(QLabel("1. 对应的域名（每行一个）:"))
        self.domain_edit = QTextEdit()
        self.domain_edit.setPlaceholderText("例如: inner.target.com")
        domain_col.addWidget(self.domain_edit)
        form.addLayout(domain_col)

        ip_col = QVBoxLayout()
        ip_col.addWidget(QLabel("2. 强制绑定的 IP（每行一个）:"))
        self.ip_edit = QTextEdit()
        self.ip_edit.setPlaceholderText("例如: 192.168.1.100")
        ip_col.addWidget(self.ip_edit)
        form.addLayout(ip_col)

        layout.addLayout(form)

        self.btn_confirm = QPushButton("确定绑定并注入主面板")
        self.btn_confirm.clicked.connect(self.accept_data)
        layout.addWidget(self.btn_confirm)

    def accept_data(self):
        self.ips = [item.strip() for item in self.ip_edit.toPlainText().split("\n") if item.strip()]
        self.domains = [
            item.strip() for item in self.domain_edit.toPlainText().split("\n") if item.strip()
        ]

        if not self.ips or not self.domains:
            QMessageBox.warning(self, "提示", "IP 和域名都不能为空。")
            return

        for ip in self.ips:
            if re.search(r"[g-zG-Z]", ip):
                QMessageBox.warning(
                    self,
                    "格式异常",
                    f"在 IP 框中检测到异常字符：\n【{ip}】\n\n请确认右侧输入的是纯 IP。",
                )
                return

        if self.proj_dir:
            path = os.path.join(self.proj_dir, "domain_to_ip.json")
            cache = {}
            if os.path.exists(path):
                try:
                    with open(path, "r", encoding="utf-8") as handle:
                        cache = json.load(handle)
                except Exception:
                    pass

            for domain in self.domains:
                clean_domain = domain.split(":")[0]
                cache.setdefault(clean_domain, [])
                for ip in self.ips:
                    clean_ip = ip.split(":")[0]
                    if clean_ip not in cache[clean_domain]:
                        cache[clean_domain].append(clean_ip)

            try:
                with open(path, "w", encoding="utf-8") as handle:
                    json.dump(cache, handle, indent=4, ensure_ascii=False)
            except Exception:
                pass

        self.accept()



class RealIPHunterDialog(QDialog):
    def __init__(self, parent=None, ip_pool_widget=None, proj_dir=None):
        super().__init__(parent)
        self.setWindowTitle("真实IP猎手 - 绕过 CDN/WAF 探测引擎")
        self.resize(1000, 600)
        self.ip_pool_widget = ip_pool_widget 
        self.proj_dir = proj_dir
        self.setStyleSheet("""
            QDialog { background-color: #0d1117; color: #c9d1d9; }
            QTableWidget { background-color: #161b22; border: 1px solid #30363d; gridline-color: #30363d; }
            QHeaderView::section { background-color: #21262d; border: 1px solid #30363d; font-weight:bold; color: #c9d1d9; }
            QPushButton { background-color: #238636; color: white; font-weight: bold; padding: 6px; border-radius: 3px; }
            QPushButton:hover { background-color: #2ea043; }
            QTextEdit { background-color: #161b22; border: 1px solid #30363d; color: #c9d1d9; }
        """)
        self.init_ui()
        self.load_state()
    def init_ui(self):
        ml = QVBoxLayout(self)
        sp = QSplitter(Qt.Horizontal)
        
        left_w = QWidget(); ll = QVBoxLayout(left_w)
        ll.setContentsMargins(0,0,0,0)
        ll.addWidget(QLabel("待探测的子域名列表（每行一个）:"))
        self.input_doms = QTextEdit()
        self.input_doms.textChanged.connect(self.save_state) # 瀹炴椂淇濆瓨
        self.input_doms.setPlaceholderText("sub.target.com\napi.target.com\n...")
        ll.addWidget(self.input_doms)
        
        self.btn_run = QPushButton("开始并发溯源分析")
        self.btn_run.clicked.connect(self.start_resolve)
        ll.addWidget(self.btn_run)
        sp.addWidget(left_w)
        
        right_w = QWidget(); rl = QVBoxLayout(right_w)
        rl.setContentsMargins(0,0,0,0)
        self.tb = QTableWidget(0, 4)
        self.tb.setHorizontalHeaderLabels(["域名 (Domain)", "解析 IP (A Record)", "别名 (CNAME)", "资产诊断"])
        self.tb.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.tb.horizontalHeader().setStretchLastSection(True)
        self.tb.setColumnWidth(0, 180); self.tb.setColumnWidth(1, 130); self.tb.setColumnWidth(2, 200)
        self.tb.setSortingEnabled(True)
        rl.addWidget(self.tb)
        
        hl = QHBoxLayout()
        self.btn_extract_all = QPushButton("提取全部成功 IP 到主界面")
        self.btn_extract_all.setStyleSheet("background-color: #1f6feb;")
        self.btn_extract_all.clicked.connect(lambda: self.extract_ips(all_ips=True))
        
        self.btn_extract_real = QPushButton("仅提取【真实源站】IP 到主界面（推荐）")
        self.btn_extract_real.setStyleSheet("background-color: #8957e5;")
        self.btn_extract_real.clicked.connect(lambda: self.extract_ips(all_ips=False))
        
        hl.addWidget(self.btn_extract_all); hl.addWidget(self.btn_extract_real)
        rl.addLayout(hl)
        sp.addWidget(right_w)
        sp.setStretchFactor(0, 1); sp.setStretchFactor(1, 3)
        ml.addWidget(sp)

    # ========== 状态保存与恢复（包含表格结果） ==========
    def save_state(self):
        if not self.proj_dir: return
        results = []
        for r in range(self.tb.rowCount()):
            # 安全读取表格项，避免空对象异常
            i_dom = self.tb.item(r, 0)
            i_ip = self.tb.item(r, 1)
            i_cname = self.tb.item(r, 2)
            i_status = self.tb.item(r, 3)
            
            # 没有单元格时写空字符串，保证恢复过程稳定
            results.append({
                "dom": i_dom.text() if i_dom else "", 
                "ip": i_ip.text() if i_ip else "",
                "cname": i_cname.text() if i_cname else "", 
                "status": i_status.text() if i_status else ""
            })
            
        try:
            json.dump({
                "doms": self.input_doms.toPlainText(), "results": results
            }, open(os.path.join(self.proj_dir, "hunter.json"), 'w', encoding='utf-8'))
        except: pass

    def load_state(self):
        if not self.proj_dir: return
        p = os.path.join(self.proj_dir, "hunter.json")
        if os.path.exists(p):
            try:
                data = json.load(open(p, 'r', encoding='utf-8'))
                self.input_doms.blockSignals(True)
                self.input_doms.setPlainText(data.get("doms", ""))
                self.input_doms.blockSignals(False)
                
                self.tb.setRowCount(0)
                for res in data.get("results", []):
                    self.add_row(res["dom"], res["ip"], res["cname"], res["status"])
            except: pass

    def on_finish(self):
        self.tb.setSortingEnabled(True)
        self.btn_run.setEnabled(True); self.btn_run.setText("开始并发溯源分析")
        self.save_state()
        QMessageBox.information(self, "完成", "资产溯源分析完毕。")

    def start_resolve(self):
        doms = [d.strip() for d in self.input_doms.toPlainText().split('\n') if d.strip()]
        if not doms: return
        self.tb.setSortingEnabled(False)
        self.tb.setRowCount(0)
        self.btn_run.setEnabled(False); self.btn_run.setText("分析中...")
        
        self.thread = DnsResolverTask(doms)
        self.thread.res_sig.connect(self.add_row)
        self.thread.fin_sig.connect(self.on_finish)
        self.thread.start()

    @Slot(str, str, str, str)
    def add_row(self, dom, ip, cname, status):
        r = self.tb.rowCount()
        self.tb.insertRow(r)
        
        i_dom = QTableWidgetItem(dom)
        i_ip = QTableWidgetItem(ip)
        i_cname = QTableWidgetItem(cname)
        i_status = QTableWidgetItem(status)
        
        if "源站" in status:
            i_status.setForeground(QColor(88, 166, 255))
        elif "CDN" in status:
            i_status.setForeground(QColor(139, 148, 158))
        else:
            i_status.setForeground(QColor(248, 81, 73))
            
        self.tb.setItem(r, 0, i_dom); self.tb.setItem(r, 1, i_ip)
        self.tb.setItem(r, 2, i_cname); self.tb.setItem(r, 3, i_status)

    def extract_ips(self, all_ips):
        if not self.ip_pool_widget: return
        extracted = set()
        
        bindings_to_save = {}

        for row in range(self.tb.rowCount()):
            dom_item = self.tb.item(row, 0)
            ip_item = self.tb.item(row, 1)
            status_item = self.tb.item(row, 3)
            
            if not ip_item or not status_item or not dom_item: continue
            dom, ip, status = dom_item.text(), ip_item.text(), status_item.text()
            
            if "无效" in status or "失败" in ip: continue
            if not all_ips and "CDN" in status: continue
            
            extracted.add(ip)
            
            clean_dom = dom.split(':')[0]
            clean_ip = ip.split(':')[0]
            if clean_dom not in bindings_to_save: bindings_to_save[clean_dom] = []
            if clean_ip not in bindings_to_save[clean_dom]: bindings_to_save[clean_dom].append(clean_ip)
            
        if not extracted: return QMessageBox.warning(self, "提示", "没有符合条件的有效 IP 可提取。")
        
        if self.proj_dir and bindings_to_save:
            p = os.path.join(self.proj_dir, "domain_to_ip.json")
            cache = {}
            if os.path.exists(p):
                try: cache = json.load(open(p, 'r', encoding='utf-8'))
                except: pass
            
            for d, ips in bindings_to_save.items():
                if d not in cache: cache[d] = []
                for i in ips:
                    if i not in cache[d]: cache[d].append(i)
            try: json.dump(cache, open(p, 'w', encoding='utf-8'), indent=4)
            except: pass

        current_text = self.ip_pool_widget.toPlainText()
        existing_lines = [line.strip() for line in current_text.split('\n') if line.strip()]
        new_ips = [x for x in extracted if x not in set(existing_lines)]
        
        if new_ips:
            final_lines = existing_lines + new_ips
            self.ip_pool_widget.setPlainText("\n".join(final_lines) + "\n")
            QMessageBox.information(self, "成功", f"提取了 {len(new_ips)} 个 IP，并已自动建立底层域名绑定关系。")
        else:
            QMessageBox.information(self, "提示", "提取的 IP 已经全部存在于主界面中，绑定关系也已刷新。")


class IPFissionDialog(QDialog):
    def __init__(self, parent=None, ip_pool_widget=None, proj_dir=None):
        super().__init__(parent)
        self.setWindowTitle("资产裂变与指纹提纯引擎（C段狙击手）")
        self.resize(1100, 650)
        self.ip_pool_widget = ip_pool_widget
        self.proj_dir = proj_dir
        self.setStyleSheet("""
            QDialog { background-color: #0d1117; color: #c9d1d9; font-family: 'Microsoft YaHei'; }
            QTableWidget { background-color: #161b22; border: 1px solid #30363d; }
            QHeaderView::section { background-color: #21262d; border: 1px solid #30363d; font-weight:bold; }
            QPushButton { background-color: #238636; color: white; font-weight: bold; padding: 7px; border-radius: 3px; }
            QPushButton:hover { background-color: #2ea043; }
            QTextEdit, QLineEdit { background-color: #161b22; border: 1px solid #30363d; color: #c9d1d9; padding: 5px; }
        """)
        self.init_ui()
        self.load_state()
    def init_ui(self):
        ml = QVBoxLayout(self)
        sp = QSplitter(Qt.Horizontal)
        
        left_w = QWidget(); ll = QVBoxLayout(left_w); ll.setContentsMargins(0,0,0,0)
        ll.addWidget(QLabel("1. 输入种子 IP（支持单 IP 或网段）:"))
        self.input_ips = QTextEdit()
        self.input_ips.textChanged.connect(self.save_state)
        ll.addWidget(self.input_ips, stretch=2)
        
        btn_c = QPushButton("一键扩展 C 段（转为 /24）")
        btn_c.setStyleSheet("background-color: #8957e5;")
        btn_c.clicked.connect(self.expand_c_class)
        ll.addWidget(btn_c)
        
        ll.addWidget(QLabel("\n2. Title 关键词匹配（逗号分隔）:"))
        self.input_kws = QLineEdit()
        self.input_kws.textChanged.connect(self.save_state)
        ll.addWidget(self.input_kws)

        ll.addWidget(QLabel("\n3. Web 端口探测（逗号分隔）:"))
        self.input_ports = QLineEdit()
        self.input_ports.setText("80, 443, 8080, 8443, 8888, 7001")
        self.input_ports.textChanged.connect(self.save_state)
        ll.addWidget(self.input_ports)
        
        hl_threads = QHBoxLayout()
        hl_threads.addWidget(QLabel("\n4. 线程并发数:"))
        self.spin_threads = QSpinBox()
        self.spin_threads.setRange(10, 3000)
        self.spin_threads.setValue(200)
        self.spin_threads.setStyleSheet("background-color: #161b22; color: #c9d1d9; padding: 4px;")
        self.spin_threads.valueChanged.connect(self.save_state)
        hl_threads.addWidget(self.spin_threads)
        ll.addLayout(hl_threads)

        run_layout = QHBoxLayout()
        self.btn_run = QPushButton("启动并发测绘")
        self.btn_run.clicked.connect(self.start_scan)
        
        self.btn_stop = QPushButton("停止")
        self.btn_stop.setStyleSheet("background-color: #da3633;")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.stop_scan)
        
        run_layout.addWidget(self.btn_run, stretch=3)
        run_layout.addWidget(self.btn_stop, stretch=1)
        ll.addLayout(run_layout)
        
        sp.addWidget(left_w)
        
        right_w = QWidget(); rl = QVBoxLayout(right_w); rl.setContentsMargins(0,0,0,0)
        self.tb = QTableWidget(0, 3)
        self.tb.setHorizontalHeaderLabels(["存活 URL", "页面 Title", "提纯诊断"])
        self.tb.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.tb.horizontalHeader().setStretchLastSection(True)
        self.tb.setColumnWidth(0, 220); self.tb.setColumnWidth(1, 400)
        self.tb.setSortingEnabled(True)
        rl.addWidget(self.tb)
        
        self.btn_ext = QPushButton("将【精准命中】的 IP 注入主战 IP 池")
        self.btn_ext.setStyleSheet("background-color: #1f6feb; height: 35px; font-size: 14px;")
        self.btn_ext.clicked.connect(self.extract_to_main)
        rl.addWidget(self.btn_ext)
        sp.addWidget(right_w)
        sp.setStretchFactor(0, 1); sp.setStretchFactor(1, 3)
        ml.addWidget(sp)

    def save_state(self):
        if self.proj_dir:
            try:
                json.dump({
                    "ips": self.input_ips.toPlainText(), 
                    "kws": self.input_kws.text(), 
                    "ports": self.input_ports.text(),
                    "threads": self.spin_threads.value(),
                }, open(os.path.join(self.proj_dir, "fission.json"), 'w'))
            except: pass

    def load_state(self):
        if self.proj_dir and os.path.exists(os.path.join(self.proj_dir, "fission.json")):
            try:
                self.input_ips.blockSignals(True)
                self.input_kws.blockSignals(True)
                self.input_ports.blockSignals(True)
                self.spin_threads.blockSignals(True)
                
                s = json.load(open(os.path.join(self.proj_dir, "fission.json")))
                self.input_ips.setPlainText(s.get("ips", ""))
                self.input_kws.setText(s.get("kws", ""))
                self.input_ports.setText(s.get("ports", "80, 443, 8080, 8443, 8888, 7001"))
                self.spin_threads.setValue(s.get("threads", 200))
                self.input_ips.blockSignals(False)
                self.input_kws.blockSignals(False)
                self.input_ports.blockSignals(False)
                self.spin_threads.blockSignals(False)
            except: pass

    def closeEvent(self, event):
        if hasattr(self, 'work_thread') and self.work_thread.isRunning():
            self.work_thread._stop = True
            self.btn_stop.setText("正在安全退出...")
            self.work_thread.wait(1500) 
        event.accept()

    def stop_scan(self):
        if hasattr(self, 'work_thread') and self.work_thread.isRunning():
            self.work_thread._stop = True
            self.btn_stop.setEnabled(False); self.btn_stop.setText("正在强杀请求...")

    def expand_c_class(self):
        text = self.input_ips.toPlainText()
        raw_ips = re.findall(RE_IP, text)
        c_classes = set()
        for ip in raw_ips:
            try:
                clean_ip = ip.split(':')[0]
                net = ipaddress.ip_network(f"{clean_ip}/24", strict=False)
                c_classes.add(str(net))
            except: pass
        if c_classes:
            self.input_ips.setPlainText("\n".join(c_classes))
            QMessageBox.information(self, "拓扑成功", f"已自动计算并去重，生成 {len(c_classes)} 个 C 段。")

    def start_scan(self):
        text = self.input_ips.toPlainText()
        raw_lines = [line.strip() for line in text.split('\n') if line.strip()]
        target_ips = set()
        for line in raw_lines:
            try:
                if '/' in line: 
                    net = ipaddress.ip_network(line, strict=False)
                    for ip in net.hosts(): target_ips.add(str(ip))
                else: target_ips.add(line.split(':')[0])
            except: pass

        if not target_ips: return QMessageBox.warning(self, "提示", "未发现有效 IP 或网段。")
        self.tb.setSortingEnabled(False); self.tb.setRowCount(0)
        self.btn_run.setEnabled(False); self.btn_run.setText(f"正在测绘 {len(target_ips)} 个独立 IP...")
        self.btn_stop.setEnabled(True); self.btn_stop.setText("停止")
        
        local_concurrency = self.spin_threads.value()

        self.work_thread = FissionTask(list(target_ips), self.input_kws.text(), self.input_ports.text(), local_concurrency)
        self.work_thread.res_sig.connect(self.add_row)
        self.work_thread.fin_sig.connect(self.on_finish)
        self.work_thread.start()

    @Slot(str, str, str, str)
    def add_row(self, url, title, status, color):
        r = self.tb.rowCount(); self.tb.insertRow(r)
        i_url = QTableWidgetItem(url); i_url.setForeground(QColor(color))
        i_title = QTableWidgetItem(title); i_title.setForeground(QColor(color))
        i_status = QTableWidgetItem(status); i_status.setForeground(QColor(color))
        self.tb.setItem(r, 0, i_url); self.tb.setItem(r, 1, i_title); self.tb.setItem(r, 2, i_status)

    def on_finish(self):
        self.tb.setSortingEnabled(True)
        self.btn_run.setEnabled(True); self.btn_run.setText("启动并发测绘")
        self.btn_stop.setEnabled(False); self.btn_stop.setText("停止")
        QMessageBox.information(self, "完成", "C 段指纹测绘已完成，无效资产已静默丢弃。")

    def extract_to_main(self):
        if not self.ip_pool_widget: return
        extracted = set()
        for row in range(self.tb.rowCount()):
            status_item = self.tb.item(row, 2)
            url_item = self.tb.item(row, 0)
            if status_item and url_item and "命中" in status_item.text():
                clean_ip = url_item.text().replace("http://", "").replace("https://", "").split(':')[0]
                extracted.add(clean_ip)
                
        if not extracted: return QMessageBox.warning(self, "提示", "没有【精准命中】的目标可以提取。")
        
        current_text = self.ip_pool_widget.toPlainText()
        existing_lines = [line.strip() for line in current_text.split('\n') if line.strip()]
        new_ips = [x for x in extracted if x not in set(existing_lines)]
        
        if new_ips:
            final_lines = existing_lines + new_ips
            self.ip_pool_widget.setPlainText("\n".join(final_lines) + "\n")
            QMessageBox.information(self, "成功", f"提纯完成，已将 {len(new_ips)} 个高价值 IP 注入主界面。")
        else:
            QMessageBox.information(self, "提示", "提取的 IP 已经全部存在于主界面中。")


class ReverseIPDialog(QDialog):
    def __init__(self, parent=None, dom_pool_widget=None, ips=None, proj_dir=None):
        super().__init__(parent)
        self.setWindowTitle("IP 反查域名引擎（扩大碰撞面）")
        self.resize(800, 500)
        self.dom_pool_widget = dom_pool_widget
        self.ips = ips or []
        self.proj_dir = proj_dir
        self.setStyleSheet("""
            QDialog { background-color: #0d1117; color: #c9d1d9; font-family: 'Microsoft YaHei'; }
            QTableWidget { background-color: #161b22; border: 1px solid #30363d; gridline-color: #30363d;}
            QHeaderView::section { background-color: #21262d; border: 1px solid #30363d; font-weight:bold; }
            QPushButton { background-color: #8957e5; color: white; font-weight: bold; padding: 6px; border-radius: 3px; }
            QPushButton:hover { background-color: #9e6cf2; }
            QTextEdit { background-color: #161b22; border: 1px solid #30363d; color: #c9d1d9; }
        """)
        self.init_ui()
        self.load_state()
    def init_ui(self):
        ml = QVBoxLayout(self)
        sp = QSplitter(Qt.Horizontal)
        
        left_w = QWidget(); ll = QVBoxLayout(left_w); ll.setContentsMargins(0,0,0,0)
        ll.addWidget(QLabel("待反查的 IP（已自动从主战池同步）:"))
        self.input_ips = QTextEdit()
        if not self.input_ips.toPlainText():
            self.input_ips.setPlainText("\n".join(self.ips))
        self.input_ips.textChanged.connect(self.save_state)
        ll.addWidget(self.input_ips)
        
        self.btn_run = QPushButton("开始反查旁站域名")
        self.btn_run.clicked.connect(self.start_reverse)
        ll.addWidget(self.btn_run)
        sp.addWidget(left_w)
        
        right_w = QWidget(); rl = QVBoxLayout(right_w); rl.setContentsMargins(0,0,0,0)
        self.tb = QTableWidget(0, 2)
        self.tb.setHorizontalHeaderLabels(["源 IP", "反查出的旁站域名"])
        self.tb.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.tb.horizontalHeader().setStretchLastSection(True)
        self.tb.setColumnWidth(0, 150)
        rl.addWidget(self.tb)
        
        self.btn_ext = QPushButton("将新域名追加到主战域名池")
        self.btn_ext.setStyleSheet("background-color: #238636;")
        self.btn_ext.clicked.connect(self.extract_domains)
        rl.addWidget(self.btn_ext)
        sp.addWidget(right_w)
        
        ml.addWidget(sp)

    def save_state(self):
        if not self.proj_dir: return
        results = []
        for r in range(self.tb.rowCount()):
            i_ip = self.tb.item(r, 0)
            i_dom = self.tb.item(r, 1)
            
            results.append({
                "ip": i_ip.text() if i_ip else "", 
                "dom": i_dom.text() if i_dom else ""
            })
            
        try:
            json.dump({
                "ips": self.input_ips.toPlainText(), "results": results
            }, open(os.path.join(self.proj_dir, "reverse_ip.json"), 'w', encoding='utf-8'))
        except: pass

    def load_state(self):
        if not self.proj_dir: return
        p = os.path.join(self.proj_dir, "reverse_ip.json")
        if os.path.exists(p):
            try:
                data = json.load(open(p, 'r', encoding='utf-8'))
                self.input_ips.blockSignals(True)
                self.input_ips.setPlainText(data.get("ips", ""))
                self.input_ips.blockSignals(False)
                
                self.tb.setRowCount(0)
                for res in data.get("results", []):
                    self.add_row(res["ip"], res["dom"])
            except: pass

    def start_reverse(self):
        ips = [ip.strip() for ip in self.input_ips.toPlainText().split('\n') if ip.strip() and re.match(RE_IP, ip.strip())]
        if not ips: return
        self.tb.setRowCount(0)
        self.btn_run.setEnabled(False); self.btn_run.setText("查询中...")
        
        self.work_thread = ReverseIPTask(list(set(ips)))
        self.work_thread.res_sig.connect(self.add_row)
        self.work_thread.fin_sig.connect(self.on_finish)
        self.work_thread.start()

    @Slot(str, str)
    def add_row(self, ip, domain):
        r = self.tb.rowCount()
        self.tb.insertRow(r)
        self.tb.setItem(r, 0, QTableWidgetItem(ip))
        it_dom = QTableWidgetItem(domain)
        if "暂无" not in domain: it_dom.setForeground(QColor(88, 166, 255))
        else: it_dom.setForeground(QColor(139, 148, 158))
        self.tb.setItem(r, 1, it_dom)

    def on_finish(self):
        self.btn_run.setEnabled(True); self.btn_run.setText("开始反查旁站域名")
        self.save_state()
        QMessageBox.information(self, "完成", "IP 反查已完成。")

    def extract_domains(self):
        if not self.dom_pool_widget: return
        extracted = set()
        bindings_to_save = {}

        for r in range(self.tb.rowCount()):
            ip_item = self.tb.item(r, 0)
            dom_item = self.tb.item(r, 1)
            if not ip_item or not dom_item: continue
            
            ip = ip_item.text()
            dom = dom_item.text()
            
            if dom and "暂无" not in dom:
                extracted.add(dom)

                clean_dom = dom.split(':')[0]
                clean_ip = ip.split(':')[0]
                if clean_dom not in bindings_to_save: bindings_to_save[clean_dom] = []
                if clean_ip not in bindings_to_save[clean_dom]: bindings_to_save[clean_dom].append(clean_ip)
                
        if not extracted: return QMessageBox.warning(self, "提示", "没有有效的新域名可供提取。")

        if self.proj_dir and bindings_to_save:
            p = os.path.join(self.proj_dir, "domain_to_ip.json")
            cache = {}
            if os.path.exists(p):
                try: cache = json.load(open(p, 'r', encoding='utf-8'))
                except: pass
            
            for d, ips in bindings_to_save.items():
                if d not in cache: cache[d] = []
                for i in ips:
                    if i not in cache[d]: cache[d].append(i)
            try: json.dump(cache, open(p, 'w', encoding='utf-8'), indent=4)
            except: pass

        current_text = self.dom_pool_widget.toPlainText()
        existing_lines = [line.strip() for line in current_text.split('\n') if line.strip()]
        new_doms = [x for x in extracted if x not in set(existing_lines)]
        
        if new_doms:
            final_lines = existing_lines + new_doms
            self.dom_pool_widget.setPlainText("\n".join(final_lines) + "\n")
            QMessageBox.information(self, "成功", f"追加了 {len(new_doms)} 个新域名，并已自动建立 IP 绑定关系。")
        else:
            QMessageBox.information(self, "提示", "反查出的域名已经在池中，绑定关系也已刷新。")

    def closeEvent(self, event):
        if hasattr(self, 'work_thread') and self.work_thread.isRunning():
            self.work_thread._stop = True
            self.work_thread.wait(1500)
        event.accept()

__all__ = [
    "CustomBindDialog",
    "IPFissionDialog",
    "RealIPHunterDialog",
    "ReverseIPDialog",
    "SubdomainDictDialog",
]
