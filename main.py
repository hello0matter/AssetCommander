import sys, os, re, asyncio, subprocess, json, socket, ipaddress, csv
from datetime import datetime
from PySide6.QtCore import Qt, Slot, QTimer
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                               QHBoxLayout, QTextEdit, QLineEdit, QPushButton, 
                               QLabel, QTableWidget, QTableWidgetItem, QSplitter,
                               QHeaderView, QGroupBox, QCheckBox, QFileDialog, 
                               QInputDialog, QMessageBox, QSpinBox, QDialog,
                               QGridLayout, QProgressBar)
from PySide6.QtGui import QTextCursor, QColor
from asset_common import (
    FAIL_SAMPLE_FILE,
    LOW_RISK_UI_LIMIT,
    PROJECT_COPY_FILES,
    RE_AST,
    RE_DOM,
    RE_IP,
    RESULT_FIELDS,
    SCAN_PROGRESS_FILE,
    WORKSPACE_DIR,
    get_base_config,
    install_global_crash_handlers,
    normalize_task_record,
    write_global_log,
)
from asset_dialogs import (
    CustomBindDialog,
    IPFissionDialog,
    RealIPHunterDialog,
    ReverseIPDialog,
    SubdomainDictDialog,
)
from asset_engine import CollTask
from asset_project import (
    append_csv_rows,
    append_lines,
    default_project_root,
    fail_sample_path,
    is_subpath,
    open_local_path,
    overwrite_csv_rows,
    read_progress_state,
    save_settings,
    save_text_file,
    write_progress_state,
)


CONFIDENCE_SORT_WEIGHT = {
    "极危": 0,
    "高危": 1,
    "中危": 2,
    "低危": 3,
}
MEDIUM_RISK_UI_LIMIT = 4000

MOJIBAKE_CONFIDENCE_MAP = {
    "6942樺嵄": "高危",
    "楂樺嵄": "高危",
    "✅ 高危": "高危",
    "9241": "高危",
    "6935": "中危",
    "涓嵄": "中危",
    "⚠️ 中危": "中危",
    "⚠ 中危": "中危",
    "93cb佸嵄": "极危",
    "鏋佸嵄": "极危",
    "🔥 极危": "极危",
    "6d63庡嵄": "低危",
    "浣庡嵄": "低危",
    "ℹ️ 低危": "低危",
    "ℹ 低危": "低危",
}


def normalize_confidence_label(value):
    raw = str(value or "").strip()
    if not raw:
        return ""

    if "极危" in raw or "🔥" in raw:
        return "极危"
    if "高危" in raw or "✅" in raw:
        return "高危"
    if "中危" in raw or "⚠" in raw:
        return "中危"
    if "低危" in raw or "ℹ" in raw or "🛈" in raw:
        return "低危"

    for pattern, normalized in MOJIBAKE_CONFIDENCE_MAP.items():
        if pattern in raw:
            return normalized

    cleaned = (
        raw.replace("✅", "")
        .replace("⚠️", "")
        .replace("⚠", "")
        .replace("🔥", "")
        .replace("ℹ️", "")
        .replace("ℹ", "")
        .strip()
    )
    return cleaned


def normalize_result_row(row_data):
    normalized = {field: row_data.get(field, "") for field in RESULT_FIELDS}
    raw_conf = str(normalized.get("conf", "") or "").strip()
    normalized_conf = normalize_confidence_label(raw_conf)
    normalized["conf"] = normalized_conf
    changed = normalized_conf != raw_conf
    return normalized, changed


class SortableTableWidgetItem(QTableWidgetItem):
    def __lt__(self, other):
        if isinstance(other, QTableWidgetItem):
            self_key = self.data(Qt.UserRole)
            other_key = other.data(Qt.UserRole)
            if self_key is not None and other_key is not None:
                return self_key < other_key
        return super().__lt__(other)


class AssetCommander(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AssetCommander V3.5 - 智能资产过滤版")
        self.resize(1450, 950)
        self.config = get_base_config()
        if not os.path.exists(WORKSPACE_DIR): os.makedirs(WORKSPACE_DIR)
        self.proj = None
        self.ips, self.doms = set(), set()
        self.init_ui()
        self.last_scan_stats = {}
        self.csv_buffer = []
        self.scanned_buffer = []
        self.scanned_set = set()
        self.scanned_count = 0
        self._pending_scanned_keys = set()
        self.ui_conf_counts = {"极危": 0, "高危": 0, "中危": 0, "低危": 0}
        self._risk_cap_notified = set()
        self.csv_timer = QTimer(self)
        self.csv_timer.timeout.connect(self.flush_csv_buffer)
        self.csv_timer.start(2000)
        self._update_artifact_buttons()

    def select_dict(self):
        path, _ = QFileDialog.getOpenFileName(self, "选择无差别碰撞字典", "", "Text Files (*.txt);;All Files (*)")
        if path:
            self.dict_path = path
            try:
                size_mb = os.path.getsize(path) / (1024 * 1024)
                self.lbl_dict_info.setText(f"已挂载 {os.path.basename(path)} ({size_mb:.2f} MB)")
                self.sv_sett()
            except Exception as e:
                QMessageBox.warning(self, "错误", f"读取字典失败: {e}")

    def inject_internal_hosts(self):
        internal_hosts = [
            "127.0.0.1", "localhost", "127.1", "127.0.1", "0.0.0.0",
            "::1", "[::1]", "0x7f000001", "2130706433", "0177.0.0.1",
            "10.0.0.1", "10.0.0.254", "10.1.1.1", "10.10.10.1",
            "192.168.0.1", "192.168.1.1", "192.168.1.254", "192.168.3.1", "192.168.10.1",
            "172.16.0.1", "172.16.0.254", "172.17.0.1",
            "169.254.169.254", "100.100.100.200",
            "kubernetes.default", "kubernetes.default.svc",
            "docker.for.mac.localhost", "host.docker.internal",
            "localdomain", "broadcasthost", "internal",
        ]

        current_doms = [x.strip() for x in self.d_pl.toPlainText().split('\n') if x.strip()]
        all_doms = current_doms + internal_hosts
        unique_doms = list(dict.fromkeys(all_doms))
        
        self.d_pl.setPlainText("\n".join(unique_doms) + "\n")
        self.log("SUCCESS", f"成功注入 {len(internal_hosts)} 个高价值内网/云原生 Host，已准备好继续测试。")

    def inject_internal_ips(self):
        internal_ips = [
            "10.0.0.1", "10.0.0.254", "10.1.1.1", "10.10.10.1",
            "192.168.0.1", "192.168.1.1", "192.168.1.254", "192.168.3.1", "192.168.10.1", "192.168.100.1",
            "172.16.0.1", "172.16.0.254", 
            "172.17.0.1",
            "169.254.169.254", "100.64.0.1",
            "127.0.0.1", "0.0.0.0"
        ]
        
        current_ips = [x.strip() for x in self.i_pl.toPlainText().split('\n') if x.strip()]
        all_ips = current_ips + internal_ips
        unique_ips = list(dict.fromkeys(all_ips))
        
        self.i_pl.setPlainText("\n".join(unique_ips) + "\n")
        self.log("SUCCESS", f"成功注入 {len(internal_ips)} 个高价值内网 IP（网关 / 元数据 / 回环）。")

    def deduplicate_pools(self):
        for pl in [self.i_pl, self.d_pl]:
            lines = [line.strip() for line in pl.toPlainText().split('\n') if line.strip()]
            unique_lines = list(dict.fromkeys(lines))
            pl.setPlainText("\n".join(unique_lines) + ("\n" if unique_lines else ""))
        self.log("SUCCESS", "资产清理完毕，IP 池与域名池已完成一键去重。")

    def open_custom_bind(self):
        if not self.proj: return QMessageBox.warning(self, "提示", "请先选择或新建一个工程。")
        dlg = CustomBindDialog(self, self.proj)
        if dlg.exec() == QDialog.Accepted:
            # 获取主界面当前数据
            cur_ips = [x.strip() for x in self.i_pl.toPlainText().split('\n') if x.strip()]
            cur_doms = [x.strip() for x in self.d_pl.toPlainText().split('\n') if x.strip()]
            
            # 追加新数据
            all_ips = cur_ips + dlg.ips
            all_doms = cur_doms + dlg.domains
            
            # 自动去重并回填到主界面
            self.i_pl.setPlainText("\n".join(list(dict.fromkeys(all_ips))) + "\n")
            self.d_pl.setPlainText("\n".join(list(dict.fromkeys(all_doms))) + "\n")
            self.log("SUCCESS", f"自定义绑定成功，已注入并去重 {len(dlg.ips)} 个 IP 和 {len(dlg.domains)} 个域名。")
    def open_ip_fission(self):
        self.fission_dialog = IPFissionDialog(self, ip_pool_widget=self.i_pl, proj_dir=self.proj)
        self.fission_dialog.show()

    def open_ip_hunter(self):
        self.hunter_dialog = RealIPHunterDialog(self, ip_pool_widget=self.i_pl, proj_dir=self.proj)
        self.hunter_dialog.show()

    def open_ip_reverse(self):
        ips = [ip.strip() for ip in self.i_pl.toPlainText().split() if ip.strip()]
        self.rev_dialog = ReverseIPDialog(self, dom_pool_widget=self.d_pl, ips=ips, proj_dir=self.proj)
        self.rev_dialog.show()

    def open_dict_ui(self):
        if not self.proj: return QMessageBox.warning(self, "提示", "请先打开或新建一个工程。")
        dlg = SubdomainDictDialog(self, self.proj)
        dlg.exec()
    def init_ui(self):
        self.setStyleSheet("""
            QMainWindow { background-color: #0d1117; }
            QWidget { color: #c9d1d9; font-family: 'Consolas', 'Microsoft YaHei'; }
            QLineEdit, QTextEdit { background-color: #161b22; border: 1px solid #30363d; border-radius:3px; padding:5px; }
            QPushButton { background-color: #238636; color: white; font-weight: bold; border-radius:3px; padding:7px; }
            QPushButton:hover { background-color: #2ea043; }
            QTableWidget { background-color: #161b22; border: 1px solid #30363d; }
            QHeaderView::section { background-color: #21262d; border: 1px solid #30363d; font-weight:bold; }
            QGroupBox { border: 1px solid #30363d; margin-top: 10px; font-weight: bold; }
        """)
        cw = QWidget(); self.setCentralWidget(cw); ml = QVBoxLayout(cw)

        pl = QHBoxLayout(); self.lbl_p = QLabel("当前工程: [未载入]"); self.lbl_p.setStyleSheet("color:#e3b341; font-size:14px;")
        bn = QPushButton("新建工程"); bn.clicked.connect(self.new_p); bo = QPushButton("打开工程"); bo.clicked.connect(self.open_p)
        
        bc = QPushButton("关闭工程")
        bc.setStyleSheet("background-color: #da3633;")
        bc.clicked.connect(self.close_project)
        pl.addWidget(self.lbl_p); pl.addStretch(1);  pl.addWidget(bn); pl.addWidget(bo); pl.addWidget(bc); ml.addLayout(pl)

        tl = QHBoxLayout(); self.t_ed = QLineEdit(); self.t_ed.setPlaceholderText("Target Domain or IP Segment")
        bf = QPushButton("FScan 收割"); bf.clicked.connect(self.run_f); bo_ofa = QPushButton("OFA 收割"); bo_ofa.clicked.connect(self.run_o)
        tl.addWidget(QLabel("目标:")); tl.addWidget(self.t_ed); tl.addWidget(bf); tl.addWidget(bo_ofa); ml.addLayout(tl)
        self.t_ed.textChanged.connect(self.sv_sett)

        sp = QSplitter(Qt.Horizontal); lb = QWidget(); ll = QVBoxLayout(lb)
        self.i_pl = QTextEdit(); self.d_pl = QTextEdit()
        self.i_pl.setLineWrapMode(QTextEdit.NoWrap)
        self.d_pl.setLineWrapMode(QTextEdit.NoWrap)
        self.i_pl.textChanged.connect(lambda: self.sv_f("ips.txt", self.i_pl))
        self.d_pl.textChanged.connect(lambda: self.sv_f("domains.txt", self.d_pl))
        
        # ==========================================
        # 左侧：IP 池与辅助工具
        # ==========================================
        i_header = QHBoxLayout()
        i_header.addWidget(QLabel("IP 池 (ips.txt) [TCP连接目标]:"))
        i_header.addStretch(1)
        ll.addLayout(i_header)

        i_tools = QGridLayout()
        i_tools.setContentsMargins(0, 0, 0, 5)
        i_tools.setSpacing(5)

        btn_fission = QPushButton("C段裂变与提纯")
        btn_fission.setStyleSheet("background-color: #8957e5; padding: 5px; font-size: 12px; border-radius: 4px;")
        btn_fission.clicked.connect(self.open_ip_fission)

        btn_dedup = QPushButton("一键去重")
        btn_dedup.setStyleSheet("background-color: #d29922; padding: 5px; font-size: 12px; border-radius: 4px;")
        btn_dedup.clicked.connect(self.deduplicate_pools)

        btn_internal_ip = QPushButton("注入内网 IP")
        btn_internal_ip.setStyleSheet("background-color: #2ea043; padding: 5px; font-size: 12px; border-radius: 4px;")
        btn_internal_ip.clicked.connect(self.inject_internal_ips)

        i_tools.addWidget(btn_fission, 0, 0)
        i_tools.addWidget(btn_dedup, 0, 1)
        i_tools.addWidget(btn_internal_ip, 1, 0, 1, 2)
        ll.addLayout(i_tools)
        ll.addWidget(self.i_pl)

        # ==========================================
        # 右侧：域名池与辅助工具
        # ==========================================
        d_header = QHBoxLayout()
        d_header.addWidget(QLabel("域名池 (domains.txt) [伪造 Host 身份]:"))
        d_header.addStretch(1)
        ll.addLayout(d_header)

        d_tools = QGridLayout()
        d_tools.setContentsMargins(0, 0, 0, 5)
        d_tools.setSpacing(5)

        btn_hunter = QPushButton("真实 IP 猎手")
        btn_hunter.setStyleSheet("background-color: #238636; padding: 5px; font-size: 12px; border-radius: 4px;")
        btn_hunter.clicked.connect(self.open_ip_hunter)

        btn_reverse = QPushButton("IP 反查域名")
        btn_reverse.setStyleSheet("background-color: #8957e5; padding: 5px; font-size: 12px; border-radius: 4px;")
        btn_reverse.clicked.connect(self.open_ip_reverse)

        btn_bind = QPushButton("强制绑定")
        btn_bind.setStyleSheet("background-color: #1f6feb; padding: 5px; font-size: 12px; border-radius: 4px;")
        btn_bind.clicked.connect(self.open_custom_bind)

        btn_internal_host = QPushButton("注入内网 Host")
        btn_internal_host.setStyleSheet("background-color: #d29922; padding: 5px; font-size: 12px; border-radius: 4px;")
        btn_internal_host.clicked.connect(self.inject_internal_hosts)

        d_tools.addWidget(btn_hunter, 0, 0)
        d_tools.addWidget(btn_reverse, 0, 1)
        d_tools.addWidget(btn_bind, 1, 0)
        d_tools.addWidget(btn_internal_host, 1, 1)

        ll.addLayout(d_tools)
        ll.addWidget(self.d_pl)

        pg = QGroupBox("碰撞策略与高级绕过"); pgl = QVBoxLayout(pg)
        hl1 = QHBoxLayout()
        self.c_k = QCheckBox("保留原端口")
        self.c_8 = QCheckBox("补齐:80")
        self.c_4 = QCheckBox("补齐:443")
        self.c_n = QCheckBox("无端口")
        for c in [self.c_k, self.c_8, self.c_4, self.c_n]:
            c.setChecked(True)
            c.stateChanged.connect(self.sv_sett)
            hl1.addWidget(c)

        hl2 = QHBoxLayout()
        self.c_abs = QCheckBox("绝对路径")
        self.c_waf = QCheckBox("注入 WAF 绕过头")
        self.c_sni = QCheckBox("强同步 SNI")
        for c in [self.c_abs, self.c_waf, self.c_sni]:
            c.stateChanged.connect(self.sv_sett)
            hl2.addWidget(c)
        hl2.addStretch(1)
        pgl.addLayout(hl1)
        pgl.addLayout(hl2)

        self.btn_adv_dict = QPushButton("高级字典配置（防 OOM 模式）")
        self.btn_adv_dict.setStyleSheet("background-color: #d29922; color: white; padding: 6px; border-radius: 4px;")
        self.btn_adv_dict.clicked.connect(self.open_dict_ui)
        ll.addWidget(self.btn_adv_dict)

        hl_ctrl = QHBoxLayout()
        hl_ctrl.addWidget(QLabel("并发:"))
        self.spin_threads = QSpinBox()
        self.spin_threads.setRange(10, 3000)
        self.spin_threads.setValue(150)
        self.spin_threads.setStyleSheet("background-color: #161b22; color: #c9d1d9;")
        hl_ctrl.addWidget(self.spin_threads)

        self.btn_c = QPushButton("启动对撞")
        self.btn_c.clicked.connect(self.run_c)
        hl_ctrl.addWidget(self.btn_c)

        self.btn_stop = QPushButton("停止")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.stop_c)
        hl_ctrl.addWidget(self.btn_stop)

        self.btn_export = QPushButton("导出新工程")
        self.btn_export.setStyleSheet("background-color: #1f6feb;")
        self.btn_export.clicked.connect(self.export_project)
        hl_ctrl.addWidget(self.btn_export)

        self.btn_fail_samples = QPushButton("失败样本")
        self.btn_fail_samples.setStyleSheet("background-color: #d29922;")
        self.btn_fail_samples.clicked.connect(self.show_fail_samples)
        self.btn_fail_samples.setEnabled(False)
        hl_ctrl.addWidget(self.btn_fail_samples)

        # 3. 进度条（占满剩余空间）
        #   self.pg_bar = QProgressBar()
        #   self.pg_bar.setTextVisible(True)
        #   self.pg_bar.setFormat("%v / %m [%p%]")
        #self.pg_bar.setStyleSheet("""
        #       QProgressBar { border: 1px solid #30363d; background-color: #161b22; color: white; border-radius: 4px; text-align: center; font-weight: bold; }
        #    QProgressBar::chunk { background-color: #2ea043; border-radius: 3px; }
        #""")
        #hl_ctrl.addWidget(self.pg_bar, stretch=1)

        # 允许左侧面板在窗口缩小时继续压缩
        lb.setMinimumWidth(200)

        # 将策略和并发控制加入左侧布局
        ll.addWidget(pg)
        ll.addLayout(hl_ctrl)

        sp.addWidget(lb)

        # --- 右侧：结果表格区域 ---
        self.tb = QTableWidget(0, 7)
        self.tb.setHorizontalHeaderLabels(["Target", "Host", "Code", "Len", "Title", "置信度", "智能诊断"])
        self.tb.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.tb.horizontalHeader().setStretchLastSection(True)
        self.tb.setColumnWidth(0, 220)
        self.tb.setColumnWidth(1, 200)
        self._table_sort_active = False
        self._table_sort_column = -1
        self._table_sort_order = Qt.AscendingOrder
        header = self.tb.horizontalHeader()
        header.setSortIndicatorShown(True)
        header.sectionClicked.connect(self.handle_table_sort_click)
        self.tb.setSortingEnabled(False)
        
        sp.addWidget(self.tb); sp.setStretchFactor(1, 2); ml.addWidget(sp)

        self.pg_bar = QProgressBar()
        self.pg_bar.setTextVisible(True)
        self.pg_bar.setFormat("引擎火力全开：对撞进度 %v / %m [%p%]")
        self.pg_bar.setFixedHeight(22)
        self.pg_bar.setStyleSheet("""
            QProgressBar { border: 1px solid #30363d; background-color: #0d1117; color: #58a6ff; border-radius: 4px; text-align: center; font-weight: bold; font-family: 'Microsoft YaHei'; }
            QProgressBar::chunk { background-color: #238636; border-radius: 3px; }
        """)
        ml.addWidget(self.pg_bar)

        self.lv = QTextEdit()
        self.lv.setReadOnly(True)
        self.lv.setFixedHeight(150)
        
        ml.addWidget(QLabel("战地实时审计日志:"))
        ml.addWidget(self.lv)

        self.lv.document().setMaximumBlockCount(2000)
        self.log_buffer = []
        self.log_timer = QTimer(self)
        self.log_timer.timeout.connect(self.flush_log_buffer)
        self.log_timer.start(200)

    # =============== 鏍稿績閫昏緫鍑芥暟 ===============
    def sv_f(self, f, w):
        if not self.proj:
            return
        try:
            save_text_file(self.proj, f, w.toPlainText())
        except Exception:
            pass

    @Slot(str, str)
    def log(self, lvl, m):
        self.log_buffer.append((lvl, m))

    @Slot(int)
    def handle_table_sort_click(self, column):
        if self._table_sort_active and self._table_sort_column == column:
            self._table_sort_order = (
                Qt.DescendingOrder
                if self._table_sort_order == Qt.AscendingOrder
                else Qt.AscendingOrder
            )
        else:
            self._table_sort_active = True
            self._table_sort_column = column
            self._table_sort_order = Qt.AscendingOrder

        self.apply_table_sort()

    def apply_table_sort(self):
        if not getattr(self, "_table_sort_active", False):
            return
        if self._table_sort_column < 0:
            return
        self.tb.sortItems(self._table_sort_column, self._table_sort_order)
        self.tb.horizontalHeader().setSortIndicator(
            self._table_sort_column,
            self._table_sort_order,
        )

    def flush_log_buffer(self):
        if not hasattr(self, 'pending_file_log'):
            self.pending_file_log = ""

        # 1. 先刷新界面日志
        if hasattr(self, 'log_buffer') and self.log_buffer:
            tm = datetime.now().strftime("%H:%M:%S")
            cs = {"INFO":"#58a6ff", "SUCCESS":"#3fb950", "ERROR":"#f85149", "DEBUG":"#8b949e", "FATAL":"#ff0000"}
            gui_html = []
            
            for lvl, m in self.log_buffer:
                gui_html.append(f'<span style="color:#8b949e">[{tm}]</span> <span style="color:{cs.get(lvl,"#fff")}">[{lvl}]</span> {m}')
                self.pending_file_log += f"[{tm}] [{lvl}] {m}\n"
                
            self.lv.append("<br>".join(gui_html))
            self.lv.moveCursor(QTextCursor.End)
            self.log_buffer.clear()

        # 2. 再同步写入磁盘日志
        if self.proj and self.pending_file_log:
            try: 
                with open(os.path.join(self.proj, "runtime.log"), 'a', encoding='utf-8') as f:
                    f.write(self.pending_file_log)
                
                # 只有真正落盘成功，才清空待写缓存
                self.pending_file_log = "" 
            except Exception as e:
                # 写入失败时保留缓存，等待下一个周期继续重试
                pass

    @Slot(str)
    def cln(self, t):
        if not self.proj: return
        self.i_pl.blockSignals(True); self.d_pl.blockSignals(True)
        ip_c, dom_c = False, False

        for i in re.findall(RE_AST, t):
            ci = i.replace("http://","").replace("https://","").strip().split('/')[0]
            if ci not in self.ips: self.ips.add(ci); self.i_pl.append(ci); ip_c = True

        ex = [".html", ".js", ".css", ".py", ".exe", "fscan", "version"]
        for d in re.findall(RE_DOM, t):
            if "." in d and d not in self.doms and not any(x in d.lower() for x in ex):
                self.doms.add(d); self.d_pl.append(d); dom_c = True
                
        self.i_pl.blockSignals(False); self.d_pl.blockSignals(False)
        if ip_c: self.sv_f("ips.txt", self.i_pl)
        if dom_c: self.sv_f("domains.txt", self.d_pl)

    def run_f(self):
        if not self.proj: return QMessageBox.warning(self, "提示", "请先选择工程")
        if hasattr(self, 'th') and self.th.isRunning(): return self.log("ERROR", "外部工具仍在运行，请等待结束。")
        t = self.t_ed.text().strip(); st = t
        try:
            if not re.match(RE_IP, t) and "/" not in t:
                clean_t = t.replace("http://", "").replace("https://", "").split(':')[0].split('/')[0]
                ip = socket.gethostbyname(clean_t)
                st = str(ipaddress.ip_network(f"{ip}/24", False).network_address)+"/24"
        except: pass
        cmd = self.config.get("fscan_cmd", "").replace("{target}", st)
        self.th = ToolTask("FScan", cmd); self.th.log_sig.connect(self.log); self.th.ast_sig.connect(self.cln); self.th.start()

    def run_o(self):
        if not self.proj: return QMessageBox.warning(self, "提示", "请先选择工程")
        if hasattr(self, 'th') and self.th.isRunning(): return self.log("ERROR", "外部工具仍在运行，请等待结束。")
        
        cmd = self.config.get("oneforall_cmd", "").replace("{target}", self.t_ed.text().strip())
        self.th = ToolTask("OFA", cmd); self.th.log_sig.connect(self.log); self.th.ast_sig.connect(self.cln); self.th.start()

    def stop_c(self):
        if hasattr(self, 'cth') and self.cth.isRunning():
            self.log("INFO", "正在发送强制截断指令...")
            self.btn_stop.setEnabled(False); self.btn_stop.setText("截断中...")
            self.cth.stop() 

    def force_save(self):
        if not self.proj: return
        try:
            rows = []
            for row in range(self.tb.rowCount()):
                row_data = {
                    "url": self.tb.item(row, 0).text() if self.tb.item(row, 0) else "",
                    "host": self.tb.item(row, 1).text() if self.tb.item(row, 1) else "",
                    "code": self.tb.item(row, 2).text() if self.tb.item(row, 2) else "",
                    "len": self.tb.item(row, 3).text() if self.tb.item(row, 3) else "",
                    "title": self.tb.item(row, 4).text() if self.tb.item(row, 4) else "",
                    "conf": self.tb.item(row, 5).text() if self.tb.item(row, 5) else "",
                    "remark": self.tb.item(row, 6).text() if self.tb.item(row, 6) else "",
                }
                if row_data["url"]:
                    rows.append(row_data)
            overwrite_csv_rows(os.path.join(self.proj, "results.csv"), RESULT_FIELDS, rows)
            self.log("SUCCESS", "战果已强制覆盖保存，并已转换为标准 CSV 格式。")
            QMessageBox.information(self, "成功", "当前表格数据已完整保存为 CSV，可以直接用 Excel 打开。")
        except Exception as e:
            self.log("ERROR", f"保存失败: {str(e)}")
    def _default_project_root(self):
        return default_project_root(self.proj, WORKSPACE_DIR)

    def _fail_sample_path(self):
        return fail_sample_path(self.proj, FAIL_SAMPLE_FILE)

    def _is_subpath(self, candidate, parent):
        return is_subpath(candidate, parent)

    def _open_local_path(self, path):
        try:
            open_local_path(path)
            return True
        except Exception as e:
            QMessageBox.warning(self, "错误", f"打开失败: {e}")
            return False

    def _update_artifact_buttons(self):
        if hasattr(self, 'btn_fail_samples'):
            fail_path = self._fail_sample_path()
            self.btn_fail_samples.setEnabled(bool(fail_path and os.path.exists(fail_path)))

    def _progress_state_path(self, proj_dir=None):
        base_dir = proj_dir or self.proj
        if not base_dir:
            return ""
        return os.path.join(base_dir, SCAN_PROGRESS_FILE)

    def _read_progress_state(self, proj_dir=None):
        try:
            return read_progress_state(proj_dir or self.proj, SCAN_PROGRESS_FILE)
        except Exception as e:
            self.log("ERROR", f"读取扫描进度失败: {e}")
            return {}

    def _load_scanned_index(self, proj_dir=None, quiet=False):
        proj_dir = proj_dir or self.proj
        self.scanned_set = set()
        self.scanned_count = 0
        self._pending_scanned_keys.clear()
        if not proj_dir:
            return

        scanned_path = os.path.join(proj_dir, "scanned.log")
        if not os.path.exists(scanned_path):
            return

        try:
            loaded = set()
            with open(scanned_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    task_key = normalize_task_record(line)
                    if task_key:
                        loaded.add(task_key)
            self.scanned_set = loaded
            self.scanned_count = len(loaded)
        except Exception as e:
            self.scanned_set = set()
            self.scanned_count = 0
            self._pending_scanned_keys.clear()
            if not quiet:
                self.log("ERROR", f"读取 scanned.log 失败: {e}")

    def _write_progress_state(self, current=None, total=None, active=None, stats=None):
        if not self.proj:
            return

        scanned_current = self.scanned_count
        try:
            write_progress_state(
                self.proj,
                SCAN_PROGRESS_FILE,
                scanned_current=scanned_current,
                current=current,
                total=total,
                bar_total=self.pg_bar.maximum() if hasattr(self, 'pg_bar') else 0,
                active=active,
                stats=stats,
            )
        except Exception as e:
            self.log("ERROR", f"保存扫描进度失败: {e}")

    def sv_sett(self):
        if not self.proj:
            return
        try:
            save_settings(self.proj, {
                    'target': self.t_ed.text(),
                    'k': self.c_k.isChecked(),
                    '80': self.c_8.isChecked(),
                    '443': self.c_4.isChecked(),
                    'n': self.c_n.isChecked(),
                    'abs': self.c_abs.isChecked(),
                    'waf': self.c_waf.isChecked(),
                    'sni': self.c_sni.isChecked(),
                    'threads': self.spin_threads.value(),
                })
        except Exception as e:
            self.log("ERROR", f"保存设置失败: {e}")

    def persist_project_state(self):
        if not self.proj:
            return
        try:
            self.sv_f("ips.txt", self.i_pl)
            self.sv_f("domains.txt", self.d_pl)
            self.sv_sett()
        except Exception:
            pass

        self.flush_log_buffer()
        self.flush_csv_buffer()
        self._write_progress_state(
            current=self.scanned_count,
            total=max(self.pg_bar.maximum(), self.scanned_count, 1),
            active=bool(hasattr(self, 'cth') and self.cth.isRunning()),
        )

    def new_p(self):
        root = QFileDialog.getExistingDirectory(self, "选择工程根目录", self._default_project_root())
        if not root:
            return

        name, ok = QInputDialog.getText(self, "新建工程", "输入工程名")
        if not ok:
            return

        name = name.strip().strip("\\/")
        if not name:
            return

        proj_dir = os.path.abspath(os.path.join(root, name))
        try:
            os.makedirs(proj_dir, exist_ok=True)
        except Exception as e:
            return QMessageBox.warning(self, "错误", f"创建工程失败: {e}")

        self.load_p(proj_dir)

    def open_p(self):
        proj_dir = QFileDialog.getExistingDirectory(self, "选择工程", self._default_project_root())
        if proj_dir:
            self.load_p(proj_dir)

    def close_project(self):
        if hasattr(self, 'cth') and self.cth.isRunning():
            return QMessageBox.warning(self, "提示", "请先停止当前扫描任务，再关闭工程。")

        self.persist_project_state()
        self.proj = None
        self.ips.clear()
        self.doms.clear()
        self.scanned_set.clear()
        self.scanned_count = 0
        self.csv_buffer.clear()
        self.scanned_buffer.clear()
        self._pending_scanned_keys.clear()

        self.i_pl.blockSignals(True)
        self.d_pl.blockSignals(True)
        self.t_ed.blockSignals(True)
        self.i_pl.clear()
        self.d_pl.clear()
        self.t_ed.clear()
        self.i_pl.blockSignals(False)
        self.d_pl.blockSignals(False)
        self.t_ed.blockSignals(False)

        self.tb.setRowCount(0)
        self.pg_bar.setMaximum(1)
        self.pg_bar.setValue(0)
        self.lbl_p.setText("当前工程: [未载入]")
        self.lbl_p.setToolTip("")
        self.last_scan_stats = {}
        self.ui_conf_counts = {"极危": 0, "高危": 0, "中危": 0, "低危": 0}
        self._risk_cap_notified.clear()
        self._table_sort_active = False
        self._table_sort_column = -1
        self._update_artifact_buttons()
        self.log("INFO", "当前工程已关闭。")

    def load_p(self, d):
        if hasattr(self, 'cth') and self.cth.isRunning():
            return QMessageBox.warning(self, "提示", "请先停止当前扫描任务，再切换工程。")

        proj_dir = os.path.abspath(d)
        if not os.path.isdir(proj_dir):
            try:
                os.makedirs(proj_dir, exist_ok=True)
            except Exception as e:
                return QMessageBox.warning(self, "错误", f"无法打开工程: {e}")

        if self.proj and os.path.abspath(self.proj) != proj_dir:
            self.persist_project_state()

        self.proj = proj_dir
        self.lbl_p.setText(f"工程: {os.path.basename(proj_dir)}")
        self.lbl_p.setToolTip(proj_dir)

        self.ips.clear()
        self.doms.clear()
        self.scanned_set.clear()
        self.scanned_count = 0
        self.csv_buffer.clear()
        self.scanned_buffer.clear()
        self._pending_scanned_keys.clear()
        self.ui_conf_counts = {"极危": 0, "高危": 0, "中危": 0, "低危": 0}
        self._risk_cap_notified.clear()

        self.i_pl.blockSignals(True)
        self.d_pl.blockSignals(True)
        self.t_ed.blockSignals(True)
        self.i_pl.clear()
        self.d_pl.clear()
        self.t_ed.clear()

        for filename, widget, bucket in [("ips.txt", self.i_pl, self.ips), ("domains.txt", self.d_pl, self.doms)]:
            path = os.path.join(proj_dir, filename)
            if not os.path.exists(path):
                continue
            try:
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                widget.setPlainText(content)
                bucket.update(line.strip() for line in content.splitlines() if line.strip())
            except Exception as e:
                self.log("ERROR", f"读取 {filename} 失败: {e}")

        settings_path = os.path.join(proj_dir, "settings.json")
        if os.path.exists(settings_path):
            try:
                with open(settings_path, 'r', encoding='utf-8') as f:
                    settings = json.load(f)
                self.t_ed.setText(settings.get('target', ''))
                self.c_k.setChecked(settings.get('k', True))
                self.c_8.setChecked(settings.get('80', True))
                self.c_4.setChecked(settings.get('443', True))
                self.c_n.setChecked(settings.get('n', True))
                self.c_abs.setChecked(settings.get('abs', False))
                self.c_waf.setChecked(settings.get('waf', False))
                self.c_sni.setChecked(settings.get('sni', False))
                self.spin_threads.setValue(int(settings.get('threads', self.spin_threads.value())))
            except Exception as e:
                self.log("ERROR", f"读取 settings.json 失败: {e}")

        self.i_pl.blockSignals(False)
        self.d_pl.blockSignals(False)
        self.t_ed.blockSignals(False)

        self.tb.setUpdatesEnabled(False)
        self.tb.setRowCount(0)
        results_path = os.path.join(proj_dir, "results.csv")
        if os.path.exists(results_path):
            try:
                normalized_rows = []
                normalized_count = 0
                with open(results_path, 'r', encoding='utf-8-sig', errors='ignore') as f:
                    reader = csv.DictReader(f)
                    for row_data in reader:
                        if row_data.get("url"):
                            normalized_row, changed = normalize_result_row(row_data)
                            normalized_rows.append(normalized_row)
                            if changed:
                                normalized_count += 1
                            self.add_res_ui(normalized_row, save=False)
                if normalized_count:
                    overwrite_csv_rows(results_path, RESULT_FIELDS, normalized_rows)
                    self.log("INFO", f"已自动标准化 {normalized_count} 条历史置信度记录。")
            except Exception as e:
                self.log("ERROR", f"读取 results.csv 失败: {e}")
        self.tb.setUpdatesEnabled(True)
        self.apply_table_sort()

        self._load_scanned_index(proj_dir)

        progress_state = self._read_progress_state(proj_dir)
        self.last_scan_stats = progress_state.get("stats", {}) if isinstance(progress_state.get("stats"), dict) else {}
        current_progress = self.scanned_count
        total_progress = max(int(progress_state.get("total", 0) or 0), current_progress, 1)
        self.pg_bar.setMaximum(total_progress)
        self.pg_bar.setValue(current_progress)

        if current_progress:
            self.log("INFO", f"已恢复扫描进度: {current_progress} / {total_progress}")
        self._update_artifact_buttons()
        self.log("SUCCESS", f"工程载入成功，IP:{len(self.ips)}，Host:{len(self.doms)}，已扫描:{self.scanned_count}")

    @Slot(str)
    def mark_task_done(self, task_id):
        task_key = normalize_task_record(task_id)
        if not task_key:
            return

        if task_key in self.scanned_set or task_key in self._pending_scanned_keys:
            return

        self._pending_scanned_keys.add(task_key)
        self.scanned_buffer.append(task_key)
        self.scanned_count += 1

        current = self.scanned_count
        total = max(self.pg_bar.maximum(), current, 1)
        if self.pg_bar.maximum() != total:
            self.pg_bar.setMaximum(total)
        self.pg_bar.setValue(current)

        if current % 100 == 0 or len(self.scanned_buffer) >= 2000:
            self._write_progress_state(
                current=current,
                total=total,
                active=bool(hasattr(self, 'cth') and self.cth.isRunning()),
            )
        if len(self.scanned_buffer) >= 2000:
            self.flush_csv_buffer()

    def run_c(self):
        if not self.proj:
            return QMessageBox.warning(self, "提示", "请先打开或新建一个工程。")
        if hasattr(self, 'cth') and self.cth.isRunning():
            return self.log("ERROR", "上一轮对撞任务仍在进行中。")

        ip_list = [x.strip() for x in self.i_pl.toPlainText().split() if x.strip()]
        domain_list = list(dict.fromkeys(x.strip() for x in self.d_pl.toPlainText().split() if x.strip()))
        if not ip_list or not domain_list:
            return self.log("ERROR", "IP 池或域名池为空。")

        self._load_scanned_index(self.proj, quiet=True)

        dict_config = {}
        dict_path = os.path.join(self.proj, "dict_config.json")
        if os.path.exists(dict_path):
            try:
                with open(dict_path, 'r', encoding='utf-8') as f:
                    dict_config = json.load(f)
            except Exception as e:
                self.log("ERROR", f"读取字典配置失败: {e}")

        self.persist_project_state()
        self.btn_c.setEnabled(False)
        self.btn_c.setText("识别中...")
        self.btn_stop.setEnabled(True)
        self.btn_stop.setText("停止")

        progress_state = self._read_progress_state()
        current_progress = self.scanned_count
        total_hint = max(int(progress_state.get("total", 0) or 0), current_progress, 1)
        self.pg_bar.setMaximum(total_hint)
        self.pg_bar.setValue(current_progress)

        if current_progress:
            self.log("INFO", f"从断点继续扫描，已扫描 {current_progress} 条任务。")

        policies = {
            'k': self.c_k.isChecked(),
            '80': self.c_8.isChecked(),
            '443': self.c_4.isChecked(),
            'n': self.c_n.isChecked(),
            'abs': self.c_abs.isChecked(),
            'waf': self.c_waf.isChecked(),
            'sni': self.c_sni.isChecked(),
        }

        self._write_progress_state(current=current_progress, total=total_hint, active=True)

        self.cth = CollTask(
            ip_list,
            domain_list,
            policies,
            self.spin_threads.value(),
            self.proj,
            set(self.scanned_set),
            dict_config,
        )
        self.cth.log_sig.connect(self.log)
        self.cth.res_sig.connect(self.add_res_ui)
        self.cth.summary_sig.connect(self.show_summary)
        self.cth.progress_sig.connect(self.update_progress)
        self.cth.task_done_sig.connect(self.mark_task_done)
        self.cth.start()

    @Slot(dict, bool)
    def show_summary(self, stats, was_stopped):
        stats = stats or {}
        self.last_scan_stats = dict(stats)
        current_progress = self.scanned_count
        total_progress = max(int(stats.get('total', 0) or 0), self.pg_bar.maximum(), current_progress, 1)

        self._write_progress_state(
            current=current_progress,
            total=total_progress,
            active=False,
            stats=stats,
        )
        self.persist_project_state()

        self.btn_c.setEnabled(True)
        self.btn_c.setText("启动对撞")
        self.btn_stop.setEnabled(False)
        self.btn_stop.setText("停止")
        self.apply_table_sort()

        title = "扫描已中止" if was_stopped else "扫描完成"
        msg = (
            f"总计构建: {stats.get('total', 0)} 个变体\n"
            f"命中并写入战果: {stats.get('success', 0)} 条\n"
            f"失败/异常: {stats.get('fail', 0)} 条\n"
            f"当前断点进度: {current_progress} / {total_progress}\n\n"
            f"results.csv、scanned.log、runtime.log、{SCAN_PROGRESS_FILE}、{FAIL_SAMPLE_FILE} 已保存，下次打开工程可继续。"
        )
        if int(stats.get('success', 0) or 0) == 0:
            msg += "\n\n本轮没有新增命中，所以 results.csv 不更新是正常现象。"
        top_fail_reasons = stats.get("top_fail_reasons") or {}
        if top_fail_reasons:
            fail_lines = [f"{reason}: {count}" for reason, count in top_fail_reasons.items()]
            msg += "\n\n高频失败原因:\n" + "\n".join(fail_lines[:5])
        self._update_artifact_buttons()
        self.log("INFO", f"[{title}] {msg.replace(chr(10), ' | ')}")
        QMessageBox.information(self, title, msg)

    @Slot(int, int)
    def update_progress(self, current, total):
        total = max(int(total), int(current), 1)
        current = max(0, min(int(current), total))
        if self.pg_bar.maximum() != total:
            self.pg_bar.setMaximum(total)
        self.pg_bar.setValue(current)
        self._write_progress_state(
            current=current,
            total=total,
            active=bool(hasattr(self, 'cth') and self.cth.isRunning()),
        )

    def export_project(self):
        if not self.proj:
            return QMessageBox.warning(self, "提示", "当前没有打开的工程，无法导出。")

        self.persist_project_state()
        root = QFileDialog.getExistingDirectory(self, "选择导出目录", self._default_project_root())
        if not root:
            return

        default_name = os.path.basename(self.proj.rstrip("\\/"))
        name, ok = QInputDialog.getText(self, "导出工程", "输入导出后的工程名", text=default_name)
        if not ok:
            return

        name = name.strip().strip("\\/")
        if not name:
            return

        new_dir = os.path.abspath(os.path.join(root, name))
        if os.path.abspath(new_dir) == os.path.abspath(self.proj):
            return QMessageBox.warning(self, "提示", "导出目录不能与当前工程目录相同。")
        if self._is_subpath(new_dir, self.proj):
            return QMessageBox.warning(self, "提示", "不能导出到当前工程目录内部，否则会造成工程目录递归嵌套。")
        if os.path.exists(new_dir):
            return QMessageBox.warning(self, "错误", "目标目录已存在，请更换一个名字。")

        import shutil
        try:
            shutil.copytree(self.proj, new_dir, ignore=shutil.ignore_patterns("__pycache__"))
        except Exception as e:
            return QMessageBox.warning(self, "错误", f"导出失败: {e}")

        self.log("SUCCESS", f"工程已导出到: {new_dir}")
        QMessageBox.information(self, "成功", f"工程已完整导出到:\n{new_dir}")

    def show_fail_samples(self):
        if not self.proj:
            return QMessageBox.warning(self, "提示", "当前没有打开的工程。")

        fail_path = self._fail_sample_path()
        if not fail_path or not os.path.exists(fail_path):
            extra = ""
            top_fail_reasons = self.last_scan_stats.get("top_fail_reasons") if isinstance(self.last_scan_stats, dict) else {}
            if top_fail_reasons:
                extra = "\n\n最近一次失败原因统计:\n" + "\n".join(
                    f"{reason}: {count}" for reason, count in top_fail_reasons.items()
                )
            return QMessageBox.information(self, "失败样本", f"当前工程还没有可查看的 {FAIL_SAMPLE_FILE}。{extra}")

        try:
            with open(fail_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read().strip()
        except Exception as e:
            return QMessageBox.warning(self, "错误", f"读取失败样本失败: {e}")

        dlg = QDialog(self)
        dlg.setWindowTitle("失败样本预览")
        dlg.resize(980, 720)
        dlg.setStyleSheet("""
            QDialog { background-color: #0d1117; color: #c9d1d9; font-family: 'Consolas', 'Microsoft YaHei'; }
            QTextEdit { background-color: #161b22; border: 1px solid #30363d; color: #c9d1d9; }
            QPushButton { background-color: #238636; color: white; font-weight: bold; padding: 7px; border-radius: 3px; }
            QPushButton:hover { background-color: #2ea043; }
        """)

        layout = QVBoxLayout(dlg)
        summary = QLabel(f"文件: {os.path.basename(fail_path)}")
        summary.setTextInteractionFlags(Qt.TextSelectableByMouse)
        summary.setToolTip(fail_path)
        layout.addWidget(summary)

        preview = QTextEdit()
        preview.setReadOnly(True)
        preview.setLineWrapMode(QTextEdit.NoWrap)
        preview.setPlainText(content or f"{FAIL_SAMPLE_FILE} 为空。")
        layout.addWidget(preview)

        btn_row = QHBoxLayout()
        btn_open_file = QPushButton("外部打开")
        btn_open_file.clicked.connect(lambda: self._open_local_path(fail_path))
        btn_row.addWidget(btn_open_file)

        btn_open_dir = QPushButton("打开目录")
        btn_open_dir.clicked.connect(lambda: self._open_local_path(os.path.dirname(fail_path)))
        btn_row.addWidget(btn_open_dir)

        btn_row.addStretch(1)

        btn_close = QPushButton("关闭")
        btn_close.clicked.connect(dlg.accept)
        btn_row.addWidget(btn_close)
        layout.addLayout(btn_row)
        dlg.exec()

    @Slot()
    def flush_csv_buffer(self):
        if not getattr(self, 'proj', None):
            return

        if self.csv_buffer:
            rows = list(self.csv_buffer)
            results_path = os.path.join(self.proj, "results.csv")
            try:
                append_csv_rows(results_path, RESULT_FIELDS, rows)
                del self.csv_buffer[:len(rows)]
            except PermissionError:
                self.log("ERROR", f"results.csv 正被占用，无法写入。请先关闭 WPS/Excel: {results_path}")
            except Exception as e:
                self.log("ERROR", f"CSV 写入失败: {e}")

        if self.scanned_buffer:
            task_ids = list(dict.fromkeys(self.scanned_buffer))
            scanned_path = os.path.join(self.proj, "scanned.log")
            try:
                append_lines(scanned_path, task_ids)
                self.scanned_buffer.clear()
                self._pending_scanned_keys.difference_update(task_ids)
            except Exception as e:
                self.log("ERROR", f"断点日志写入失败: {e}")

        self._write_progress_state(
            current=self.scanned_count,
            total=max(self.pg_bar.maximum(), self.scanned_count, 1),
            active=bool(hasattr(self, 'cth') and self.cth.isRunning()),
        )

    def add_res_ui(self, d, save=True):
        row_data, _ = normalize_result_row(d)
        if save and self.proj:
            self.csv_buffer.append(row_data)
            if len(self.csv_buffer) >= 200:
                self.flush_csv_buffer()

        conf = str(row_data.get("conf", ""))
        is_low_risk = "低危" in conf
        if is_low_risk and self.ui_conf_counts["低危"] >= LOW_RISK_UI_LIMIT:
            if "低危" not in self._risk_cap_notified:
                self._risk_cap_notified.add("低危")
                self.log("INFO", f"低危结果已达到 UI 展示上限 {LOW_RISK_UI_LIMIT}，后续仅写入 CSV。")
            return
        if "中危" in conf and self.ui_conf_counts["中危"] >= MEDIUM_RISK_UI_LIMIT:
            if "中危" not in self._risk_cap_notified:
                self._risk_cap_notified.add("中危")
                self.log("INFO", f"中危结果已达到 UI 展示上限 {MEDIUM_RISK_UI_LIMIT}，后续仅写入 CSV。")
            return

        should_resort = bool(getattr(self, "_table_sort_active", False))
        row_index = self.tb.rowCount()
        if row_index % 25 == 0:
            QApplication.processEvents()

        if should_resort:
            self.tb.setUpdatesEnabled(False)
        self.tb.insertRow(row_index)

        for col_index, field in enumerate(RESULT_FIELDS):
            value = row_data.get(field, "")
            if field in ["code", "len"]:
                item = SortableTableWidgetItem(str(value))
                try:
                    item.setData(Qt.UserRole, int(value))
                except Exception:
                    item.setData(Qt.UserRole, 0)
            elif field == "conf":
                item = SortableTableWidgetItem(str(value))
                item.setData(
                    Qt.UserRole,
                    CONFIDENCE_SORT_WEIGHT.get(str(value), 99),
                )
            else:
                item = SortableTableWidgetItem(str(value))

            if "极危" in conf:
                item.setBackground(QColor(248, 81, 73, 45))
                item.setForeground(QColor(255, 123, 114))
            elif "高危" in conf:
                item.setBackground(QColor(35, 134, 54, 40))
                item.setForeground(QColor(88, 166, 255))
            elif "中危" in conf:
                item.setForeground(QColor(210, 153, 34))
            else:
                item.setForeground(QColor(139, 148, 158))

            self.tb.setItem(row_index, col_index, item)

        if conf in self.ui_conf_counts:
            self.ui_conf_counts[conf] += 1

        if should_resort:
            self.apply_table_sort()
            self.tb.setUpdatesEnabled(True)

    def closeEvent(self, event):
        if hasattr(self, 'cth') and self.cth.isRunning():
            self.cth.stop()
            self.cth.wait(2000)
        if hasattr(self, 'th') and self.th.isRunning():
            self.th.wait(1000)
        self.persist_project_state()
        event.accept()
if __name__ == "__main__":
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    install_global_crash_handlers()
    app = QApplication(sys.argv)
    win = AssetCommander()
    win.show()
    sys.exit(app.exec())
