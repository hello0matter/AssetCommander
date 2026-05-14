import sys, os, re, asyncio, subprocess, json, socket, ipaddress, csv
import hashlib
import time
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
    collect_unique_hosts,
    collect_unique_ips,
    derive_site_label,
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
from asset_tasks import ToolTask
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
LOW_RISK_UI_RENDER_LIMIT = 80
MEDIUM_RISK_UI_LIMIT = 300
TOTAL_UI_SOFT_LIMIT = 1200

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
        self.scan_signature = ""
        self.scan_started_at = 0.0
        self.scan_resume_base = 0
        self.ui_conf_counts = {"极危": 0, "高危": 0, "中危": 0, "低危": 0}
        self._risk_cap_notified = set()
        self.csv_timer = QTimer(self)
        self.csv_timer.timeout.connect(self.flush_csv_buffer)
        self.csv_timer.start(2000)
        self._update_artifact_buttons()

    def _set_pool_text(self, widget, items):
        unique_items = list(dict.fromkeys(item for item in items if item))
        widget.setPlainText("\n".join(unique_items) + ("\n" if unique_items else ""))

    def _current_ip_pool(self):
        return collect_unique_ips(self.i_pl.toPlainText().splitlines())

    def _current_domain_pool(self):
        return collect_unique_hosts(self.d_pl.toPlainText().splitlines())

    def _sanitize_ip_pool(self):
        self._set_pool_text(self.i_pl, self._current_ip_pool())

    def _sanitize_domain_pool(self):
        domains = []
        for host in self._current_domain_pool():
            if not re.fullmatch(RE_IP, host):
                domains.append(host)
        self._set_pool_text(self.d_pl, domains)

    def _set_result_header_tooltips(self):
        tips = {
            0: "实际发包目标，通常是 IP 或 IP:端口。",
            1: "更适合人工识别的站点身份，通常带协议。",
            2: "本次碰撞注入的 Host 头。",
            3: "Host 碰撞请求返回的状态码。",
            4: "Host 碰撞请求响应长度。",
            5: "Host 碰撞请求页面标题。",
            6: "引擎给出的风险置信度。",
            7: "差异判断和命中原因说明。",
        }
        for column, tip in tips.items():
            header_item = self.tb.horizontalHeaderItem(column)
            if header_item is not None:
                header_item.setToolTip(tip)

    def _format_eta(self, seconds):
        seconds = max(int(seconds), 0)
        mins, secs = divmod(seconds, 60)
        hours, mins = divmod(mins, 60)
        if hours > 0:
            return f"{hours}h {mins}m {secs}s"
        if mins > 0:
            return f"{mins}m {secs}s"
        return f"{secs}s"

    def _refresh_main_progress_display(self, current, total, stopped=False):
        current = max(0, int(current))
        total = max(1, int(total))
        elapsed = max(time.time() - self.scan_started_at, 0.0) if self.scan_started_at else 0.0

        eta_text = "ETA: 计算中"
        if current > self.scan_resume_base and elapsed > 0:
            delta_done = current - self.scan_resume_base
            remaining = max(total - current, 0)
            eta_seconds = int((elapsed / max(delta_done, 1)) * remaining)
            eta_text = f"ETA: {self._format_eta(eta_seconds)}"
        elif current >= total:
            eta_text = "ETA: 0s"

        percent = int((current / total) * 100) if total else 0
        status = "已停止" if stopped else ("已完成" if current >= total else "对撞进度")
        self.pg_bar.setFormat(f"{status} {current} / {total} [{percent}%] {eta_text}")
        if hasattr(self, "lbl_scan_eta"):
            self.lbl_scan_eta.setText(
                f"进度: {current} / {total} | 已耗时: {self._format_eta(elapsed)} | {eta_text}"
            )

    def _apply_result_item_style(self, item, field, conf):
        base_bg = None
        base_fg = QColor(201, 209, 217)
        if field == "url":
            base_bg = QColor(31, 111, 235, 28)
            base_fg = QColor(88, 166, 255)
        elif field == "site":
            base_bg = QColor(35, 134, 54, 28)
            base_fg = QColor(63, 185, 80)
        elif field == "host":
            base_bg = QColor(210, 153, 34, 28)
            base_fg = QColor(227, 179, 65)
        elif field in {"code", "len"}:
            base_fg = QColor(139, 148, 158)

        if base_bg is not None:
            item.setBackground(base_bg)
        item.setForeground(base_fg)

        if "极危" in conf:
            if field in {"conf", "remark"}:
                item.setBackground(QColor(248, 81, 73, 45))
            item.setForeground(QColor(255, 123, 114))
        elif "高危" in conf:
            if field in {"conf", "remark"}:
                item.setBackground(QColor(35, 134, 54, 40))
            item.setForeground(QColor(88, 166, 255))
        elif "中危" in conf:
            if field in {"conf", "remark"}:
                item.setBackground(QColor(210, 153, 34, 28))
            item.setForeground(QColor(210, 153, 34))
        elif field not in {"url", "site", "host", "code", "len"}:
            item.setForeground(QColor(139, 148, 158))

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
            "kubernetes.default", "kubernetes.default.svc",
            "kubernetes.default.svc.cluster.local",
            "host.docker.internal",
            "gateway.docker.internal",
            "localhost",
        ]
        current_doms = self._current_domain_pool()
        self._set_pool_text(self.d_pl, current_doms + internal_hosts)
        self.log("SUCCESS", f"成功注入 {len(internal_hosts)} 个高价值内网/云原生 Host，已准备好继续测试。")

    def inject_internal_ips(self):
        internal_ips = [
            "127.0.0.1",
            "169.254.169.254",
            "100.100.100.200",
            "172.17.0.1",
            "192.168.1.1",
            "10.0.0.1",
        ]
        current_ips = self._current_ip_pool()
        self._set_pool_text(self.i_pl, current_ips + internal_ips)
        self.log("SUCCESS", f"成功注入 {len(internal_ips)} 个高价值内网 IP（网关 / 元数据 / 回环）。")

    def deduplicate_pools(self):
        self._sanitize_ip_pool()
        self._sanitize_domain_pool()
        self.log("SUCCESS", "资产清理完毕，IP 池与域名池已完成一键去重。")

    def open_custom_bind(self):
        if not self.proj: return QMessageBox.warning(self, "提示", "请先选择或新建一个工程。")
        dlg = CustomBindDialog(self, self.proj)
        if dlg.exec() == QDialog.Accepted:
            all_ips = self._current_ip_pool() + dlg.ips
            all_doms = self._current_domain_pool() + dlg.domains
            self._set_pool_text(self.i_pl, all_ips)
            self._set_pool_text(self.d_pl, all_doms)
            self.log("SUCCESS", f"自定义绑定成功，已注入并去重 {len(dlg.ips)} 个 IP 和 {len(dlg.domains)} 个域名。")
    def open_ip_fission(self):
        self.fission_dialog = IPFissionDialog(self, ip_pool_widget=self.i_pl, proj_dir=self.proj)
        self.fission_dialog.show()

    def open_ip_hunter(self):
        self.hunter_dialog = RealIPHunterDialog(self, ip_pool_widget=self.i_pl, proj_dir=self.proj)
        self.hunter_dialog.show()

    def open_ip_reverse(self):
        ips = self._current_ip_pool()
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
        self.tb = QTableWidget(0, 8)
        self.tb.setHorizontalHeaderLabels(["Target(IP/URL)", "站点身份", "Host 头", "Code", "Len", "Title", "置信度", "智能诊断"])
        self.tb.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.tb.horizontalHeader().setStretchLastSection(True)
        self.tb.setColumnWidth(0, 220)
        self.tb.setColumnWidth(1, 240)
        self.tb.setColumnWidth(2, 220)
        self.tb.setColumnWidth(7, 320)
        self._table_sort_active = False
        self._table_sort_column = -1
        self._table_sort_order = Qt.AscendingOrder
        header = self.tb.horizontalHeader()
        header.setSortIndicatorShown(True)
        header.sectionClicked.connect(self.handle_table_sort_click)
        self.tb.setSortingEnabled(False)
        self._set_result_header_tooltips()
        
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

        self.lbl_scan_eta = QLabel("进度: 0 / 1 | 已耗时: 0s | ETA: 计算中")
        self.lbl_scan_eta.setStyleSheet("color: #8b949e;")
        ml.addWidget(self.lbl_scan_eta)

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

        for ip in collect_unique_ips(re.findall(RE_AST, t)):
            if ip not in self.ips:
                self.ips.add(ip)
                self.i_pl.append(ip)
                ip_c = True

        ex = [".html", ".js", ".css", ".py", ".exe", "fscan", "version"]
        candidates = collect_unique_hosts(re.findall(RE_DOM, t))
        for host in candidates:
            if "." in host and host not in self.doms and not any(x in host.lower() for x in ex):
                self.doms.add(host)
                self.d_pl.append(host)
                dom_c = True
                
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

        raw_target = self.t_ed.text().strip()
        ip_target = collect_unique_ips([raw_target])
        if ip_target:
            target = ip_target[0]
        else:
            host_target = collect_unique_hosts([raw_target])
            target = host_target[0] if host_target else ""
        if not target:
            return self.log("ERROR", "OFA 目标为空。")

        cmd_tpl = self.config.get("oneforall_cmd", "").strip()
        if not cmd_tpl:
            return self.log("ERROR", "未配置 OneForAll 命令。")

        cmd = cmd_tpl.replace("{target}", target)
        self.th = ToolTask("OFA", cmd); self.th.log_sig.connect(self.log); self.th.ast_sig.connect(self.cln); self.th.start()

    def stop_c(self):
        if hasattr(self, 'cth') and self.cth.isRunning():
            self.log("INFO", "正在发送强制截断指令...")
            self.btn_stop.setEnabled(False); self.btn_stop.setText("截断中...")
            self.pg_bar.setFormat(f"正在停止 {self.pg_bar.value()} / {self.pg_bar.maximum()} [请等待]")
            self.cth.stop() 

    def force_save(self):
        if not self.proj: return
        try:
            rows = []
            for row in range(self.tb.rowCount()):
                row_data = {
                    "url": self.tb.item(row, 0).text() if self.tb.item(row, 0) else "",
                    "site": self.tb.item(row, 1).text() if self.tb.item(row, 1) else "",
                    "host": self.tb.item(row, 2).text() if self.tb.item(row, 2) else "",
                    "code": self.tb.item(row, 3).text() if self.tb.item(row, 3) else "",
                    "len": self.tb.item(row, 4).text() if self.tb.item(row, 4) else "",
                    "title": self.tb.item(row, 5).text() if self.tb.item(row, 5) else "",
                    "conf": self.tb.item(row, 6).text() if self.tb.item(row, 6) else "",
                    "remark": self.tb.item(row, 7).text() if self.tb.item(row, 7) else "",
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

    def _load_dict_config(self, proj_dir=None, quiet=True):
        proj_dir = proj_dir or self.proj
        if not proj_dir:
            return {}

        path = os.path.join(proj_dir, "dict_config.json")
        if not os.path.exists(path):
            return {}

        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f) or {}
        except Exception as e:
            if not quiet:
                self.log("ERROR", f"读取字典配置失败: {e}")
            return {}

    def _build_scan_signature(self, ip_list, domain_list, policies, dict_config):
        dict_config = dict(dict_config or {})
        dict_path = os.path.abspath(dict_config.get("path", "")) if dict_config.get("path") else ""
        dict_meta = {"path": dict_path}
        if dict_path and os.path.exists(dict_path):
            try:
                dict_meta["size"] = os.path.getsize(dict_path)
                dict_meta["mtime"] = int(os.path.getmtime(dict_path))
            except OSError:
                pass

        payload = {
            "ips": sorted(dict.fromkeys(str(item).strip() for item in ip_list if str(item).strip())),
            "domains": sorted(dict.fromkeys(str(item).strip() for item in domain_list if str(item).strip())),
            "policies": {key: bool(value) for key, value in sorted((policies or {}).items())},
            "dict": {
                "enabled": bool(dict_config.get("enabled")),
                "prefixes": [item.strip() for item in str(dict_config.get("prefixes", "")).splitlines() if item.strip()],
                "suffixes": [item.strip() for item in str(dict_config.get("suffixes", "")).splitlines() if item.strip()],
                "meta": dict_meta,
            },
        }
        raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return hashlib.blake2b(raw.encode("utf-8"), digest_size=16).hexdigest()

    def _estimate_scan_total(self, ip_list, domain_list, policies, dict_config):
        url_variants_per_ip = 0
        if policies.get("k", True):
            url_variants_per_ip += 2
        if policies.get("80", True):
            url_variants_per_ip += 1
        if policies.get("443", True):
            url_variants_per_ip += 1
        if policies.get("n", True):
            url_variants_per_ip += 2
        if url_variants_per_ip == 0:
            url_variants_per_ip = 4

        dom_variants = len(domain_list)
        dict_path = str((dict_config or {}).get("path", "") or "").strip()
        if (
            dict_config
            and dict_config.get("enabled")
            and dict_path
            and os.path.exists(dict_path)
        ):
            try:
                with open(dict_path, "rb") as handle:
                    dict_lines = sum(1 for _ in handle)
            except OSError:
                dict_lines = 0

            prefix_count = max(
                1,
                len([item for item in str(dict_config.get("prefixes", "")).splitlines() if item.strip()]),
            )
            suffix_count = max(
                1,
                len([item for item in str(dict_config.get("suffixes", "")).splitlines() if item.strip()]),
            )
            dom_variants += dict_lines * prefix_count * suffix_count

        return len(ip_list) * url_variants_per_ip * dom_variants

    def _scanned_log_path(self, proj_dir=None, signature=None):
        proj_dir = proj_dir or self.proj
        if not proj_dir:
            return ""
        if signature:
            return os.path.join(proj_dir, f"scanned.{signature[:8]}.log")
        return os.path.join(proj_dir, "scanned.log")

    def _migrate_legacy_scanned_log(self, proj_dir=None, signature=None):
        proj_dir = proj_dir or self.proj
        signature = signature or self.scan_signature
        if not proj_dir or not signature:
            return

        legacy_path = self._scanned_log_path(proj_dir=proj_dir, signature=None)
        signature_path = self._scanned_log_path(proj_dir=proj_dir, signature=signature)
        if not os.path.exists(legacy_path) or os.path.exists(signature_path):
            return

        try:
            os.replace(legacy_path, signature_path)
        except OSError:
            return

    def _set_scan_config_enabled(self, enabled):
        widgets = [
            getattr(self, "t_ed", None),
            getattr(self, "i_pl", None),
            getattr(self, "d_pl", None),
            getattr(self, "c_k", None),
            getattr(self, "c_8", None),
            getattr(self, "c_4", None),
            getattr(self, "c_n", None),
            getattr(self, "c_abs", None),
            getattr(self, "c_waf", None),
            getattr(self, "c_sni", None),
            getattr(self, "spin_threads", None),
            getattr(self, "btn_adv_dict", None),
        ]
        for widget in widgets:
            if widget is not None:
                widget.setEnabled(bool(enabled))

    def _load_scanned_index(self, proj_dir=None, quiet=False, signature=None):
        proj_dir = proj_dir or self.proj
        self.scanned_set = set()
        self.scanned_count = 0
        self._pending_scanned_keys.clear()
        if not proj_dir:
            return

        scanned_path = self._scanned_log_path(proj_dir=proj_dir, signature=signature)
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
                scan_signature=self.scan_signature,
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
        self.scan_signature = ""
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
        self.scan_started_at = 0.0
        self.scan_resume_base = 0
        self._refresh_main_progress_display(0, 1)
        self.lbl_p.setText("当前工程: [未载入]")
        self.lbl_p.setToolTip("")
        self.last_scan_stats = {}
        self.ui_conf_counts = {"极危": 0, "高危": 0, "中危": 0, "低危": 0}
        self._risk_cap_notified.clear()
        self._table_sort_active = False
        self._table_sort_column = -1
        self._set_scan_config_enabled(True)
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
        self.scan_signature = ""
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
                if filename == "ips.txt":
                    items = collect_unique_ips(content.splitlines())
                else:
                    items = collect_unique_hosts(content.splitlines())
                self._set_pool_text(widget, items)
                bucket.update(items)
            except Exception as e:
                self.log("ERROR", f"读取 {filename} 失败: {e}")

        settings = {}
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

        dict_config = self._load_dict_config(proj_dir, quiet=True)
        policies = {
            'k': settings.get('k', True),
            '80': settings.get('80', True),
            '443': settings.get('443', True),
            'n': settings.get('n', True),
            'abs': settings.get('abs', False),
            'waf': settings.get('waf', False),
            'sni': settings.get('sni', False),
        }
        self.scan_signature = self._build_scan_signature(
            list(self.ips),
            list(self.doms),
            policies,
            dict_config,
        )
        estimated_total = self._estimate_scan_total(
            list(self.ips),
            list(self.doms),
            policies,
            dict_config,
        )
        progress_state = self._read_progress_state(proj_dir)
        self.last_scan_stats = progress_state.get("stats", {}) if isinstance(progress_state.get("stats"), dict) else {}
        progress_signature = str(progress_state.get("scan_signature", "") or "").strip()
        can_restore_legacy = (
            not progress_signature
            and int(progress_state.get("current", 0) or 0) <= max(int(estimated_total), 1)
        )
        if progress_signature == self.scan_signature or can_restore_legacy:
            self._migrate_legacy_scanned_log(proj_dir=proj_dir, signature=self.scan_signature)
            self._load_scanned_index(proj_dir, signature=self.scan_signature)
            current_progress = self.scanned_count
            total_progress = max(int(progress_state.get("total", 0) or 0), current_progress, 1)
        else:
            current_progress = 0
            total_progress = 1
            if progress_state.get("current"):
                self.log("INFO", "检测到当前工程配置已变化，旧断点进度不再复用，本轮将从 0 开始。")
        self.pg_bar.setMaximum(total_progress)
        self.pg_bar.setValue(current_progress)
        self.scan_started_at = 0.0
        self.scan_resume_base = current_progress
        self._refresh_main_progress_display(current_progress, total_progress)

        if current_progress:
            self.log("INFO", f"已恢复扫描进度: {current_progress} / {total_progress}")
        self._set_scan_config_enabled(True)
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
        self._refresh_main_progress_display(current, total)

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

        ip_list = self._current_ip_pool()
        domain_list = self._current_domain_pool()
        if not ip_list or not domain_list:
            return self.log("ERROR", "IP 池或域名池为空。")

        dict_config = self._load_dict_config(self.proj, quiet=False)
        policies = {
            'k': self.c_k.isChecked(),
            '80': self.c_8.isChecked(),
            '443': self.c_4.isChecked(),
            'n': self.c_n.isChecked(),
            'abs': self.c_abs.isChecked(),
            'waf': self.c_waf.isChecked(),
            'sni': self.c_sni.isChecked(),
        }
        self.scan_signature = self._build_scan_signature(
            ip_list,
            domain_list,
            policies,
            dict_config,
        )
        estimated_total = self._estimate_scan_total(
            ip_list,
            domain_list,
            policies,
            dict_config,
        )

        progress_state = self._read_progress_state()
        progress_signature = str(progress_state.get("scan_signature", "") or "").strip()
        can_restore_legacy = (
            not progress_signature
            and int(progress_state.get("current", 0) or 0) <= max(int(estimated_total), 1)
        )
        if progress_signature == self.scan_signature or can_restore_legacy:
            self._migrate_legacy_scanned_log(signature=self.scan_signature)
            self._load_scanned_index(self.proj, quiet=True, signature=self.scan_signature)
        else:
            if progress_state.get("current"):
                self.log("INFO", "检测到扫描配置变化，本轮不会复用旧断点进度。")
            self.scanned_set.clear()
            self.scanned_count = 0
            self.scanned_buffer.clear()
            self._pending_scanned_keys.clear()
            progress_state = {}

        self.persist_project_state()
        self.btn_c.setEnabled(False)
        self.btn_c.setText("识别中...")
        self.btn_stop.setEnabled(True)
        self.btn_stop.setText("停止")
        self._set_scan_config_enabled(False)

        current_progress = self.scanned_count
        total_hint = max(int(progress_state.get("total", 0) or 0), current_progress, 1)
        self.pg_bar.setMaximum(total_hint)
        self.pg_bar.setValue(current_progress)
        self.scan_started_at = time.time()
        self.scan_resume_base = current_progress
        self._refresh_main_progress_display(current_progress, total_hint)

        if current_progress:
            self.log("INFO", f"从断点继续扫描，已扫描 {current_progress} 条任务。")

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
        self._set_scan_config_enabled(True)
        self.apply_table_sort()
        self._refresh_main_progress_display(current_progress, total_progress, stopped=was_stopped)

        title = "扫描已中止" if was_stopped else "扫描完成"
        msg = (
            f"总计构建: {stats.get('total', 0)} 个变体\n"
            f"命中并写入战果: {stats.get('success', 0)} 条\n"
            f"失败/异常: {stats.get('fail', 0)} 条\n"
            f"当前断点进度: {current_progress} / {total_progress}\n\n"
            f"results.csv、断点记录文件、runtime.log、{SCAN_PROGRESS_FILE}、{FAIL_SAMPLE_FILE} 已保存，下次打开工程可继续。"
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
        self._refresh_main_progress_display(current, total)
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
            scanned_path = self._scanned_log_path(signature=self.scan_signature)
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
        row_data["site"] = derive_site_label(row_data.get("url", ""), row_data.get("host", ""))
        if save and self.proj:
            self.csv_buffer.append(row_data)
            if len(self.csv_buffer) >= 200:
                self.flush_csv_buffer()

        conf = str(row_data.get("conf", ""))
        remark = str(row_data.get("remark", ""))
        is_low_risk = "低危" in conf
        is_medium_risk = "中危" in conf
        is_high_priority = "极危" in conf or "高危" in conf
        if (
            "域名公网解析已经包含当前 IP" in remark
            and (is_low_risk or is_medium_risk)
        ):
            if "公网解析已覆盖" not in self._risk_cap_notified:
                self._risk_cap_notified.add("公网解析已覆盖")
                self.log("INFO", "域名公网解析已包含当前 IP 的中低危结果将不再显示到表格，仅保留 CSV。")
            return
        if (
            self.tb.rowCount() >= TOTAL_UI_SOFT_LIMIT
            and not is_high_priority
        ):
            if "总量" not in self._risk_cap_notified:
                self._risk_cap_notified.add("总量")
                self.log("INFO", f"结果表格已达到 UI 软上限 {TOTAL_UI_SOFT_LIMIT}，后续中低危仅写入 CSV。")
            return
        if is_low_risk and self.ui_conf_counts["低危"] >= LOW_RISK_UI_RENDER_LIMIT:
            if "低危" not in self._risk_cap_notified:
                self._risk_cap_notified.add("低危")
                self.log("INFO", f"低危结果已达到 UI 展示上限 {LOW_RISK_UI_RENDER_LIMIT}，后续仅写入 CSV。")
            return
        if is_medium_risk and self.ui_conf_counts["中危"] >= MEDIUM_RISK_UI_LIMIT:
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
            if field == "url":
                item.setToolTip("实际发包目标，通常是 IP 或 IP:端口。")
            elif field == "site":
                item.setToolTip("用于人工识别站点的展示列。")
            elif field == "host":
                item.setToolTip("本次请求注入的 Host 头。")
            elif field == "remark":
                item.setToolTip(str(value))

            self._apply_result_item_style(item, field, conf)

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
