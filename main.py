import sys, os, re, asyncio, aiohttp, subprocess, json, socket, ipaddress, traceback, csv
from datetime import datetime
from PySide6.QtCore import Qt, QThread, Signal, Slot, QTimer
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QTextEdit, QLineEdit, QPushButton, 
                             QLabel, QTableWidget, QTableWidgetItem, QSplitter,
                             QHeaderView, QGroupBox, QCheckBox, QFileDialog, 
                             QInputDialog, QMessageBox, QSpinBox, QDialog)
from PySide6.QtGui import QTextCursor, QColor
import concurrent.futures
# 在现有的 from PySide6.QtWidgets import (...) 中加上 QDialog
# ================= 1. 全局配置与正则 =================
RE_AST = r'((?:https?://|)\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?::\d+)?\b)'
RE_IP = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?::\d+)?\b'
RE_DOM = r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'

CONFIG_FILE = "config.json"
WORKSPACE_DIR = "workspace"
GLOBAL_LOG_FILE = "AssetCommander.log"

# ================= 1.5 全局 HTTP 状态码字典 =================
HTTP_STATUS = {
    100: "Continue(继续)", 101: "Switching Protocols(切换协议)",
    200: "OK(请求成功)", 201: "Created(已创建)", 202: "Accepted(已接受)", 
    203: "Non-Authoritative(非授权信息)", 204: "No Content(无内容)", 205: "Reset Content(重置内容)", 206: "Partial Content(部分内容)",
    300: "Multiple Choices(多种选择)", 301: "Moved Permanently(永久移动)", 302: "Found(临时移动)", 
    303: "See Other(查看其它地址)", 304: "Not Modified(未修改)", 305: "Use Proxy(使用代理)", 307: "Temporary Redirect(临时重定向)",
    400: "Bad Request(语法错误)", 401: "Unauthorized(要求身份认证)", 402: "Payment Required(保留)", 
    403: "Forbidden(拒绝执行)", 404: "Not Found(无法找到资源)", 405: "Method Not Allowed(方法被禁止)", 
    406: "Not Acceptable(无法接受)", 407: "Proxy Auth Required(要求代理认证)", 408: "Request Time-out(请求超时)", 
    409: "Conflict(冲突)", 410: "Gone(资源已永久删除)", 411: "Length Required(需要长度)", 
    412: "Precondition Failed(先决条件错误)", 413: "Entity Too Large(实体过大)", 414: "URI Too Large(URI过长)", 
    415: "Unsupported Media Type(不支持的媒体格式)", 416: "Range Not Satisfiable(请求范围无效)", 417: "Expectation Failed(预期失败)", 418: "I'm a teapot(愚人节彩蛋)",
    500: "Internal Server Error(内部错误)", 501: "Not Implemented(未实现)", 502: "Bad Gateway(网关错误)", 
    503: "Service Unavailable(暂停服务)", 504: "Gateway Time-out(网关超时)", 505: "HTTP Version not supported(不支持的协议版本)"
}

def write_global_log(level, msg):
    tm = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open(GLOBAL_LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"[{tm}] [{level}] {msg}\n")
    except Exception:
        pass

def get_base_config():
    default = {
        "fscan_cmd": "fscan.exe -h {target} -p 80,443,8080,8443 -m web -np -t 100",
        "oneforall_cmd": "python oneforall.py --target {target} run" 
    }
    if not os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(default, f, indent=4, ensure_ascii=False)
        return default
        
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            current_config = json.load(f)
    except Exception:
        current_config = {}

    needs_update = False
    for key, value in default.items():
        if key not in current_config:
            current_config[key] = value
            needs_update = True
            
    if needs_update:
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(current_config, f, indent=4, ensure_ascii=False)

    return current_config

def extract_title(html_text):
    m = re.search(r'<title>(.*?)</title>', html_text, re.I | re.S)
    if m:
        return m.group(1).strip().replace('\n', '').replace('\r', '')
    return "N/A"

# ================= 2. 外部工具任务引擎 =================
class ToolTask(QThread):
    log_sig = Signal(str, str)
    ast_sig = Signal(str)

    def __init__(self, name, cmd):
        super().__init__()
        self.name, self.cmd = name, cmd

    def run(self):
        self.log_sig.emit("INFO", f"启动任务: {self.cmd}")
        try:
            tool_cwd = None
            parts = self.cmd.replace("\\", "/").split()
            for p in parts:
                if (p.endswith('.py') or p.endswith('.exe')) and (":" in p or p.startswith("/")):
                    tool_cwd = os.path.dirname(p)
                    break
            
            env = os.environ.copy()
            env["PYTHONUNBUFFERED"] = "1" 
            
            p = subprocess.Popen(
                self.cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, 
                shell=True, env=env, cwd=tool_cwd if tool_cwd and os.path.exists(tool_cwd) else None
            )
            
            while True:
                line_b = p.stdout.readline()
                if not line_b: break
                try: line = line_b.decode('utf-8').strip()
                except: line = line_b.decode('gbk', errors='ignore').strip()
                
                if line:
                    self.log_sig.emit("DEBUG", f"[{self.name}] {line}")
                    self.ast_sig.emit(line)
                    
            p.wait()
            if p.returncode == 0: self.log_sig.emit("SUCCESS", f"{self.name} 执行结束")
            else: self.log_sig.emit("ERROR", f"{self.name} 异常退出，状态码: {p.returncode}")

        except Exception as e:
            err_trace = traceback.format_exc()
            self.log_sig.emit("ERROR", f"执行崩溃: {str(e)}")
            write_global_log("FATAL", f"[{self.name}] 执行崩溃详情:\n{err_trace}")


class CollTask(QThread):
    log_sig = Signal(str, str)
    res_sig = Signal(dict)
    summary_sig = Signal(dict, bool)

    def __init__(self, ips, domains, policies, concurrency, proj_dir=None):
        super().__init__()
        self.ips, self.domains, self.policies = ips, domains, policies
        self.concurrency = concurrency
        self.proj_dir = proj_dir # 接收工程目录
        self.stats = {"total": 0, "success": 0, "fail": 0}
        self._stop_flag = False
        self.domain_cache = {}
        self.dns_cache = {} # 新增：DNS 真实解析缓存
        self.garbage_titles = ['400', '401', '403', '404', '500', '502', '503', 'error', 'not found', 'forbidden', 'nginx', 'iis', 'apache', 'waf', 'block', '拦截', '找不到', '错误', 'tomcat']
        self._load_dns_cache()

    # ====== 加上这个修复方法 ======
    def stop(self):
        self._stop_flag = True
    # ============================
    # ============ 新增：DNS 持久化存取 ============
    def _load_dns_cache(self):
        if self.proj_dir:
            p = os.path.join(self.proj_dir, "domain_to_ip.json")
            if os.path.exists(p):
                try: 
                    raw_cache = json.load(open(p, 'r', encoding='utf-8'))
                    # 🌟 核心清洗：自动剔除历史遗留的带端口脏数据
                    self.dns_cache = {}
                    for k, v in raw_cache.items():
                        clean_k = k.split(':')[0]
                        if clean_k not in self.dns_cache or not self.dns_cache[clean_k]:
                            self.dns_cache[clean_k] = v
                except: pass

    def _save_dns_cache(self):
        if self.proj_dir:
            p = os.path.join(self.proj_dir, "domain_to_ip.json")
            try: json.dump(self.dns_cache, open(p, 'w', encoding='utf-8'), indent=4, ensure_ascii=False)
            except: pass

    async def resolve_dns(self, host):
        # 核心修复：清理 Host，剥离可能存在的端口号 (例如把 "domain:80" 变成 "domain")
        clean_host = host.split(':')[0] 
        
        if clean_host in self.dns_cache: return self.dns_cache[clean_host]
        loop = asyncio.get_running_loop()
        try:
            # 原生底层 DNS 异步查询，使用干净的纯域名
            _, _, ips = await loop.run_in_executor(None, socket.gethostbyname_ex, clean_host)
            self.dns_cache[clean_host] = ips
            return ips
        except Exception:
            self.dns_cache[clean_host] = [] # 查不到就是空列表
            return []

    def evaluate_hit(self, bc, bl, bt, hc, hl, ht, dc, dl, dt, dns_resolved, target_ip=None, resolved_ips=None):
        if resolved_ips is None: resolved_ips = []
        
        # 🌟 核心拦截：如果目标 IP 本来就在域名的真实解析记录里，说明是【正常的同站业务访问】
        # 绝不是什么 WAF 穿透或隐藏资产，直接静默抛弃！
        if target_ip and target_ip in resolved_ips:
            return "DROP", ""

        is_ht_garbage = any(g in ht.lower() for g in self.garbage_titles)
        juicy_kws = ['管理', '后台', '内部', '测试', 'api', 'admin', 'test', 'platform', '平台', '系统', 'swagger', '登录', 'sso']
        is_juicy = any(k in ht.lower() for k in juicy_kws)

        if is_ht_garbage: return "DROP", ""
        if hc == dc and ht == dt and abs(hl - dl) < 500: return "DROP", ""
        if hc == bc and ht == bt and abs(hl - bl) < 500: return "DROP", ""

        bc_desc = f"{bc} {HTTP_STATUS.get(bc, '未知')}"
        hc_desc = f"{hc} {HTTP_STATUS.get(hc, '未知')}"

        # 💥 场景 A & B 完美拆分：结合真实的 DNS 解析状态进行判定
        if dc == 0 and hc == 200:
            if not dns_resolved:
                # 真的没有 DNS 记录，绝对的私有测试域名
                return "🔥 极危", f"私有域名绑定: 无DNS解析记录 --> IP碰撞获取 [{ht}]"
            else:
                # DNS 是正常的，但是 HTTP 连不上 (WAF 掐断了或者网关封禁)
                return "🔥 极危", f"源站穿透(阻断绕过): 外网被拦/连接失败 --> 碰撞源站放行 [{ht}]"

        if dc in [401, 403, 400, 500, 502, 503] and hc == 200:
            return "🔥 极危", f"防御穿透绕过: 外网直连报错({dc}) --> 源站碰撞放行 [{ht}]"

        if hc == 200 and dc == 200 and ht != dt and dt != "N/A":
            lvl = "🔥 极危" if is_juicy else "✅ 高危"
            return lvl, f"源站映射差异: 标题 [{dt}] --> [{ht}]"

        if hc == 200 and bc not in [200, 301, 302]:
            return "✅ 高危", f"网关路由突破: 状态码 [{bc_desc}] --> [{hc_desc}] 标题: [{ht}]"

        if hc in [301, 302]:
            lvl = "✅ 高危" if is_juicy else "⚠️ 中危"
            return lvl, f"内部路径跳转: 状态码 [{bc_desc}] --> [{hc_desc}] 标题: [{ht}]"

        if hc in [401, 405, 500] and bc in [404, 403, 400]:
            return "⚠️ 中危", f"后端应用触达: 边缘阻断 [{bc_desc}] --> 业务层响应 [{hc_desc}]"

        if hc == 200 and bc == 200:
            diff = hl - bl
            if diff > 1000:
                lvl = "✅ 高危" if is_juicy else "⚠️ 中危"
                return lvl, f"疑似隐藏接口: 长度 {bl} --> {hl} (暴增 {diff} 字节)"
            elif diff < -1000:
                return "ℹ️ 低危", f"响应容量锐减: 长度 {bl} --> {hl} (减少 {abs(diff)} 字节)"

        if hc >= 400 and bc >= 400 and hc != bc:
             return "ℹ️ 低危", f"内部错误解析变更: [{bc_desc}] --> [{hc_desc}]"
        return "DROP", ""

    async def fetch(self, session, url, host):
        if self._stop_flag: return
        try:
            scheme = url.split("://")[0]
            
            # 1. 前置 DNS 真实解析校验
            resolved_ips = await self.resolve_dns(host)
            dns_resolved = len(resolved_ips) > 0

            # 2. IP 直连基线
            async with session.get(url, timeout=5, allow_redirects=False, ssl=False) as rb:
                b_text = await rb.text(); bc, bl, bt = rb.status, len(b_text), extract_title(b_text)
            
            # 3. 域名外网直连基线
            cache_key = f"{scheme}://{host}"
            if cache_key not in self.domain_cache:
                if not dns_resolved:
                    # DNS 都没记录，HTTP 根本不用发，必死
                    self.domain_cache[cache_key] = (0, 0, "DEAD_DOMAIN")
                else:
                    try:
                        async with session.get(cache_key, timeout=5, ssl=False, allow_redirects=False) as rd:
                            d_text = await rd.text(); self.domain_cache[cache_key] = (rd.status, len(d_text), extract_title(d_text))
                    except Exception:
                        # 核心修正：DNS 有记录，但 HTTP 崩了 (超时/掐断)
                        self.domain_cache[cache_key] = (0, 0, "HTTP_FAILED")
            dc, dl, dt = self.domain_cache[cache_key]

            # 4. Host 碰撞注射
            headers = {"Host": host}
            if self.policies.get('waf', False):
                headers.update({"X-Forwarded-For":"127.0.0.1", "X-Real-IP":"127.0.0.1", "X-Forwarded-Host":host})
            req_url = url
            if self.policies.get('abs', False):
                req_url = url.replace(url.split("//")[1].split("/")[0], host)

            async with session.get(req_url, headers=headers, timeout=5, allow_redirects=False, ssl=False) as rh:
                h_text = await rh.text(); hc, hl, ht = rh.status, len(h_text), extract_title(h_text)
            
            # 🌟 修复：从 url (例如 http://120.7.x.x:80) 中提取出干净的 Target IP
            target_ip = url.split("://")[1].split(":")[0].split("/")[0]
            
            # 把 target_ip 和 resolved_ips 传给终极裁判
            confidence, remark = self.evaluate_hit(bc, bl, bt, hc, hl, ht, dc, dl, dt, dns_resolved, target_ip, resolved_ips)
            
            if confidence != "DROP":
                self.res_sig.emit({"url": url, "host": host, "code": hc, "len": hl, "title": ht, "conf": confidence, "remark": remark})
                self.stats["success"] += 1
                if "危" in confidence: self.log_sig.emit("SUCCESS", f"{confidence}! {url} -> Host:{host} [{remark}]")
                else: self.log_sig.emit("INFO", f"边缘资产: {url} -> Host:{host}")
        except asyncio.CancelledError: pass
        except Exception: self.stats["fail"] += 1

    def run(self):
        if sys.platform == 'win32':
            asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
            
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        # 队列消费工作者
        async def worker(queue, session):
            while not self._stop_flag:
                try:
                    # 加超时机制，超时就回去检查 _stop_flag
                    task_data = await asyncio.wait_for(queue.get(), timeout=0.5)
                    if task_data is None: 
                        queue.task_done()
                        break
                    url, host = task_data
                    await self.fetch(session, url, host)
                    queue.task_done()
                except asyncio.TimeoutError:
                    continue 
                except asyncio.CancelledError:
                    break 
                except Exception:
                    pass

        async def run_all():
            connector = aiohttp.TCPConnector(limit=self.concurrency, ssl=False, force_close=True)
            async with aiohttp.ClientSession(connector=connector) as session:
                queue = asyncio.Queue(maxsize=self.concurrency * 2) 
                
                # 启动工作协程
                workers = [asyncio.create_task(worker(queue, session)) for _ in range(self.concurrency)]
                
                task_items = []
                for rip in self.ips:
                    pure = rip.split(":")[0]; port = rip.split(":")[1] if ":" in rip else None
                    v = set()
                    if self.policies.get('k', True) and port: v.update([f"http://{rip}", f"https://{rip}"])
                    if self.policies.get('80', True): v.add(f"http://{pure}:80")
                    if self.policies.get('443', True): v.add(f"https://{pure}:443")
                    if self.policies.get('n', True): v.update([f"http://{pure}", f"https://{pure}"])
                    
                    for u in v:
                        for d in self.domains:
                            task_items.append((u, d))
                            parts = u.split(":")
                            if len(parts) == 3: 
                                port = parts[-1]
                                task_items.append((u, f"{d}:{port}"))
                
                self.stats["total"] = len(task_items)
                self.log_sig.emit("INFO", f"🚀 智能对撞引擎启动，变体池: {self.stats['total']} 个，并发: {self.concurrency}")
                
                # 推送任务进队列时，也要能被 _stop_flag 打断
                for item in task_items:
                    if self._stop_flag: break
                    while not self._stop_flag:
                        try:
                            await asyncio.wait_for(queue.put(item), timeout=0.5)
                            break
                        except asyncio.TimeoutError:
                            pass
                            
                # 发送结束信号
                if not self._stop_flag:
                    for _ in range(self.concurrency):
                        await queue.put(None)
                
                # 抛弃 gather 死等，改用轮询等待 Worker 结束，随时强杀
                while workers:
                    if self._stop_flag:
                        for w in workers: w.cancel()
                        break
                    done, pending = await asyncio.wait(workers, timeout=0.5)
                    workers = list(pending)

        try:
            loop.run_until_complete(run_all())
            self.summary_sig.emit(self.stats, self._stop_flag)
        except Exception as e:
            err_trace = traceback.format_exc()
            self.log_sig.emit("ERROR", f"对撞引擎异常: {str(e)}")
            write_global_log("FATAL", f"对撞引擎崩溃堆栈:\n{err_trace}")
        finally:
            # ==== 跑完自动保存 DNS 字典 ====
            self._save_dns_cache() 
            try:
                loop.run_until_complete(loop.shutdown_asyncgens())
                loop.close()
            except Exception:
                pass

# ================= 3.5 真实IP猎手与WAF识别引擎 =================
class DnsResolverTask(QThread):
    res_sig = Signal(str, str, str, str) # domain, ip, cname, status
    fin_sig = Signal()

    def __init__(self, domains):
        super().__init__()
        self.domains = domains
        # 常见 CDN/WAF 的 CNAME 特征黑名单
        self.waf_cdn_cname = ['cdn', 'waf', 'cloudflare', 'kunlun', 'aliyun', 'yundun', 
                              'akamai', 'fastly', 'qcloud', 'jiasu', 'ccgslb', 'edge', 'incapsula']

    def resolve_single(self, dom):
        try:
            # 核心修复：不管用户粘贴了什么鬼东西(http/https/端口/路径)，全部剥离还原为纯净域名
            clean_dom = dom.replace("http://", "").replace("https://", "").split(':')[0].split('/')[0]
            # 获取解析记录
            hostname, aliases, ips = socket.gethostbyname_ex(dom)
            cname = aliases[0] if aliases else ""
            
            # 判断是否过 WAF/CDN
            check_str = (hostname + str(aliases)).lower()
            is_waf = any(kw in check_str for kw in self.waf_cdn_cname)
            status = "☁️ CDN/WAF节点" if is_waf else "🎯 疑似真实源站"
            
            for ip in set(ips):
                self.res_sig.emit(dom, ip, cname, status)
        except Exception:
            self.res_sig.emit(dom, "解析失败 (NXDOMAIN)", "-", "❌ 无效记录")

    def run(self):
        # 采用 50 线程极速并发解析
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(self.resolve_single, d) for d in set(self.domains) if d]
            concurrent.futures.wait(futures)
        self.fin_sig.emit()

class RealIPHunterDialog(QDialog):
    def __init__(self, parent=None, ip_pool_widget=None, proj_dir=None):
        super().__init__(parent)
        self.setWindowTitle("🔍 真实IP猎手 - 绕过CDN与WAF探测引擎")
        self.resize(1000, 600)
        self.ip_pool_widget = ip_pool_widget 
        self.proj_dir = proj_dir # 新增工程目录引用
        self.setStyleSheet("""
            QDialog { background-color: #0d1117; color: #c9d1d9; }
            QTableWidget { background-color: #161b22; border: 1px solid #30363d; gridline-color: #30363d; }
            QHeaderView::section { background-color: #21262d; border: 1px solid #30363d; font-weight:bold; color: #c9d1d9; }
            QPushButton { background-color: #238636; color: white; font-weight: bold; padding: 6px; border-radius: 3px; }
            QPushButton:hover { background-color: #2ea043; }
            QTextEdit { background-color: #161b22; border: 1px solid #30363d; color: #c9d1d9; }
        """)
        self.init_ui()
        self.load_state() # 启动时读取记忆

    def init_ui(self):
        ml = QVBoxLayout(self)
        sp = QSplitter(Qt.Horizontal)
        
        left_w = QWidget(); ll = QVBoxLayout(left_w)
        ll.setContentsMargins(0,0,0,0)
        ll.addWidget(QLabel("待探测的子域名列表 (每行一个):"))
        self.input_doms = QTextEdit()
        self.input_doms.textChanged.connect(self.save_state) # 实时保存
        self.input_doms.setPlaceholderText("sub.target.com\napi.target.com\n...")
        ll.addWidget(self.input_doms)
        
        self.btn_run = QPushButton("⚡ 开始并发溯源分析")
        self.btn_run.clicked.connect(self.start_resolve)
        ll.addWidget(self.btn_run)
        sp.addWidget(left_w)
        
        right_w = QWidget(); rl = QVBoxLayout(right_w)
        rl.setContentsMargins(0,0,0,0)
        self.tb = QTableWidget(0, 4)
        self.tb.setHorizontalHeaderLabels(["域名 (Domain)", "解析IP (A Record)", "别名 (CNAME)", "资产定性诊断"])
        self.tb.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.tb.horizontalHeader().setStretchLastSection(True)
        self.tb.setColumnWidth(0, 180); self.tb.setColumnWidth(1, 130); self.tb.setColumnWidth(2, 200)
        self.tb.setSortingEnabled(True)
        rl.addWidget(self.tb)
        
        hl = QHBoxLayout()
        self.btn_extract_all = QPushButton("📥 提取全部成功IP至主界面")
        self.btn_extract_all.setStyleSheet("background-color: #1f6feb;")
        self.btn_extract_all.clicked.connect(lambda: self.extract_ips(all_ips=True))
        
        self.btn_extract_real = QPushButton("🎯 仅提取【真实源站】IP至主界面 (推荐)")
        self.btn_extract_real.setStyleSheet("background-color: #8957e5;")
        self.btn_extract_real.clicked.connect(lambda: self.extract_ips(all_ips=False))
        
        hl.addWidget(self.btn_extract_all); hl.addWidget(self.btn_extract_real)
        rl.addLayout(hl)
        sp.addWidget(right_w)
        sp.setStretchFactor(0, 1); sp.setStretchFactor(1, 3)
        ml.addWidget(sp)

    # ========== 状态保存与读取 (连带表格一起保存) ==========
    def save_state(self):
        if not self.proj_dir: return
        results = []
        for r in range(self.tb.rowCount()):
            results.append({
                "dom": self.tb.item(r, 0).text(), "ip": self.tb.item(r, 1).text(),
                "cname": self.tb.item(r, 2).text(), "status": self.tb.item(r, 3).text()
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
        self.btn_run.setEnabled(True); self.btn_run.setText("⚡ 开始并发溯源分析")
        self.save_state() # 跑完自动保存战果
        QMessageBox.information(self, "完成", "资产溯源分析完毕！")

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
            i_status.setForeground(QColor(88, 166, 255)) # 蓝色高亮，说明可以直接打
        elif "CDN" in status:
            i_status.setForeground(QColor(139, 148, 158)) # 灰色，大概率是云节点
        else:
            i_status.setForeground(QColor(248, 81, 73)) # 红色报错
            
        self.tb.setItem(r, 0, i_dom); self.tb.setItem(r, 1, i_ip)
        self.tb.setItem(r, 2, i_cname); self.tb.setItem(r, 3, i_status)

    def extract_ips(self, all_ips):
        if not self.ip_pool_widget: return
        extracted = set()
        for row in range(self.tb.rowCount()):
            ip_item = self.tb.item(row, 1)
            status_item = self.tb.item(row, 3)
            if not ip_item or not status_item: continue
            ip, status = ip_item.text(), status_item.text()
            if "无效" in status or "失败" in ip: continue
            if not all_ips and "CDN" in status: continue
            extracted.add(ip)
            
        if not extracted: return QMessageBox.warning(self, "提示", "没有符合条件的有效 IP 可提取！")
        
        # 核心修复：无视光标，整体重新渲染
        current_text = self.ip_pool_widget.toPlainText()
        existing_lines = [line.strip() for line in current_text.split('\n') if line.strip()]
        new_ips = [x for x in extracted if x not in set(existing_lines)]
        
        if new_ips:
            final_lines = existing_lines + new_ips
            self.ip_pool_widget.setPlainText("\n".join(final_lines) + "\n")
            QMessageBox.information(self, "成功", f"净化完毕！提取了 {len(new_ips)} 个干净的 IP。")
        else:
            QMessageBox.information(self, "提示", "提取的 IP 已全在主界面中。")


class FissionTask(QThread):
    res_sig = Signal(str, str, str, str) # ip:port, title, status, color
    fin_sig = Signal()

    def __init__(self, ips, keywords, ports_str):
        super().__init__()
        self.ips = ips
        self.keywords = [k.strip().lower() for k in keywords.split(',') if k.strip()]
        # 解析端口，过滤掉非数字的脏字符
        self.ports = [p.strip() for p in ports_str.split(',') if p.strip().isdigit()]
        if not self.ports: 
            self.ports = ['80', '443'] # 兜底端口
        self._stop = False

    async def fetch_title(self, session, url, sem):
        if self._stop: return
        try:
            async with sem:
                if self._stop: return 
                async with session.get(url, timeout=8, ssl=False, allow_redirects=True) as resp:
                    text = await resp.text(errors='ignore')
                    title = extract_title(text).strip()
                    if not title or title == "N/A": return 
                        
                    title_lower = title.lower()
                    is_match = True if not self.keywords else any(kw in title_lower for kw in self.keywords)

                    if is_match:
                        self.res_sig.emit(url, title, "🎯 精准命中", "#3fb950") 
                    else:
                        self.res_sig.emit(url, title, "☁️ 旁站/无关资产", "#8b949e") 
        except asyncio.CancelledError:
            pass 
        except Exception:
            pass 

    def run(self):
        if sys.platform == 'win32': asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
        loop = asyncio.new_event_loop(); asyncio.set_event_loop(loop)
        
        async def run_all():
            conn = aiohttp.TCPConnector(limit=0, ssl=False) 
            async with aiohttp.ClientSession(connector=conn) as session:
                sem = asyncio.Semaphore(200) 
                
                tasks = []
                for ip in self.ips:
                    if self._stop: break
                    for port in self.ports:
                        # 智能协议判定
                        if port in ['443', '8443', '4443']:
                            tasks.append(asyncio.create_task(self.fetch_title(session, f"https://{ip}:{port}", sem)))
                        elif port in ['80', '8080', '8888', '81', '7001']:
                            tasks.append(asyncio.create_task(self.fetch_title(session, f"http://{ip}:{port}", sem)))
                        else:
                            # 奇葩端口盲打两次
                            tasks.append(asyncio.create_task(self.fetch_title(session, f"http://{ip}:{port}", sem)))
                            tasks.append(asyncio.create_task(self.fetch_title(session, f"https://{ip}:{port}", sem)))

                while tasks:
                    if self._stop:
                        for t in tasks: t.cancel()
                        break
                    done, pending = await asyncio.wait(tasks, timeout=0.5)
                    tasks = list(pending)

        try: loop.run_until_complete(run_all())
        except Exception: pass
        finally:
            try: loop.run_until_complete(loop.shutdown_asyncgens()); loop.close()
            except: pass
        self.fin_sig.emit()

class IPFissionDialog(QDialog):
    def __init__(self, parent=None, ip_pool_widget=None, proj_dir=None):
        super().__init__(parent)
        self.setWindowTitle("🕸️ 资产裂变与指纹提纯引擎 (C段狙击手)")
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
        self.load_state() # 启动时读取记忆

    def init_ui(self):
        ml = QVBoxLayout(self)
        sp = QSplitter(Qt.Horizontal)
        
        left_w = QWidget(); ll = QVBoxLayout(left_w); ll.setContentsMargins(0,0,0,0)
        ll.addWidget(QLabel("1. 输入种子 IP (支持单IP或网段):"))
        self.input_ips = QTextEdit()
        self.input_ips.textChanged.connect(self.save_state) # 实时保存
        ll.addWidget(self.input_ips, stretch=2)
        
        btn_c = QPushButton("⚡ 一键拓扑 C 段 (转为 /24)")
        btn_c.setStyleSheet("background-color: #8957e5;")
        btn_c.clicked.connect(self.expand_c_class)
        ll.addWidget(btn_c)
        
        ll.addWidget(QLabel("\n2. Title 关键字狙击 (逗号分隔):"))
        self.input_kws = QLineEdit()
        self.input_kws.textChanged.connect(self.save_state) # 实时保存
        ll.addWidget(self.input_kws)

        # 新增端口配置
        ll.addWidget(QLabel("\n3. Web 端口探测 (逗号分隔):"))
        self.input_ports = QLineEdit()
        self.input_ports.setText("80, 443, 8080, 8443, 8888, 7001")
        self.input_ports.textChanged.connect(self.save_state) # 实时保存
        ll.addWidget(self.input_ports)
        
        run_layout = QHBoxLayout()
        self.btn_run = QPushButton("🚀 启动并发测绘")
        self.btn_run.clicked.connect(self.start_scan)
        
        self.btn_stop = QPushButton("🛑 停止")
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
        
        self.btn_ext = QPushButton("📥 将【🎯 精准命中】的 IP 注入主战IP池")
        self.btn_ext.setStyleSheet("background-color: #1f6feb; height: 35px; font-size: 14px;")
        self.btn_ext.clicked.connect(self.extract_to_main)
        rl.addWidget(self.btn_ext)
        sp.addWidget(right_w)
        sp.setStretchFactor(0, 1); sp.setStretchFactor(1, 3)
        ml.addWidget(sp)

    # ========== 状态保存与读取 ==========
    def save_state(self):
        if self.proj_dir:
            try:
                json.dump({
                    "ips": self.input_ips.toPlainText(), "kws": self.input_kws.text(), "ports": self.input_ports.text()
                }, open(os.path.join(self.proj_dir, "fission.json"), 'w'))
            except: pass

    def load_state(self):
        if self.proj_dir and os.path.exists(os.path.join(self.proj_dir, "fission.json")):
            try:
                self.input_ips.blockSignals(True); self.input_kws.blockSignals(True); self.input_ports.blockSignals(True)
                s = json.load(open(os.path.join(self.proj_dir, "fission.json")))
                self.input_ips.setPlainText(s.get("ips", ""))
                self.input_kws.setText(s.get("kws", ""))
                self.input_ports.setText(s.get("ports", "80, 443, 8080, 8443, 8888, 7001"))
                self.input_ips.blockSignals(False); self.input_kws.blockSignals(False); self.input_ports.blockSignals(False)
            except: pass

    def closeEvent(self, event):
        # 改用 work_thread 判断
        if hasattr(self, 'work_thread') and self.work_thread.isRunning():
            self.work_thread._stop = True
            self.btn_stop.setText("正在安全退出...")
            self.work_thread.wait(1500) 
        event.accept()

    def stop_scan(self):
        # 改用 work_thread 判断
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
            QMessageBox.information(self, "拓扑成功", f"已自动计算并去重，生成 {len(c_classes)} 个 C 段！")

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

        if not target_ips: return QMessageBox.warning(self, "!", "未发现有效 IP 或网段！")
        self.tb.setSortingEnabled(False); self.tb.setRowCount(0)
        self.btn_run.setEnabled(False); self.btn_run.setText(f"🚀 正在测绘 {len(target_ips)} 个独立IP...")
        self.btn_stop.setEnabled(True); self.btn_stop.setText("🛑 停止")
        
        # 传入端口配置 (把原先的 self.thread 改为 self.work_thread)
        self.work_thread = FissionTask(list(target_ips), self.input_kws.text(), self.input_ports.text())
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
        self.btn_run.setEnabled(True); self.btn_run.setText("🚀 启动并发测绘")
        self.btn_stop.setEnabled(False); self.btn_stop.setText("🛑 停止")
        QMessageBox.information(self, "完成", "C段指纹测绘完毕！无效资产已静默丢弃。")

    def extract_to_main(self):
        if not self.ip_pool_widget: return
        extracted = set()
        for row in range(self.tb.rowCount()):
            status_item = self.tb.item(row, 2)
            url_item = self.tb.item(row, 0)
            if status_item and url_item and "命中" in status_item.text():
                clean_ip = url_item.text().replace("http://", "").replace("https://", "").split(':')[0]
                extracted.add(clean_ip)
                
        if not extracted: return QMessageBox.warning(self, "提示", "没有【🎯 精准命中】的目标可以提取！")
        
        # 核心修复：无视光标，整体重新渲染
        current_text = self.ip_pool_widget.toPlainText()
        existing_lines = [line.strip() for line in current_text.split('\n') if line.strip()]
        new_ips = [x for x in extracted if x not in set(existing_lines)]
        
        if new_ips:
            final_lines = existing_lines + new_ips
            self.ip_pool_widget.setPlainText("\n".join(final_lines) + "\n")
            QMessageBox.information(self, "成功", f"净化完毕！已将 {len(new_ips)} 个极品 IP 注入主界面！")
        else:
            QMessageBox.information(self, "提示", "提取的 IP 已全在主界面中。")


# ================= 4. 主 GUI 界面 =================
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

    def open_ip_fission(self):
        self.fission_dialog = IPFissionDialog(self, ip_pool_widget=self.i_pl, proj_dir=self.proj)
        self.fission_dialog.show()

    def open_ip_hunter(self):
        self.hunter_dialog = RealIPHunterDialog(self, ip_pool_widget=self.i_pl, proj_dir=self.proj)
        self.hunter_dialog.show()

    def open_ip_reverse(self):
        ips = [ip.strip() for ip in self.i_pl.toPlainText().split() if ip.strip()]
        # 核心修正：传入 proj_dir=self.proj，激活工具的状态记忆引擎
        self.rev_dialog = ReverseIPDialog(self, dom_pool_widget=self.d_pl, ips=ips, proj_dir=self.proj)
        self.rev_dialog.show()

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
        bn = QPushButton("📁 新建工程"); bn.clicked.connect(self.new_p); bo = QPushButton("📂 打开工程"); bo.clicked.connect(self.open_p)
        # --- 新增强制保存按钮 ---
        self.bs = QPushButton("💾 强制保存战果"); self.bs.setStyleSheet("background-color: #2ea043; color: white; font-weight: bold;")
        self.bs.clicked.connect(self.force_save) # 删除了 setEnabled(False)
        pl.addWidget(self.lbl_p); pl.addStretch(1); pl.addWidget(self.bs); pl.addWidget(bn); pl.addWidget(bo); ml.addLayout(pl)

        tl = QHBoxLayout(); self.t_ed = QLineEdit(); self.t_ed.setPlaceholderText("Target Domain or IP Segment")
        bf = QPushButton("FScan 收割"); bf.clicked.connect(self.run_f); bo = QPushButton("OFA 收割"); bo.clicked.connect(self.run_o)
        tl.addWidget(QLabel("目标:")); tl.addWidget(self.t_ed); tl.addWidget(bf); tl.addWidget(bo); ml.addLayout(tl)
        self.t_ed.textChanged.connect(self.sv_sett)

        sp = QSplitter(Qt.Horizontal); lb = QWidget(); ll = QVBoxLayout(lb)
        self.i_pl = QTextEdit(); self.d_pl = QTextEdit()
        self.i_pl.textChanged.connect(lambda: self.sv_f("ips.txt", self.i_pl))
        self.d_pl.textChanged.connect(lambda: self.sv_f("domains.txt", self.d_pl))
        
        pg = QGroupBox("碰撞策略与高级绕过"); pgl = QVBoxLayout(pg)
        hl1 = QHBoxLayout(); self.c_k = QCheckBox("保留原端口"); self.c_8 = QCheckBox("补齐:80"); self.c_4 = QCheckBox("补齐:443"); self.c_n = QCheckBox("无端口")
        for c in[self.c_k, self.c_8, self.c_4, self.c_n]: c.setChecked(True); c.stateChanged.connect(self.sv_sett); hl1.addWidget(c)
        hl2 = QHBoxLayout(); self.c_abs = QCheckBox("绝对路径"); self.c_waf = QCheckBox("注入 WAF 绕过头"); self.c_sni = QCheckBox("强同步 SNI")
        for c in[self.c_abs, self.c_waf, self.c_sni]: c.stateChanged.connect(self.sv_sett); hl2.addWidget(c)
        hl2.addStretch(1); pgl.addLayout(hl1); pgl.addLayout(hl2)

        hl_ctrl = QHBoxLayout()
        hl_ctrl.addWidget(QLabel("并发:"))
        
        self.spin_threads = QSpinBox()
        self.spin_threads.setRange(10, 3000)
        self.spin_threads.setValue(150)
        # 仅保留基础颜色，去掉高度限制
        self.spin_threads.setStyleSheet("background-color: #161b22; color: #c9d1d9;")
        hl_ctrl.addWidget(self.spin_threads)

        # 极简按钮，去掉乱七八糟的 emoji 和 CSS，依靠顶部的全局 stylesheet 渲染
        self.btn_c = QPushButton("启动对撞")
        self.btn_c.clicked.connect(self.run_c)
        hl_ctrl.addWidget(self.btn_c)

        self.btn_stop = QPushButton("停止")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.stop_c)
        hl_ctrl.addWidget(self.btn_stop)

        self.btn_export = QPushButton("导出")
        self.btn_export.clicked.connect(self.export_csv)
        hl_ctrl.addWidget(self.btn_export)
        
        # 【关键破局点】：强制允许左侧面板被压缩得更小（解除布局锁死）
        lb.setMinimumWidth(200)

        # --- IP 池标题与裂变工具入口 ---
        i_lbl_layout = QHBoxLayout()
        i_lbl_layout.addWidget(QLabel("IP 池 (ips.txt):"))
        
        btn_fission = QPushButton("🕸️ C段裂变与提纯")
        btn_fission.setStyleSheet("background-color: #8957e5; padding: 2px 5px; font-size: 12px;")
        btn_fission.clicked.connect(self.open_ip_fission)
        i_lbl_layout.addWidget(btn_fission)
        i_lbl_layout.addStretch(1)
        
        ll.addLayout(i_lbl_layout)
        ll.addWidget(self.i_pl)
        # -----------------------------
        # --- 新增：猎手工具入口布局 ---
        d_lbl_layout = QHBoxLayout()
        d_lbl_layout.addWidget(QLabel("域名池 (domains.txt):"))
        
        btn_hunter = QPushButton("🔍 真实IP猎手")
        btn_hunter.setStyleSheet("background-color: #238636; padding: 2px 5px; font-size: 12px;")
        btn_hunter.clicked.connect(self.open_ip_hunter)
        d_lbl_layout.addWidget(btn_hunter)

        # ====== 新增的反查按钮 ======
        btn_reverse = QPushButton("🌐 IP反查域名")
        btn_reverse.setStyleSheet("background-color: #8957e5; padding: 2px 5px; font-size: 12px;")
        btn_reverse.clicked.connect(self.open_ip_reverse)
        d_lbl_layout.addWidget(btn_reverse)
        # ==========================
        
        d_lbl_layout.addStretch(1)
        
        ll.addLayout(d_lbl_layout)
        # ---------------------------
        
        ll.addWidget(self.d_pl)
        ll.addWidget(pg); ll.addLayout(hl_ctrl) 
        sp.addWidget(lb)

        self.tb = QTableWidget(0, 7)
        self.tb.setHorizontalHeaderLabels(["Target", "Host", "Code", "Len", "Title", "置信度", "智能诊断"])
        
        # ====== 核心修复 UI 表格太呆的问题 ======
        # 把强制填充改为 Interactive（允许鼠标拖拽列宽）
        self.tb.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        # 最后一列填满剩余空白
        self.tb.horizontalHeader().setStretchLastSection(True)
        # 默认给第一、第二列长一点的宽度
        self.tb.setColumnWidth(0, 220)
        self.tb.setColumnWidth(1, 200)
        # 允许表头点击排序功能（找数据更方便）
        self.tb.setSortingEnabled(True)
        # ========================================
        
        sp.addWidget(self.tb); sp.setStretchFactor(1, 2); ml.addWidget(sp)

        self.lv = QTextEdit(); self.lv.setReadOnly(True); self.lv.setFixedHeight(150)
        ml.addWidget(QLabel("战地实时审计日志:")); ml.addWidget(self.lv)

        self.lv.document().setMaximumBlockCount(2000)
        self.log_buffer = []
        self.log_timer = QTimer(self); self.log_timer.timeout.connect(self.flush_log_buffer); self.log_timer.start(200)

    # =============== 核心逻辑函数 ===============
    def new_p(self):
        n, ok = QInputDialog.getText(self, "新建", "输入工程名:"); 
        if ok and n: d = os.path.join(WORKSPACE_DIR, n); os.makedirs(d, exist_ok=True); self.load_p(d)

    def open_p(self):
        d = QFileDialog.getExistingDirectory(self, "选择工程", WORKSPACE_DIR)
        if d: self.load_p(d)

    def load_p(self, d):
        self.i_pl.blockSignals(True); self.d_pl.blockSignals(True)
        self.proj = d; self.lbl_p.setText(f"工程: {os.path.basename(d)}")
        self.i_pl.clear(); self.d_pl.clear(); self.tb.setRowCount(0); self.ips.clear(); self.doms.clear()
        
        for f, w in [("ips.txt", self.i_pl), ("domains.txt", self.d_pl)]:
            p = os.path.join(d, f)
            if os.path.exists(p):
                with open(p, 'r', encoding='utf-8') as file:
                    content = file.read(); w.setPlainText(content)
                    if "ips" in f: self.ips.update(content.split())
                    else: self.doms.update(content.split())
                    
        self.i_pl.blockSignals(False); self.d_pl.blockSignals(False)
        
        sp = os.path.join(d, "settings.json")
        if os.path.exists(sp):
            s = json.load(open(sp,'r'))
            # 增加读取 target
            self.t_ed.blockSignals(True)
            self.t_ed.setText(s.get('target', ''))
            self.t_ed.blockSignals(False)
            
            self.c_k.setChecked(s.get('k',True)); self.c_8.setChecked(s.get('80',True)); self.c_4.setChecked(s.get('443',True))
            self.c_n.setChecked(s.get('n',True)); self.c_abs.setChecked(s.get('abs',False)); self.c_waf.setChecked(s.get('waf',False))
            self.c_sni.setChecked(s.get('sni',False))
        
        # --- 核心修复：更换为 CSV 并加入 UI 防卡死锁 ---
        rp = os.path.join(d, "results.csv")
        if os.path.exists(rp):
            self.tb.setUpdatesEnabled(False) # 关键：锁死UI刷新，防止插入千行数据时崩溃
            self.tb.setSortingEnabled(False) # 关键：关闭排序，防止插入时反复重排
            try:
                with open(rp, 'r', encoding='utf-8-sig') as f:
                    reader = csv.DictReader(f)
                    for row_data in reader:
                        # 确保读取的是有效数据
                        if row_data.get("url"):
                            self.add_res_ui(row_data, save=False)
            except Exception as e: 
                self.log("ERROR", f"读取战果缓存出错: {str(e)}")
            self.tb.setSortingEnabled(True)
            self.tb.setUpdatesEnabled(True) # 解锁UI刷新
            
        self.log("SUCCESS", f"工程载入成功，IP:{len(self.ips)}, Host:{len(self.doms)}")

    def sv_f(self, f, w):
        if self.proj: 
            try: open(os.path.join(self.proj, f), 'w', encoding='utf-8').write(w.toPlainText())
            except Exception: pass

    def sv_sett(self):
        if self.proj:
            json.dump({
                'target': self.t_ed.text(), # 增加保存 target
                'k':self.c_k.isChecked(), '80':self.c_8.isChecked(), '443':self.c_4.isChecked(),
                'n':self.c_n.isChecked(), 'abs':self.c_abs.isChecked(), 'waf':self.c_waf.isChecked(),
                'sni':self.c_sni.isChecked()
            }, open(os.path.join(self.proj, "settings.json"),'w'))

    @Slot(str, str)
    def log(self, lvl, m):
        self.log_buffer.append((lvl, m))

    def flush_log_buffer(self):
        if not self.log_buffer: return
        tm = datetime.now().strftime("%H:%M:%S")
        cs = {"INFO":"#58a6ff", "SUCCESS":"#3fb950", "ERROR":"#f85149", "DEBUG":"#8b949e", "FATAL":"#ff0000"}
        gui_html, file_text = [], ""
        for lvl, m in self.log_buffer:
            gui_html.append(f'<span style="color:#8b949e">[{tm}]</span> <span style="color:{cs.get(lvl,"#fff")}">[{lvl}]</span> {m}')
            file_text += f"[{tm}] [{lvl}] {m}\n"
        self.log_buffer.clear(); self.lv.append("<br>".join(gui_html)); self.lv.moveCursor(QTextCursor.End)
        if self.proj:
            try: open(os.path.join(self.proj, "runtime.log"), 'a', encoding='utf-8').write(file_text)
            except: pass

    @Slot(str)
    def cln(self, t):
        return
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
        if not self.proj: return QMessageBox.warning(self, "!", "请先选择工程")
        t = self.t_ed.text().strip(); st = t
        try:
            if not re.match(RE_IP, t) and "/" not in t:
                # 核心修复：先洗掉端口和协议再查 IP
                clean_t = t.replace("http://", "").replace("https://", "").split(':')[0].split('/')[0]
                ip = socket.gethostbyname(clean_t)
                st = str(ipaddress.ip_network(f"{ip}/24", False).network_address)+"/24"
        except: pass
        cmd = self.config.get("fscan_cmd", "").replace("{target}", st)
        self.th = ToolTask("FScan", cmd); self.th.log_sig.connect(self.log); self.th.ast_sig.connect(self.cln); self.th.start()

    def run_o(self):
        if not self.proj: return QMessageBox.warning(self, "!", "请先选择工程")
        cmd = self.config.get("oneforall_cmd", "").replace("{target}", self.t_ed.text().strip())
        self.th = ToolTask("OFA", cmd); self.th.log_sig.connect(self.log); self.th.ast_sig.connect(self.cln); self.th.start()

    def run_c(self):
        if not self.proj: return QMessageBox.warning(self, "!", "请先打开或新建一个工程")
        if hasattr(self, 'cth') and self.cth.isRunning(): return self.log("ERROR", "上一个对撞任务仍在进行中！")
        il, dl = self.i_pl.toPlainText().split(), self.d_pl.toPlainText().split()
        if not il or not dl: return self.log("ERROR", "IP池或域名池为空！")
        
        self.btn_c.setEnabled(False); self.btn_c.setText("识别中...")
        self.btn_stop.setEnabled(True); self.btn_stop.setText("停止")
        
        pol = {'k':self.c_k.isChecked(), '80':self.c_8.isChecked(), '443':self.c_4.isChecked(),
               'n':self.c_n.isChecked(), 'abs':self.c_abs.isChecked(), 'waf':self.c_waf.isChecked(), 
               'sni':self.c_sni.isChecked()}
        
        self.tb.setSortingEnabled(False) 
        self.tb.setRowCount(0) 
        
        old_rp = os.path.join(self.proj, "results.csv")
        if os.path.exists(old_rp):
            history_name = f"results_history_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            try: os.rename(old_rp, os.path.join(self.proj, history_name))
            except: pass

        # 核心修改点：加上 self.proj，把工程目录传进底层引擎
        self.cth = CollTask(il, dl, pol, self.spin_threads.value(), self.proj)
        self.cth.log_sig.connect(self.log)
        self.cth.res_sig.connect(self.add_res_ui)
        self.cth.summary_sig.connect(self.show_summary)
        self.cth.start()

    def stop_c(self):
        if hasattr(self, 'cth') and self.cth.isRunning():
            self.log("INFO", "⚠️ 正在发送强制截断指令...")
            self.btn_stop.setEnabled(False); self.btn_stop.setText("截断中...")
            self.cth.stop() 

    @Slot(dict, bool)
    def show_summary(self, stats, was_stopped):
        self.btn_c.setEnabled(True); self.btn_c.setText("启动对撞")
        self.btn_stop.setEnabled(False); self.btn_stop.setText("停止")
        self.tb.setSortingEnabled(True) # 恢复表格排序功能
        
        title = "🛑 扫描强制中止" if was_stopped else "🏁 扫描圆满完成"
        msg = f"总计构建：{stats['total']} 个变体\n🎯 命中并过滤出：{stats['success']} 个有效资产！\n\n💡 干扰数据已全部在底层被拦截遗弃。"
        self.log("INFO", f"[{title}] {msg.replace(chr(10), ' | ')}")
        QMessageBox.information(self, title, msg)

    def export_csv(self):
        if self.tb.rowCount() == 0: return QMessageBox.information(self, "提示", "当前没有扫到任何资产，无法导出！")
        path, _ = QFileDialog.getSaveFileName(self, "保存文件", f"战果导出_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv", "CSV 电子表格 (*.csv)")
        if path:
            try:
                with open(path, 'w', newline='', encoding='utf-8-sig') as f:
                    writer = csv.writer(f)
                    writer.writerow(["Target", "Host", "Code", "Len", "Title", "置信度", "智能诊断"])
                    for row in range(self.tb.rowCount()):
                        writer.writerow([self.tb.item(row, col).text() if self.tb.item(row, col) else "" for col in range(self.tb.columnCount())])
                self.log("SUCCESS", f"✅ 资产已成功导出: {path}")
            except Exception as e:
                self.log("ERROR", f"导出失败: {str(e)}")

    def force_save(self):
        if not self.proj: return
        p = os.path.join(self.proj, "results.csv")
        try:
            with open(p, 'w', newline='', encoding='utf-8-sig') as f:
                writer = csv.DictWriter(f, fieldnames=["url", "host", "code", "len", "title", "conf", "remark"])
                writer.writeheader()
                for row in range(self.tb.rowCount()):
                    d = {
                        "url": self.tb.item(row, 0).text() if self.tb.item(row, 0) else "",
                        "host": self.tb.item(row, 1).text() if self.tb.item(row, 1) else "",
                        "code": self.tb.item(row, 2).text() if self.tb.item(row, 2) else "",
                        "len": self.tb.item(row, 3).text() if self.tb.item(row, 3) else "",
                        "title": self.tb.item(row, 4).text() if self.tb.item(row, 4) else "",
                        "conf": self.tb.item(row, 5).text() if self.tb.item(row, 5) else "",
                        "remark": self.tb.item(row, 6).text() if self.tb.item(row, 6) else ""
                    }
                    if d["url"]:
                        writer.writerow(d)
            self.log("SUCCESS", "✅ 战果已强制覆盖保存！并已转换为标准 CSV 格式。")
            QMessageBox.information(self, "成功", "当前表格数据已完美保存为 CSV，可以直接用 Excel 爽看了！")
        except Exception as e:
            self.log("ERROR", f"保存失败: {str(e)}")

    def add_res_ui(self, d, save=True):
        r = self.tb.rowCount()
        self.tb.insertRow(r)
        keys = ["url", "host", "code", "len", "title", "conf", "remark"]
        
        for i, k in enumerate(keys):
            # 将数字强制转为 int 存入，这样点击表头排序时才能按大小正确排序 (比如对长度排)
            val = d.get(k, "")
            if k in ["code", "len"]:
                it = QTableWidgetItem()
                it.setData(Qt.EditRole, int(val) if val != "" else 0)
            else:
                it = QTableWidgetItem(str(val))
            
            conf = d.get("conf", "")
            if "✅" in conf:
                it.setBackground(QColor(35, 134, 54, 40)) 
                it.setForeground(QColor(88, 166, 255)) 
            elif "⚠️" in conf:
                it.setForeground(QColor(210, 153, 34)) 
            else:
                it.setForeground(QColor(139, 148, 158)) 
                
            self.tb.setItem(r, i, it)
            
        # 在 add_res_ui 函数的末尾
        if save and self.proj:
            p = os.path.join(self.proj, "results.csv")
            file_exists = os.path.exists(p)
            try: 
                # utf-8-sig 确保 Excel 优先识别无乱码
                with open(p, 'a', newline='', encoding='utf-8-sig') as f:
                    writer = csv.DictWriter(f, fieldnames=["url", "host", "code", "len", "title", "conf", "remark"])
                    if not file_exists:
                        writer.writeheader() # 如果文件不存在，先写表头
                    writer.writerow(d)
            except: pass

# ================= 3.7 IP 反查域名引擎 =================
class ReverseIPTask(QThread):
    res_sig = Signal(str, str) # ip, domain
    fin_sig = Signal()

    def __init__(self, ips):
        super().__init__()
        self.ips = ips
        self._stop = False

    async def fetch_domains(self, session, ip):
        if self._stop: return
        domains = set()

        ip = raw_ip.split(':')[0]
        # 核心过滤机制：专门屏蔽运营商和云厂商的垃圾动态 PTR 记录
        def is_valid_domain(d):
            d = d.strip().lower()
            if not d or "." not in d: return False
            if re.match(RE_IP, d): return False # 过滤纯 IP
            # 过滤掉域名中包含原始 IP 的记录 (比如 1.1.1.1.adsl.com)
            ip_dash = ip.replace('.', '-')
            if ip in d or ip_dash in d: return False
            # 过滤常见的无价值云主机/宽带动态域名
            junk_keywords = ['in-addr.arpa', 'adsl', 'pool', 'compute.amazonaws', 'dynamic', 'broadband', 'static', 'qcloud', 'aliyun']
            if any(k in d for k in junk_keywords): return False
            return True

        # ================= 战术 1：原生 PTR 反查 =================
        try:
            loop = asyncio.get_running_loop()
            host, _, _ = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
            if host and is_valid_domain(host): domains.add(host)
        except Exception: pass

        # ================= 战术 2：AlienVault OTX =================
        try:
            url_otx = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/passive_dns"
            async with session.get(url_otx, timeout=6, ssl=False) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for entry in data.get('passive_dns', []):
                        d = entry.get('hostname', '')
                        if is_valid_domain(d): domains.add(d)
        except Exception: pass

        # ================= 战术 3：HackerTarget =================
        try:
            url_ht = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
            async with session.get(url_ht, timeout=6, ssl=False) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    if "API count exceeded" not in text and "No DNS A records" not in text:
                        for d in text.strip().split('\n'):
                            if is_valid_domain(d): domains.add(d)
        except Exception: pass

        if domains:
            for d in domains: self.res_sig.emit(ip, d)
        else:
            self.res_sig.emit(ip, "🔍 暂无公开解析记录")

    def run(self):
        if sys.platform == 'win32': asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
        loop = asyncio.new_event_loop(); asyncio.set_event_loop(loop)
        
        async def run_all():
            # 并发不要开太高，防止被各大情报 API 封禁出口 IP
            conn = aiohttp.TCPConnector(limit=5, ssl=False) 
            async with aiohttp.ClientSession(connector=conn) as session:
                tasks = [asyncio.create_task(self.fetch_domains(session, ip)) for ip in self.ips]
                while tasks:
                    if self._stop:
                        for t in tasks: t.cancel()
                        break
                    done, pending = await asyncio.wait(tasks, timeout=0.5)
                    tasks = list(pending)

        try: loop.run_until_complete(run_all())
        except: pass
        finally:
            try: loop.run_until_complete(loop.shutdown_asyncgens()); loop.close()
            except: pass
        self.fin_sig.emit()

class ReverseIPDialog(QDialog):
    def __init__(self, parent=None, dom_pool_widget=None, ips=None, proj_dir=None):
        super().__init__(parent)
        self.setWindowTitle("🌐 IP 反查域名引擎 (扩大碰撞面)")
        self.resize(800, 500)
        self.dom_pool_widget = dom_pool_widget
        self.ips = ips or []
        self.proj_dir = proj_dir # 接收工程目录
        self.setStyleSheet("""
            QDialog { background-color: #0d1117; color: #c9d1d9; font-family: 'Microsoft YaHei'; }
            QTableWidget { background-color: #161b22; border: 1px solid #30363d; gridline-color: #30363d;}
            QHeaderView::section { background-color: #21262d; border: 1px solid #30363d; font-weight:bold; }
            QPushButton { background-color: #8957e5; color: white; font-weight: bold; padding: 6px; border-radius: 3px; }
            QPushButton:hover { background-color: #9e6cf2; }
            QTextEdit { background-color: #161b22; border: 1px solid #30363d; color: #c9d1d9; }
        """)
        self.init_ui()
        self.load_state() # 启动时读取记忆

    def init_ui(self):
        ml = QVBoxLayout(self)
        sp = QSplitter(Qt.Horizontal)
        
        left_w = QWidget(); ll = QVBoxLayout(left_w); ll.setContentsMargins(0,0,0,0)
        ll.addWidget(QLabel("待反查的 IP (已自动从主战池同步):"))
        self.input_ips = QTextEdit()
        # 只有在没有历史记忆的情况下，才使用传入的默认 ips
        if not self.input_ips.toPlainText():
            self.input_ips.setPlainText("\n".join(self.ips))
        self.input_ips.textChanged.connect(self.save_state)
        ll.addWidget(self.input_ips)
        
        self.btn_run = QPushButton("⚡ 开始反查旁站域名")
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
        
        self.btn_ext = QPushButton("📥 将新域名追加到主战域名池")
        self.btn_ext.setStyleSheet("background-color: #238636;")
        self.btn_ext.clicked.connect(self.extract_domains)
        rl.addWidget(self.btn_ext)
        sp.addWidget(right_w)
        
        ml.addWidget(sp)

    # ========== 状态保存与读取 (连带表格一起保存) ==========
    def save_state(self):
        if not self.proj_dir: return
        results = []
        for r in range(self.tb.rowCount()):
            results.append({"ip": self.tb.item(r, 0).text(), "dom": self.tb.item(r, 1).text()})
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
        self.btn_run.setEnabled(True); self.btn_run.setText("⚡ 开始反查旁站域名")
        self.save_state() # 跑完自动保存战果
        QMessageBox.information(self, "完成", "IP 反查完成！")

    def extract_domains(self):
        if not self.dom_pool_widget: return
        extracted = set()
        for r in range(self.tb.rowCount()):
            dom = self.tb.item(r, 1).text()
            # 顺手干掉占位符脏数据
            if dom and "暂无" not in dom and "🔍" not in dom:
                extracted.add(dom)
                
        if not extracted: return QMessageBox.warning(self, "提示", "没有有效的新域名可供提取！")
        
        # 核心修复：无视光标，整体重新渲染
        current_text = self.dom_pool_widget.toPlainText()
        existing_lines = [line.strip() for line in current_text.split('\n') if line.strip()]
        new_doms = [x for x in extracted if x not in set(existing_lines)]
        
        if new_doms:
            final_lines = existing_lines + new_doms
            self.dom_pool_widget.setPlainText("\n".join(final_lines) + "\n")
            QMessageBox.information(self, "成功", f"扩大攻击面成功！追加了 {len(new_doms)} 个新域名。")
        else:
            QMessageBox.information(self, "提示", "反查出的有效域名已全部在主界面池子中。")

    def closeEvent(self, event):
        if hasattr(self, 'work_thread') and self.work_thread.isRunning():
            self.work_thread._stop = True
            self.work_thread.wait(1500)
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv); win = AssetCommander(); win.show(); sys.exit(app.exec())