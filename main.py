import sys, os, re, asyncio, aiohttp, subprocess, json, socket, ipaddress, traceback, csv
from datetime import datetime
from PySide6.QtCore import Qt, QThread, Signal, Slot, QTimer
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                               QHBoxLayout, QTextEdit, QLineEdit, QPushButton, 
                               QLabel, QTableWidget, QTableWidgetItem, QSplitter,
                               QHeaderView, QGroupBox, QCheckBox, QFileDialog, 
                               QInputDialog, QMessageBox, QSpinBox, QDialog, 
                               QGridLayout,QProgressBar) # <--- 加上这个
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
# ================= 🚀 核心系统级修复：压制 Windows Proactor 10054 崩溃 =================
if sys.platform == 'win32':
    import asyncio.proactor_events
    _orig_call_conn_lost = asyncio.proactor_events._ProactorBasePipeTransport._call_connection_lost

    def _silence_10054(self, exc):
        try:
            _orig_call_conn_lost(self, exc)
        except ConnectionResetError:
            pass # 发生连接重置时静默吞掉，保护事件循环不崩溃

    asyncio.proactor_events._ProactorBasePipeTransport._call_connection_lost = _silence_10054
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
    # 🛡️ 性能进化 2：定义进度更新信号 (当前已完成, 总任务数)
    progress_sig = Signal(int, int) # <---- 加上这行
    def __init__(self, ips, domains, policies, concurrency, proj_dir=None):
        super().__init__()
        self.ips, self.domains, self.policies = ips, domains, policies
        self.concurrency = concurrency
        self.proj_dir = proj_dir
        self.stats = {"total": 0, "success": 0, "fail": 0}
        self._stop_flag = False
        self.domain_cache = {}
        self.dns_cache = {} 
        self._dns_locks = {}  # 🎯 新增：防止 DNS 缓存击穿的并发锁
        self._dom_locks = {}  # 🎯 新增：防止 HTTP 基线探测缓存击穿的并发锁
        self.garbage_titles = ['400', '401', '403', '404', '500', '502', '503', 'error', 'not found', 'forbidden', 'nginx', 'iis', 'apache', 'waf', 'block', '拦截', '找不到', '错误', 'tomcat']
        self._load_dns_cache()
        self.dns_executor = concurrent.futures.ThreadPoolExecutor(max_workers=concurrency + 50)

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
        clean_host = host.split(':')[0] 
        if clean_host in self.dns_cache: return self.dns_cache[clean_host]
        
        # 🎯 防止并发雪崩：同属一个域名的解析请求，只让第一个 Worker 去干活，其他的等待
        if clean_host not in self._dns_locks:
            self._dns_locks[clean_host] = asyncio.Lock()
            
        async with self._dns_locks[clean_host]:
            # 拿到锁后再次确认是否已被其他 Worker 缓存
            if clean_host in self.dns_cache: return self.dns_cache[clean_host]
            
            # 🎯 预判：如果是纯 IP，直接跳过底层 Socket 解析，防止系统卡顿
            if re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', clean_host):
                self.dns_cache[clean_host] = [clean_host]
                return [clean_host]
                
            loop = asyncio.get_running_loop()
            try:
                _, _, ips = await loop.run_in_executor(None, socket.gethostbyname_ex, clean_host)
                self.dns_cache[clean_host] = ips
            except Exception:
                self.dns_cache[clean_host] = [] # 查不到就是空列表
                
            return self.dns_cache[clean_host]

        loop = asyncio.get_running_loop()
        try:
            # 将 None 替换为 self.dns_executor
            _, _, ips = await loop.run_in_executor(self.dns_executor, socket.gethostbyname_ex, clean_host)
            self.dns_cache[clean_host] = ips
        except Exception:
            self.dns_cache[clean_host] = []
        
        return self.dns_cache[clean_host]

    def evaluate_hit(self, bc, bl, bt, hc, hl, ht, dc, dl, dt, dns_resolved, target_ip=None, resolved_ips=None):
        if resolved_ips is None: resolved_ips = []
        
        # 🌟 核心拦截：如果目标 IP 本来就在域名的真实解析记录里，说明是【正常的同站业务访问】
        # 🌟 修复：同源资产不再静默丢弃，而是标记为低危正常映射
        if target_ip and target_ip in resolved_ips:
            return "ℹ️ 低危", "公开的正常解析映射"

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
                # 🎯 防止并发雪崩：150 个 Worker 等待同一个直连基线
                if cache_key not in self._dom_locks:
                    self._dom_locks[cache_key] = asyncio.Lock()
                    
                async with self._dom_locks[cache_key]:
                    if cache_key not in self.domain_cache:
                        if not dns_resolved:
                            # DNS 都没记录，HTTP 根本不用发，必死
                            self.domain_cache[cache_key] = (0, 0, "DEAD_DOMAIN")
                        else:
                            try:
                                async with session.get(cache_key, timeout=5, ssl=False, allow_redirects=False) as rd:
                                    d_text = await rd.text(); self.domain_cache[cache_key] = (rd.status, len(d_text), extract_title(d_text))
                            except Exception:
                                self.domain_cache[cache_key] = (0, 0, "HTTP_FAILED")
                                
            dc, dl, dt = self.domain_cache[cache_key]

            # 4. Host 碰撞注射
            # 4. Host 碰撞注射
            headers = {"Host": host}
            if self.policies.get('waf', False):
                headers.update({"X-Forwarded-For":"127.0.0.1", "X-Real-IP":"127.0.0.1", "X-Forwarded-Host":host})
            
            req_url = url
            proxy_url = None
            
            # 🌟 核心修复 1：真正的绝对路径 (GET http://域名.com HTTP/1.1)
            # 通过把目标 IP 设置为 proxy，强制 aiohttp 发送绝对 URI，且不会触发本地 DNS 覆盖
            if self.policies.get('abs', False) and scheme == "http":
                req_url = f"http://{host}"
                proxy_url = url  # url 本身是 http://目标IP:端口，正好做为代理地址

            # 🌟 核心修复 2：处理强同步 SNI (防止 443 端口握手失败被静默抛弃)
            sni_host = host if self.policies.get('sni', False) and scheme == "https" else None

            # 发包：增加 proxy=proxy_url 和 server_hostname=sni_host
            async with session.get(req_url, headers=headers, proxy=proxy_url, server_hostname=sni_host, timeout=5, allow_redirects=False, ssl=False) as rh:
                h_text = await rh.text(); hc, hl, ht = rh.status, len(h_text), extract_title(h_text)
            
            # 🌟 修复：从 url (例如 http://120.7.x.x:80) 中提取出干净的 Target IP
            target_ip = url.split("://")[1].split(":")[0].split("/")[0]
            
            # 把 target_ip 和 resolved_ips 传给终极裁判
            confidence, remark = self.evaluate_hit(bc, bl, bt, hc, hl, ht, dc, dl, dt, dns_resolved, target_ip, resolved_ips)
            
            if confidence != "DROP":
                # [原本的逻辑: 存 CSV / 上 UI 表格代码依然在这里运行，保存在本地硬盘里]
                self.res_sig.emit({"url": url, "host": host, "code": hc, "len": hl, "title": ht, "conf": confidence, "remark": remark})
                self.stats["success"] += 1
                
                # 🛡️ 性能进化 4：日志彻底限流！
                # 只有危急资产才发送日志信号（彻底屏蔽低危）
                if "危" in confidence and "低危" not in confidence: 
                    self.log_sig.emit("SUCCESS", f"{confidence}! {url} -> Host:{host} [{remark}]")
                else: 
                    # else { 低危资产只存在 CSV 里，静默不发送日志信号，防止界面卡死 }
                    pass
        except asyncio.CancelledError: pass
        except Exception: self.stats["fail"] += 1

    def run(self):
            
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop._completed_tasks_for_ui = 0
        # 队列消费工作者
        async def worker(queue, session):
            # 获取任务总数用于信号抛出
            total_tasks = self.stats["total"]
            while not self._stop_flag:
                try:
                    task_data = await asyncio.wait_for(queue.get(), timeout=0.5)
                    if task_data is None: 
                        queue.task_done()
                        break
                    url, host = task_data
                    await self.fetch(session, url, host)
                    queue.task_done()
                    loop._completed_tasks_for_ui += 1
                    # 每完成 50 个任务或者变体很少时抛出一次进度信号，防止信号本身淹没 UI 线程
                    if loop._completed_tasks_for_ui % 50 == 0 or total_tasks < 1000:
                        self.progress_sig.emit(loop._completed_tasks_for_ui, total_tasks)
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
                    
                    if not v:
                        v.update([f"http://{pure}:80", f"https://{pure}:443", f"http://{pure}", f"https://{pure}"])

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
                        # 🌟 核心修复：绝对不能直接 break！必须让已取消的 Worker 走完清理流程
                        # 否则 aiohttp 的 session 关闭机制会在这里永久死锁
                        await asyncio.gather(*workers, return_exceptions=True)
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
            # 🛡️ 安全获取 Item 对象，防止 NoneType 崩溃
            i_dom = self.tb.item(r, 0)
            i_ip = self.tb.item(r, 1)
            i_cname = self.tb.item(r, 2)
            i_status = self.tb.item(r, 3)
            
            # 使用三元表达式：如果有数据就拿 text()，如果没有就给个空字符串
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
        
        # 🌟 核心修复：准备收集绑定关系
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
            
            # 建立映射关系
            clean_dom = dom.split(':')[0]
            clean_ip = ip.split(':')[0]
            if clean_dom not in bindings_to_save: bindings_to_save[clean_dom] = []
            if clean_ip not in bindings_to_save[clean_dom]: bindings_to_save[clean_dom].append(clean_ip)
            
        if not extracted: return QMessageBox.warning(self, "提示", "没有符合条件的有效 IP 可提取！")
        
        # 🌟 核心修复：将收集到的映射关系静默注入底层 DNS 缓存档案
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

        # 刷新主界面 UI
        current_text = self.ip_pool_widget.toPlainText()
        existing_lines = [line.strip() for line in current_text.split('\n') if line.strip()]
        new_ips = [x for x in extracted if x not in set(existing_lines)]
        
        if new_ips:
            final_lines = existing_lines + new_ips
            self.ip_pool_widget.setPlainText("\n".join(final_lines) + "\n")
            QMessageBox.information(self, "成功", f"提取了 {len(new_ips)} 个IP，并已自动在底层建立域名绑定关系！")
        else:
            QMessageBox.information(self, "提示", "提取的 IP 已全在主界面中 (绑定关系已刷新)。")


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
            
        # 🎯 核心修复：定义并发量！C段测绘量大，直接飙到 300 并发
        self.concurrency = 300 
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
        loop = asyncio.new_event_loop(); asyncio.set_event_loop(loop)
        
        async def run_all():
            # 🌟 增加 enable_cleanup_closed，强制回收僵尸连接
            connector = aiohttp.TCPConnector(limit=self.concurrency, ssl=False, force_close=True, enable_cleanup_closed=True)
            # 设置整个 Session 的硬超时，防止网络层假死
            timeout = aiohttp.ClientTimeout(total=8, connect=3)
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                sem = asyncio.Semaphore(self.concurrency) 
                
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
                        # 让被取消的任务完成异常抛出和资源释放
                        await asyncio.gather(*tasks, return_exceptions=True)
                        break
                    done, pending = await asyncio.wait(tasks, timeout=0.5)
                    tasks = list(pending)

        try: 
            loop.run_until_complete(run_all())
        except Exception as e: 
            # 🎯 修复：千万别用 pass 吞掉错误了，打印出来方便以后排查
            import traceback
            traceback.print_exc()
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
        
# 🎯 新增：独立的并发控制框
        hl_threads = QHBoxLayout()
        hl_threads.addWidget(QLabel("\n4. 线程并发数:"))
        self.spin_threads = QSpinBox()
        self.spin_threads.setRange(10, 3000)
        self.spin_threads.setValue(200) # 默认给个 200
        self.spin_threads.setStyleSheet("background-color: #161b22; color: #c9d1d9; padding: 4px;")
        self.spin_threads.valueChanged.connect(self.save_state) # 实时保存
        hl_threads.addWidget(self.spin_threads)
        ll.addLayout(hl_threads)

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

    def save_state(self):
        if self.proj_dir:
            try:
                json.dump({
                    "ips": self.input_ips.toPlainText(), 
                    "kws": self.input_kws.text(), 
                    "ports": self.input_ports.text(),
                    "threads": self.spin_threads.value() # 🎯 保存并发值
                }, open(os.path.join(self.proj_dir, "fission.json"), 'w'))
            except: pass

    def load_state(self):
        if self.proj_dir and os.path.exists(os.path.join(self.proj_dir, "fission.json")):
            try:
                self.input_ips.blockSignals(True)
                self.input_kws.blockSignals(True)
                self.input_ports.blockSignals(True)
                self.spin_threads.blockSignals(True) # 🎯 屏蔽信号
                
                s = json.load(open(os.path.join(self.proj_dir, "fission.json")))
                self.input_ips.setPlainText(s.get("ips", ""))
                self.input_kws.setText(s.get("kws", ""))
                self.input_ports.setText(s.get("ports", "80, 443, 8080, 8443, 8888, 7001"))
                self.spin_threads.setValue(s.get("threads", 200)) # 🎯 读取并发值
                
                self.input_ips.blockSignals(False)
                self.input_kws.blockSignals(False)
                self.input_ports.blockSignals(False)
                self.spin_threads.blockSignals(False) # 🎯 恢复信号
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
        
        # 🎯 直接读取本地并发框的值！
        local_concurrency = self.spin_threads.value()

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
        self.csv_buffer = []
        self.csv_timer = QTimer(self)
        self.csv_timer.timeout.connect(self.flush_csv_buffer)
        self.csv_timer.start(2000) # 每 2 秒批量落盘一次
    def select_dict(self):
        path, _ = QFileDialog.getOpenFileName(self, "选择无差别碰撞字典", "", "Text Files (*.txt);;All Files (*)")
        if path:
            self.dict_path = path
            try:
                # 稍微估算下文件大小/行数给老哥看
                size_mb = os.path.getsize(path) / (1024 * 1024)
                self.lbl_dict_info.setText(f"已挂载: {os.path.basename(path)} ({size_mb:.2f} MB)")
                self.cb_enable_dict.setChecked(True)
                self.sv_sett()
            except Exception as e:
                QMessageBox.warning(self, "错误", f"读取字典失败: {e}")

    def inject_internal_hosts(self):
        # 涵盖了更全面的实战 Bypass 字典、云环境元数据、容器环境以及特殊编码绕过
        internal_hosts = [
            # 1. 经典本地回环 (包含各类变形用于绕过 WAF 的正则匹配)
            "127.0.0.1", "localhost", "127.1", "127.0.1", "0.0.0.0", 
            "::1", "[::1]", "0x7f000001", "2130706433", "0177.0.0.1",
            
            # 2. 常见局域网默认网关、B 段/C 段常用管理端 IP
            "10.0.0.1", "10.0.0.254", "10.1.1.1", "10.10.10.1",
            "192.168.0.1", "192.168.1.1", "192.168.1.254", "192.168.3.1", "192.168.10.1",
            "172.16.0.1", "172.16.0.254", "172.17.0.1", # Docker 默认网桥
            
            # 3. ☁️ 云安全实战必杀：云服务商 Metadata 元数据获取接口 (AWS, 阿里云, 腾讯云等)
            "169.254.169.254", # AWS/Tencent/大多数云通用
            "100.100.100.200", # 阿里云专属元数据接口
            
            # 4. 🐳 容器与微服务内部环境 (K8s / Docker)
            "kubernetes.default", "kubernetes.default.svc", 
            "docker.for.mac.localhost", "host.docker.internal",
            
            # 5. 特殊内网主机名
            "localdomain", "broadcasthost", "internal"
        ]
        
        # 获取当前域名池，注入并自动去重
        current_doms = [x.strip() for x in self.d_pl.toPlainText().split('\n') if x.strip()]
        all_doms = current_doms + internal_hosts
        unique_doms = list(dict.fromkeys(all_doms))
        
        self.d_pl.setPlainText("\n".join(unique_doms) + "\n")
        self.log("SUCCESS", f"🏠 成功注入 {len(internal_hosts)} 个高价值内网/云原生 Host！准备测试高级路由欺骗。")

    def inject_internal_ips(self):
        # 适用于左侧 IP 池：精简版核心内网节点（主要用于已接入 VPN 或代理时的内网横向测绘）
        internal_ips = [
            # 常见网关与核心路由（极高概率绑定内部管理面板后台）
            "10.0.0.1", "10.0.0.254", "10.1.1.1", "10.10.10.1",
            "192.168.0.1", "192.168.1.1", "192.168.1.254", "192.168.3.1", "192.168.10.1", "192.168.100.1",
            "172.16.0.1", "172.16.0.254", 
            "172.17.0.1", # Docker 默认宿主机网桥
            
            # 云原生与运营商底层节点
            "169.254.169.254", # 云服务器元数据
            "100.64.0.1",      # 运营商/云厂商 CGNAT 核心网关
            
            # 本地回环 (主要用于配合 Socks 代理打本地服务，或测试本地环境)
            "127.0.0.1", "0.0.0.0"
        ]
        
        # 获取当前 IP 池，注入并自动去重
        current_ips = [x.strip() for x in self.i_pl.toPlainText().split('\n') if x.strip()]
        all_ips = current_ips + internal_ips
        unique_ips = list(dict.fromkeys(all_ips))
        
        self.i_pl.setPlainText("\n".join(unique_ips) + "\n")
        self.log("SUCCESS", f"🏠 成功注入 {len(internal_ips)} 个高价值内网 IP（网关/元数据/回环）！")

    def deduplicate_pools(self):
        # 遍历 IP池 和 域名池，进行一键去重
        for pl in [self.i_pl, self.d_pl]:
            lines = [line.strip() for line in pl.toPlainText().split('\n') if line.strip()]
            # 用 dict.fromkeys 去重，不仅速度极快，还能保持原有顺序
            unique_lines = list(dict.fromkeys(lines))
            pl.setPlainText("\n".join(unique_lines) + ("\n" if unique_lines else ""))
        self.log("SUCCESS", "🧹 资产清理完毕！IP池与域名池已完成一键去重。")

    def open_custom_bind(self):
        if not self.proj: return QMessageBox.warning(self, "提示", "请先选择或新建一个工程！")
        dlg = CustomBindDialog(self, self.proj)
        if dlg.exec() == QDialog.Accepted:
            # 获取现有数据
            cur_ips = [x.strip() for x in self.i_pl.toPlainText().split('\n') if x.strip()]
            cur_doms = [x.strip() for x in self.d_pl.toPlainText().split('\n') if x.strip()]
            
            # 追加新数据
            all_ips = cur_ips + dlg.ips
            all_doms = cur_doms + dlg.domains
            
            # 自动去重并更新回 UI
            self.i_pl.setPlainText("\n".join(list(dict.fromkeys(all_ips))) + "\n")
            self.d_pl.setPlainText("\n".join(list(dict.fromkeys(all_doms))) + "\n")
            self.log("SUCCESS", f"🔗 自定义绑定成功！已注入并去重 {len(dlg.ips)} 个 IP 和 {len(dlg.domains)} 个域名。")
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

        # --- 顶部：工程管理与导出 ---
        pl = QHBoxLayout(); self.lbl_p = QLabel("当前工程: [未载入]"); self.lbl_p.setStyleSheet("color:#e3b341; font-size:14px;")
        bn = QPushButton("📁 新建工程"); bn.clicked.connect(self.new_p); bo = QPushButton("📂 打开工程"); bo.clicked.connect(self.open_p)
        
        pl.addWidget(self.lbl_p); pl.addStretch(1);  pl.addWidget(bn); pl.addWidget(bo); ml.addLayout(pl)

        # --- 顶部：目标收割 ---
        tl = QHBoxLayout(); self.t_ed = QLineEdit(); self.t_ed.setPlaceholderText("Target Domain or IP Segment")
        bf = QPushButton("FScan 收割"); bf.clicked.connect(self.run_f); bo_ofa = QPushButton("OFA 收割"); bo_ofa.clicked.connect(self.run_o)
        tl.addWidget(QLabel("目标:")); tl.addWidget(self.t_ed); tl.addWidget(bf); tl.addWidget(bo_ofa); ml.addLayout(tl)
        self.t_ed.textChanged.connect(self.sv_sett)

        sp = QSplitter(Qt.Horizontal); lb = QWidget(); ll = QVBoxLayout(lb)
        self.i_pl = QTextEdit(); self.d_pl = QTextEdit()
        # 🌟 修复排版：关闭自动换行，超宽内容使用横向滚动条
        self.i_pl.setLineWrapMode(QTextEdit.NoWrap)
        self.d_pl.setLineWrapMode(QTextEdit.NoWrap)
        self.i_pl.textChanged.connect(lambda: self.sv_f("ips.txt", self.i_pl))
        self.d_pl.textChanged.connect(lambda: self.sv_f("domains.txt", self.d_pl))
        
        # ==========================================
        # 🔫 左侧武器库：IP 池 (物理寻址层) -> 网格布局
        # ==========================================
        i_header = QHBoxLayout()
        i_header.addWidget(QLabel("IP 池 (ips.txt) [TCP连接目标]:"))
        i_header.addStretch(1)
        ll.addLayout(i_header)

        i_tools = QGridLayout()
        i_tools.setContentsMargins(0, 0, 0, 5)
        i_tools.setSpacing(5)

        btn_fission = QPushButton("🕸️ C段裂变与提纯")
        btn_fission.setStyleSheet("background-color: #8957e5; padding: 5px; font-size: 12px; border-radius: 4px;")
        btn_fission.clicked.connect(self.open_ip_fission)

        btn_dedup = QPushButton("🧹 一键去重")
        btn_dedup.setStyleSheet("background-color: #d29922; padding: 5px; font-size: 12px; border-radius: 4px;")
        btn_dedup.clicked.connect(self.deduplicate_pools)

        btn_internal_ip = QPushButton("🏠 注入内网IP")
        btn_internal_ip.setStyleSheet("background-color: #2ea043; padding: 5px; font-size: 12px; border-radius: 4px;")
        btn_internal_ip.clicked.connect(self.inject_internal_ips)

        i_tools.addWidget(btn_fission, 0, 0)
        i_tools.addWidget(btn_dedup, 0, 1)
        i_tools.addWidget(btn_internal_ip, 1, 0, 1, 2)
        ll.addLayout(i_tools)
        ll.addWidget(self.i_pl)

        # ==========================================
        # 🔫 右侧武器库：域名/Host 池 -> 网格布局
        # ==========================================
        d_header = QHBoxLayout()
        d_header.addWidget(QLabel("域名池 (domains.txt) [伪造Host身份]:"))
        d_header.addStretch(1)
        ll.addLayout(d_header)

        d_tools = QGridLayout()
        d_tools.setContentsMargins(0, 0, 0, 5)
        d_tools.setSpacing(5)

        btn_hunter = QPushButton("🔍 真实IP猎手")
        btn_hunter.setStyleSheet("background-color: #238636; padding: 5px; font-size: 12px; border-radius: 4px;")
        btn_hunter.clicked.connect(self.open_ip_hunter)

        btn_reverse = QPushButton("🌐 IP反查域名")
        btn_reverse.setStyleSheet("background-color: #8957e5; padding: 5px; font-size: 12px; border-radius: 4px;")
        btn_reverse.clicked.connect(self.open_ip_reverse)

        btn_bind = QPushButton("🔗 强制绑定")
        btn_bind.setStyleSheet("background-color: #1f6feb; padding: 5px; font-size: 12px; border-radius: 4px;")
        btn_bind.clicked.connect(self.open_custom_bind)

        btn_internal_host = QPushButton("🏠 注入内网Host")
        btn_internal_host.setStyleSheet("background-color: #d29922; padding: 5px; font-size: 12px; border-radius: 4px;")
        btn_internal_host.clicked.connect(self.inject_internal_hosts)

        d_tools.addWidget(btn_hunter, 0, 0)
        d_tools.addWidget(btn_reverse, 0, 1)
        d_tools.addWidget(btn_bind, 1, 0)
        d_tools.addWidget(btn_internal_host, 1, 1)

        ll.addLayout(d_tools)
        ll.addWidget(self.d_pl)

        # --- 策略与高级绕过 ---
        pg = QGroupBox("碰撞策略与高级绕过"); pgl = QVBoxLayout(pg)
        hl1 = QHBoxLayout(); self.c_k = QCheckBox("保留原端口"); self.c_8 = QCheckBox("补齐:80"); self.c_4 = QCheckBox("补齐:443"); self.c_n = QCheckBox("无端口")
        for c in[self.c_k, self.c_8, self.c_4, self.c_n]: c.setChecked(True); c.stateChanged.connect(self.sv_sett); hl1.addWidget(c)
        hl2 = QHBoxLayout(); self.c_abs = QCheckBox("绝对路径"); self.c_waf = QCheckBox("注入 WAF 绕过头"); self.c_sni = QCheckBox("强同步 SNI")
        for c in[self.c_abs, self.c_waf, self.c_sni]: c.stateChanged.connect(self.sv_sett); hl2.addWidget(c)
        hl2.addStretch(1); pgl.addLayout(hl1); pgl.addLayout(hl2)
        # --- 无差别盲打外挂字典 UI (去臃肿精简版) ---
        self.dict_group = QGroupBox("🔥 外挂字典盲打") # 砍掉臃肿的后缀说明
        self.dict_group.setStyleSheet("QGroupBox { border: 1px solid #30363d; margin-top: 10px; font-weight: bold; color: #e3b341; }")
        dict_layout = QHBoxLayout(self.dict_group)

        self.cb_enable_dict = QCheckBox("启用字典")
        self.cb_enable_dict.stateChanged.connect(self.sv_sett)

        self.btn_sel_dict = QPushButton("📂 载入字典") # 名字改清爽
        self.btn_sel_dict.setStyleSheet("background-color: #d29922; color: white; padding: 4px; border-radius: 3px;")
        self.btn_sel_dict.clicked.connect(self.select_dict)

        self.lbl_dict_info = QLabel("未加载文件")
        self.lbl_dict_info.setStyleSheet("color: #8b949e;")

        dict_layout.addWidget(self.cb_enable_dict)
        dict_layout.addWidget(self.btn_sel_dict)
        dict_layout.addWidget(self.lbl_dict_info)
        dict_layout.addStretch(1)
        
        # 把这个框加到左侧主布局里
        ll.addWidget(self.dict_group)
        # --- 并发与底部控制 ---
        hl_ctrl = QHBoxLayout()
        hl_ctrl.addWidget(QLabel("并发:"))
        
        self.spin_threads = QSpinBox()

        # --- 并发与底部控制 (修复后) ---
        hl_ctrl = QHBoxLayout()
        
        # 1. 并发设置
        hl_ctrl.addWidget(QLabel("并发:"))
        self.spin_threads = QSpinBox()
        self.spin_threads.setRange(10, 3000)
        self.spin_threads.setValue(150)
        self.spin_threads.setStyleSheet("background-color: #161b22; color: #c9d1d9;")
        hl_ctrl.addWidget(self.spin_threads)

        # 2. 控制按钮组
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

        # 3. 进度条 (占满剩余空间)
        #   self.pg_bar = QProgressBar()
        #   self.pg_bar.setTextVisible(True)
        #   self.pg_bar.setFormat("%v / %m [%p%]")
        #self.pg_bar.setStyleSheet("""
        #       QProgressBar { border: 1px solid #30363d; background-color: #161b22; color: white; border-radius: 4px; text-align: center; font-weight: bold; }
        #    QProgressBar::chunk { background-color: #2ea043; border-radius: 3px; }
        #""")
        #hl_ctrl.addWidget(self.pg_bar, stretch=1)

        # 强制允许左侧面板被压缩得更小
        lb.setMinimumWidth(200)

        # 把策略和并发控制加进左侧布局
        ll.addWidget(pg)
        ll.addLayout(hl_ctrl)

        sp.addWidget(lb)

        # --- 右侧：表格区域 ---
        self.tb = QTableWidget(0, 7)
        self.tb.setHorizontalHeaderLabels(["Target", "Host", "Code", "Len", "Title", "置信度", "智能诊断"])
        self.tb.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.tb.horizontalHeader().setStretchLastSection(True)
        self.tb.setColumnWidth(0, 220)
        self.tb.setColumnWidth(1, 200)
        self.tb.setSortingEnabled(True)
        
        sp.addWidget(self.tb); sp.setStretchFactor(1, 2); ml.addWidget(sp)

        # ==========================================
        # --- 底部：全局任务进度条 & 战地审计日志 ---
        # ==========================================
        
        # 1. 创建横跨全屏的全局进度条
        self.pg_bar = QProgressBar()
        self.pg_bar.setTextVisible(True)
        self.pg_bar.setFormat("🔥 引擎火力全开：对撞进度 %v / %m [%p%]") # 加点霸气的提示文字
        self.pg_bar.setFixedHeight(22) # 设置固定高度，显得修长精致
        self.pg_bar.setStyleSheet("""
            QProgressBar { border: 1px solid #30363d; background-color: #0d1117; color: #58a6ff; border-radius: 4px; text-align: center; font-weight: bold; font-family: 'Microsoft YaHei'; }
            QProgressBar::chunk { background-color: #238636; border-radius: 3px; }
        """)
        ml.addWidget(self.pg_bar) # 🎯 关键：直接添加到最外层 ml 布局

        # 2. 战地实时审计日志
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
            
            self.c_sni.setChecked(s.get('sni',False))
            
            # --- 新增字典恢复逻辑 ---
            self.dict_path = s.get('dict_path', '')
            self.cb_enable_dict.setChecked(s.get('dict_enable', False))
            if self.dict_path and os.path.exists(self.dict_path):
                size_mb = os.path.getsize(self.dict_path) / (1024 * 1024)
                self.lbl_dict_info.setText(f"已记忆: {os.path.basename(self.dict_path)} ({size_mb:.2f} MB)")
            else:
                self.lbl_dict_info.setText("未加载文件")
                self.cb_enable_dict.setChecked(False)

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
                'target': self.t_ed.text(),
                'k':self.c_k.isChecked(), '80':self.c_8.isChecked(), '443':self.c_4.isChecked(),
                'n':self.c_n.isChecked(), 'abs':self.c_abs.isChecked(), 'waf':self.c_waf.isChecked(),
                'sni':self.c_sni.isChecked(),
                # --- 新增这两行 ---
                'dict_enable': self.cb_enable_dict.isChecked(),
                'dict_path': getattr(self, 'dict_path', '')
            }, open(os.path.join(self.proj, "settings.json"),'w'))

    @Slot(str, str)
    def log(self, lvl, m):
        self.log_buffer.append((lvl, m))

    def flush_log_buffer(self):
        if not hasattr(self, 'pending_file_log'):
            self.pending_file_log = ""

        # 1. UI 渲染照常进行
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

        # 2. 硬盘同步写入
        if self.proj and self.pending_file_log:
            try: 
                with open(os.path.join(self.proj, "runtime.log"), 'a', encoding='utf-8') as f:
                    f.write(self.pending_file_log)
                
                # 🛡️ 绝对防御：完全写进硬盘了，才清空暂存变量
                self.pending_file_log = "" 
            except Exception as e:
                # 写入失败，什么都不做，等下一个 200ms 重试
                pass

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
        # 加上这行防护
        if hasattr(self, 'th') and self.th.isRunning(): return self.log("ERROR", "外部工具仍在运行，请等待结束！")
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
        if hasattr(self, 'th') and self.th.isRunning(): return self.log("ERROR", "外部工具仍在运行，请等待结束！")
        
        cmd = self.config.get("oneforall_cmd", "").replace("{target}", self.t_ed.text().strip())
        self.th = ToolTask("OFA", cmd); self.th.log_sig.connect(self.log); self.th.ast_sig.connect(self.cln); self.th.start()

    def run_c(self):
        if not self.proj: return QMessageBox.warning(self, "!", "请先打开或新建一个工程")
        if hasattr(self, 'cth') and self.cth.isRunning(): return self.log("ERROR", "上一个对撞任务仍在进行中！")
        il, dl = self.i_pl.toPlainText().split(), self.d_pl.toPlainText().split()

        # ================== 核心合并逻辑 ==================
        if hasattr(self, 'cb_enable_dict') and self.cb_enable_dict.isChecked():
            if hasattr(self, 'dict_path') and os.path.exists(self.dict_path):
                try:
                    # 💡 提取目标输入框里的主域名
                    target_input = self.t_ed.text().strip()
                    clean_target = target_input.replace("http://", "").replace("https://", "").split(':')[0].split('/')[0]
                    # 判断目标是否是一个有效的域名（而不是IP或者空）
                    is_domain_target = bool(clean_target) and not re.match(RE_IP, clean_target)

                    self.log("INFO", "⏳ 正在将外挂字典加载入内存，并自动拼接子域名...")
                    with open(self.dict_path, 'r', encoding='utf-8', errors='ignore') as f:
                        dict_lines = []
                        for line in f:
                            word = line.strip()
                            if not word: continue
                            
                            # 🎯 如果目标是个域名，且字典里的词不包含该域名，则进行强行拼接
                            if is_domain_target and not word.endswith(clean_target):
                                word = word.strip('.') # 防止字典词尾自带点号
                                dict_lines.append(f"{word}.{clean_target}")
                            else:
                                dict_lines.append(word) # 如果目标是IP，或者字典已经是完整的完整域名，直接保留原样

                        dl.extend(dict_lines) # 将拼接好的子域名直接注入底层引擎的变体池
                    self.log("SUCCESS", f"📂 外挂字典挂载完毕！共生成并注入 {len(dict_lines)} 个子域名 Payload。")
                except Exception as e:
                    self.log("ERROR", f"外挂字典读取失败，已跳过盲打: {e}")
            else:
                self.log("ERROR", "外挂字典已勾选，但文件路径丢失或被移动，已忽略。")
        # ==================================================

        if not il or not dl: return self.log("ERROR", "IP池或域名池为空！")
        dl = list(dict.fromkeys(dl))
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

        # 🛡️ 性能进化 5：将底层的总体进度信号连接到界面上的进度条控件
        self.cth.progress_sig.connect(self.update_progress)
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
    @Slot(int, int)
    def update_progress(self, current, total):
        # 动态设置最大值，并更新当前进度
        if self.pg_bar.maximum() != total:
            self.pg_bar.setMaximum(total)
        self.pg_bar.setValue(current)
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
    @Slot()
    def flush_csv_buffer(self):
        # 防御性判断：确保 buffer 存在且有数据
        if not hasattr(self, 'csv_buffer') or not self.csv_buffer or not self.proj: 
            return
            
        p = os.path.join(self.proj, "results.csv")
        file_exists = os.path.exists(p)
        
        try: 
            with open(p, 'a', newline='', encoding='utf-8-sig') as f:
                # 加上 extrasaction='ignore'，防止脏数据导致字典写入崩溃
                writer = csv.DictWriter(f, fieldnames=["url", "host", "code", "len", "title", "conf", "remark"], extrasaction='ignore')
                if not file_exists:
                    writer.writeheader() 
                writer.writerows(self.csv_buffer)
                
            # 🛡️ 绝对防御：只有代码安全走到这里，代表数据一滴不剩全写进硬盘了，才能清空！
            self.csv_buffer.clear() 
            
        except Exception as e:
            # 遇到任何阻碍（不管是 Excel 锁死、系统 I/O 阻塞、还是其他玄学报错）
            # 绝不执行 clear()！让数据继续囤在内存里，2秒后自动重试。
            
            # 限流报错，防止日志框被刷屏
            if len(self.csv_buffer) % 50 == 0:
                self.log("ERROR", f"⚠️ 硬盘写入受阻！数据已转存内存缓冲池(积压 {len(self.csv_buffer)} 条)。原因: {str(e)}")
    def add_res_ui(self, d, save=True):
        # 1. 把数据先扔进内存缓冲池
        if save and self.proj:
            self.csv_buffer.append(d)

        # 2. UI 渲染过滤逻辑保持不变...
        conf = d.get("conf", "")
        if "低危" in conf:
            return
        # ==========================================
        # 🛡️ 核心修复 1：无论上不上 UI，先无脑落盘 CSV 保平安
        # 哪怕一会程序崩了，数据也已经在硬盘里了
        # ==========================================
        if save and self.proj:
            p = os.path.join(self.proj, "results.csv")
            file_exists = os.path.exists(p)
            try: 
                with open(p, 'a', newline='', encoding='utf-8-sig') as f:
                    writer = csv.DictWriter(f, fieldnames=["url", "host", "code", "len", "title", "conf", "remark"])
                    if not file_exists:
                        writer.writeheader() # 如果文件不存在，先写表头
                    writer.writerow(d)
            except: pass

        # ==========================================
        # 🛡️ 核心修复 2：UI 防爆机制 (丢弃垃圾数据渲染)
        # ==========================================
        conf = d.get("conf", "")
        r = self.tb.rowCount()
        
        # 如果是“低危”，且当前表格已经超过 2000 行了，直接跳过 UI 渲染！
        # （只存 CSV，不显示在界面上，防止 14万个单元格撑爆内存）
        if "低危" in conf:
            return
            
        QApplication.processEvents() # 防止快速插入时界面假死

        # 下面是原本正常的 UI 渲染逻辑
        self.tb.insertRow(r)
        keys = ["url", "host", "code", "len", "title", "conf", "remark"]
        
        for i, k in enumerate(keys):
            val = d.get(k, "")
            if k in ["code", "len"]:
                it = QTableWidgetItem()
                it.setData(Qt.EditRole, int(val) if val != "" else 0)
            else:
                it = QTableWidgetItem(str(val))
            
            if "✅" in conf or "🔥" in conf:
                it.setBackground(QColor(35, 134, 54, 40)) 
                it.setForeground(QColor(88, 166, 255)) 
            elif "⚠️" in conf:
                it.setForeground(QColor(210, 153, 34)) 
            else:
                it.setForeground(QColor(139, 148, 158)) # 低危灰色
                
            self.tb.setItem(r, i, it)

# ================= 3.7 IP 反查域名引擎 =================
class ReverseIPTask(QThread):
    res_sig = Signal(str, str) # ip, domain
    fin_sig = Signal()

    def __init__(self, ips):
        super().__init__()
        self.ips = ips
        self._stop = False
        self.ptr_executor = concurrent.futures.ThreadPoolExecutor(max_workers=100) # 新增

    async def fetch_domains(self, session, ip):
        if self._stop: return
        domains = set()

        # 🎯 修复：原先写的是未定义的 raw_ip，修正为参数传进来的 ip
        clean_ip = ip.split(':')[0]
        
        # 核心过滤机制：专门屏蔽运营商和云厂商的垃圾动态 PTR 记录
        def is_valid_domain(d):
            d = d.strip().lower()
            if not d or "." not in d: return False
            if re.match(RE_IP, d): return False # 过滤纯 IP
            
            # 🎯 修复：同步使用 clean_ip
            ip_dash = clean_ip.replace('.', '-')
            if clean_ip in d or ip_dash in d: return False
            
            junk_keywords = ['in-addr.arpa', 'adsl', 'pool', 'compute.amazonaws', 'dynamic', 'broadband', 'static', 'qcloud', 'aliyun']
            if any(k in d for k in junk_keywords): return False
            return True
            
        ip = clean_ip # 让后续代码继续使用干净的 IP 变量进行请求

        # ================= 战术 1：原生 PTR 反查 =================
        try:
            loop = asyncio.get_running_loop()
            # 将 None 替换为 self.ptr_executor
            host, _, _ = await loop.run_in_executor(self.ptr_executor, socket.gethostbyaddr, ip)
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
            # 🛡️ 同样的安全获取逻辑，这里只有 IP 和 域名两列
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
        self.btn_run.setEnabled(True); self.btn_run.setText("⚡ 开始反查旁站域名")
        self.save_state() # 跑完自动保存战果
        QMessageBox.information(self, "完成", "IP 反查完成！")

    def extract_domains(self):
        if not self.dom_pool_widget: return
        extracted = set()
        
        # 🌟 核心修复：准备收集绑定关系
        bindings_to_save = {}

        for r in range(self.tb.rowCount()):
            ip_item = self.tb.item(r, 0)
            dom_item = self.tb.item(r, 1)
            if not ip_item or not dom_item: continue
            
            ip = ip_item.text()
            dom = dom_item.text()
            
            if dom and "暂无" not in dom and "🔍" not in dom:
                extracted.add(dom)
                
                # 建立映射关系
                clean_dom = dom.split(':')[0]
                clean_ip = ip.split(':')[0]
                if clean_dom not in bindings_to_save: bindings_to_save[clean_dom] = []
                if clean_ip not in bindings_to_save[clean_dom]: bindings_to_save[clean_dom].append(clean_ip)
                
        if not extracted: return QMessageBox.warning(self, "提示", "没有有效的新域名可供提取！")
        
        # 🌟 核心修复：将收集到的映射关系静默注入底层 DNS 缓存档案
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

        # 刷新主界面 UI
        current_text = self.dom_pool_widget.toPlainText()
        existing_lines = [line.strip() for line in current_text.split('\n') if line.strip()]
        new_doms = [x for x in extracted if x not in set(existing_lines)]
        
        if new_doms:
            final_lines = existing_lines + new_doms
            self.dom_pool_widget.setPlainText("\n".join(final_lines) + "\n")
            QMessageBox.information(self, "成功", f"追加了 {len(new_doms)} 个新域名，并已自动在底层建立 IP 绑定关系！")
        else:
            QMessageBox.information(self, "提示", "反查出的域名已在池中 (绑定关系已刷新)。")

    def closeEvent(self, event):
        if hasattr(self, 'work_thread') and self.work_thread.isRunning():
            self.work_thread._stop = True
            self.work_thread.wait(1500)
        event.accept()
class CustomBindDialog(QDialog):
    def __init__(self, parent=None, proj_dir=None):
        super().__init__(parent)
        self.setWindowTitle("🔗 自定义 Host 绑定 (指定内网IP/过CDN)")
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
        h_layout = QHBoxLayout()
        
        # --- 修改点 1：左边换成域名输入 ---
        v1 = QVBoxLayout()
        v1.addWidget(QLabel("1. 对应的域名 (每行一个):"))
        self.domain_edit = QTextEdit()
        self.domain_edit.setPlaceholderText("例如: inner.target.com")
        v1.addWidget(self.domain_edit)
        h_layout.addLayout(v1)
        
        # --- 修改点 2：右边换成 IP 输入 ---
        v2 = QVBoxLayout()
        v2.addWidget(QLabel("2. 强制绑定的 IP (每行一个):"))
        self.ip_edit = QTextEdit()
        self.ip_edit.setPlaceholderText("例如: 192.168.1.100")
        v2.addWidget(self.ip_edit)
        h_layout.addLayout(v2)
        
        layout.addLayout(h_layout)
        
        self.btn_confirm = QPushButton("✅ 确定绑定并注入主面板")
        self.btn_confirm.clicked.connect(self.accept_data)
        layout.addWidget(self.btn_confirm)

    def accept_data(self):
        # 提取数据（注意变量和输入框的对应关系已修正）
        self.ips = [x.strip() for x in self.ip_edit.toPlainText().split('\n') if x.strip()]
        self.domains = [x.strip() for x in self.domain_edit.toPlainText().split('\n') if x.strip()]
        
        if not self.ips or not self.domains:
            QMessageBox.warning(self, "!", "IP 和 域名都不能为空！")
            return
            
        # --- 增加防御机制：防止老哥手快再次贴反 ---
        for ip in self.ips:
            # 如果右侧 IP 框里出现了明显的英文字母（且不是 IPv6 的 a-f），大概率是贴成了域名
            if re.search(r'[g-zG-Z]', ip): 
                QMessageBox.warning(self, "格式异常", f"在 IP 框中检测到异常字符：\n【{ip}】\n\n请确认右侧输入的是纯 IP！")
                return

        # 🌟 核心：将用户手动绑定的关系强制写入解析缓存！
        if self.proj_dir:
            p = os.path.join(self.proj_dir, "domain_to_ip.json")
            cache = {}
            if os.path.exists(p):
                try: cache = json.load(open(p, 'r', encoding='utf-8'))
                except: pass
            
            for d in self.domains:
                clean_d = d.split(':')[0]
                if clean_d not in cache: cache[clean_d] = []
                for ip in self.ips:
                    clean_ip = ip.split(':')[0]
                    if clean_ip not in cache[clean_d]:
                        cache[clean_d].append(clean_ip)
            try:
                json.dump(cache, open(p, 'w', encoding='utf-8'), indent=4)
            except: pass
            
        self.accept()
if __name__ == "__main__":
    # 在进程启动的最开始，全局设置一次即可
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    app = QApplication(sys.argv); win = AssetCommander(); win.show(); sys.exit(app.exec())