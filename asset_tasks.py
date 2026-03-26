import asyncio
import concurrent.futures
import os
import re
import socket
import subprocess
import traceback

import aiohttp
from PySide6.QtCore import QThread, Signal

from asset_common import RE_IP, extract_title, write_global_log


class ToolTask(QThread):
    log_sig = Signal(str, str)
    ast_sig = Signal(str)

    def __init__(self, name, cmd):
        super().__init__()
        self.name = name
        self.cmd = cmd

    def run(self):
        self.log_sig.emit("INFO", f"启动任务: {self.cmd}")
        try:
            tool_cwd = None
            for part in self.cmd.replace("\\", "/").split():
                if (part.endswith(".py") or part.endswith(".exe")) and (
                    ":" in part or part.startswith("/")
                ):
                    tool_cwd = os.path.dirname(part)
                    break

            env = os.environ.copy()
            env["PYTHONUNBUFFERED"] = "1"
            process = subprocess.Popen(
                self.cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                shell=True,
                env=env,
                cwd=tool_cwd if tool_cwd and os.path.exists(tool_cwd) else None,
            )

            while True:
                line_bytes = process.stdout.readline()
                if not line_bytes:
                    break
                try:
                    line = line_bytes.decode("utf-8").strip()
                except Exception:
                    line = line_bytes.decode("gbk", errors="ignore").strip()

                if line:
                    self.log_sig.emit("DEBUG", f"[{self.name}] {line}")
                    self.ast_sig.emit(line)

            process.wait()
            if process.returncode == 0:
                self.log_sig.emit("SUCCESS", f"{self.name} 执行结束")
            else:
                self.log_sig.emit(
                    "ERROR", f"{self.name} 异常退出，状态码: {process.returncode}"
                )
        except Exception as exc:
            self.log_sig.emit("ERROR", f"执行崩溃: {exc}")
            write_global_log(
                "FATAL",
                f"[{self.name}] 执行崩溃详情:\n{traceback.format_exc()}",
            )


class DnsResolverTask(QThread):
    res_sig = Signal(str, str, str, str)
    fin_sig = Signal()

    def __init__(self, domains):
        super().__init__()
        self.domains = domains
        self.waf_cdn_cname = [
            "cdn",
            "waf",
            "cloudflare",
            "kunlun",
            "aliyun",
            "yundun",
            "akamai",
            "fastly",
            "qcloud",
            "jiasu",
            "ccgslb",
            "edge",
            "incapsula",
        ]

    def resolve_single(self, dom):
        clean_dom = (
            dom.replace("http://", "")
            .replace("https://", "")
            .split(":")[0]
            .split("/")[0]
            .strip()
        )
        if not clean_dom:
            return

        try:
            hostname, aliases, ips = socket.gethostbyname_ex(clean_dom)
            cname = aliases[0] if aliases else ""
            check_str = (hostname + str(aliases)).lower()
            is_waf = any(keyword in check_str for keyword in self.waf_cdn_cname)
            status = "疑似真实源站" if not is_waf else "CDN/WAF 节点"

            for ip in set(ips):
                self.res_sig.emit(clean_dom, ip, cname, status)
        except Exception:
            self.res_sig.emit(clean_dom, "解析失败 (NXDOMAIN)", "-", "无效记录")

    def run(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = [
                executor.submit(self.resolve_single, domain)
                for domain in set(self.domains)
                if domain
            ]
            concurrent.futures.wait(futures)
        self.fin_sig.emit()


class FissionTask(QThread):
    res_sig = Signal(str, str, str, str)
    fin_sig = Signal()

    def __init__(self, ips, keywords, ports_str, concurrency=300):
        super().__init__()
        self.ips = ips
        self.keywords = [item.strip().lower() for item in keywords.split(",") if item.strip()]
        self.ports = [item.strip() for item in ports_str.split(",") if item.strip().isdigit()]
        if not self.ports:
            self.ports = ["80", "443"]
        self.concurrency = max(1, int(concurrency))
        self._stop = False

    async def fetch_title(self, session, url, sem):
        if self._stop:
            return
        try:
            async with sem:
                if self._stop:
                    return
                async with session.get(
                    url, timeout=8, ssl=False, allow_redirects=True
                ) as response:
                    text = await response.text(errors="ignore")
                    title = extract_title(text).strip()
                    if not title or title == "N/A":
                        return

                    title_lower = title.lower()
                    is_match = not self.keywords or any(
                        keyword in title_lower for keyword in self.keywords
                    )
                    if is_match:
                        self.res_sig.emit(url, title, "精准命中", "#3fb950")
                    else:
                        self.res_sig.emit(url, title, "旁站/无关资产", "#8b949e")
        except asyncio.CancelledError:
            pass
        except Exception:
            pass

    def run(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        async def run_all():
            connector = aiohttp.TCPConnector(
                limit=self.concurrency,
                ssl=False,
                force_close=True,
                enable_cleanup_closed=True,
            )
            timeout = aiohttp.ClientTimeout(total=8, connect=3)
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                sem = asyncio.Semaphore(self.concurrency)
                tasks = []
                for ip in self.ips:
                    if self._stop:
                        break
                    for port in self.ports:
                        if port in ["443", "8443", "4443"]:
                            tasks.append(
                                asyncio.create_task(
                                    self.fetch_title(session, f"https://{ip}:{port}", sem)
                                )
                            )
                        elif port in ["80", "8080", "8888", "81", "7001"]:
                            tasks.append(
                                asyncio.create_task(
                                    self.fetch_title(session, f"http://{ip}:{port}", sem)
                                )
                            )
                        else:
                            tasks.append(
                                asyncio.create_task(
                                    self.fetch_title(session, f"http://{ip}:{port}", sem)
                                )
                            )
                            tasks.append(
                                asyncio.create_task(
                                    self.fetch_title(session, f"https://{ip}:{port}", sem)
                                )
                            )

                while tasks:
                    if self._stop:
                        for task in tasks:
                            task.cancel()
                        await asyncio.gather(*tasks, return_exceptions=True)
                        break
                    _, pending = await asyncio.wait(tasks, timeout=0.5)
                    tasks = list(pending)

        try:
            loop.run_until_complete(run_all())
        except Exception:
            traceback.print_exc()
        finally:
            try:
                loop.run_until_complete(loop.shutdown_asyncgens())
                loop.close()
            except Exception:
                pass
        self.fin_sig.emit()


class ReverseIPTask(QThread):
    res_sig = Signal(str, str)
    fin_sig = Signal()

    def __init__(self, ips):
        super().__init__()
        self.ips = ips
        self._stop = False
        self.ptr_executor = concurrent.futures.ThreadPoolExecutor(max_workers=100)

    async def fetch_domains(self, session, ip):
        if self._stop:
            return

        domains = set()
        clean_ip = ip.split(":")[0].strip()
        if not clean_ip:
            return

        def is_valid_domain(domain):
            domain = domain.strip().lower()
            if not domain or "." not in domain:
                return False
            if re.match(RE_IP, domain):
                return False

            ip_dash = clean_ip.replace(".", "-")
            if clean_ip in domain or ip_dash in domain:
                return False

            junk_keywords = [
                "in-addr.arpa",
                "adsl",
                "pool",
                "compute.amazonaws",
                "dynamic",
                "broadband",
                "static",
                "qcloud",
                "aliyun",
            ]
            return not any(keyword in domain for keyword in junk_keywords)

        try:
            loop = asyncio.get_running_loop()
            host, _, _ = await loop.run_in_executor(
                self.ptr_executor, socket.gethostbyaddr, clean_ip
            )
            if host and is_valid_domain(host):
                domains.add(host)
        except Exception:
            pass

        try:
            url_otx = (
                f"https://otx.alienvault.com/api/v1/indicators/IPv4/{clean_ip}/passive_dns"
            )
            async with session.get(url_otx, timeout=6, ssl=False) as response:
                if response.status == 200:
                    data = await response.json()
                    for entry in data.get("passive_dns", []):
                        domain = entry.get("hostname", "")
                        if is_valid_domain(domain):
                            domains.add(domain)
        except Exception:
            pass

        try:
            url_ht = f"https://api.hackertarget.com/reverseiplookup/?q={clean_ip}"
            async with session.get(url_ht, timeout=6, ssl=False) as response:
                if response.status == 200:
                    text = await response.text()
                    if "API count exceeded" not in text and "No DNS A records" not in text:
                        for domain in text.strip().split("\n"):
                            if is_valid_domain(domain):
                                domains.add(domain)
        except Exception:
            pass

        if domains:
            for domain in domains:
                self.res_sig.emit(clean_ip, domain)
        else:
            self.res_sig.emit(clean_ip, "暂无公开解析记录")

    def run(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        async def run_all():
            connector = aiohttp.TCPConnector(limit=5, ssl=False)
            async with aiohttp.ClientSession(connector=connector) as session:
                tasks = [
                    asyncio.create_task(self.fetch_domains(session, ip))
                    for ip in self.ips
                ]
                while tasks:
                    if self._stop:
                        for task in tasks:
                            task.cancel()
                        break
                    _, pending = await asyncio.wait(tasks, timeout=0.5)
                    tasks = list(pending)

        try:
            loop.run_until_complete(run_all())
        except Exception:
            pass
        finally:
            try:
                loop.run_until_complete(loop.shutdown_asyncgens())
                loop.close()
            except Exception:
                pass
            self.ptr_executor.shutdown(wait=False, cancel_futures=True)

        self.fin_sig.emit()


__all__ = [
    "DnsResolverTask",
    "FissionTask",
    "ReverseIPTask",
    "ToolTask",
]
