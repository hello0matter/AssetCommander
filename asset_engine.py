import asyncio
import concurrent.futures
import json
import os
import re
import socket
import traceback
from collections import OrderedDict
from datetime import datetime

import aiohttp
from PySide6.QtCore import QThread, Signal
from asset_bindings import load_dns_cache, save_dns_cache

from asset_common import (
    FAIL_SAMPLE_FILE,
    HTTP_STATUS,
    collect_unique_ips,
    extract_title,
    normalize_host_value,
    normalize_ip_value,
    task_fingerprint,
    write_global_log,
)


MAX_DOMAIN_CACHE_SIZE = 12000
MAX_DNS_CACHE_SIZE = 8000
WINDOWS_MAX_CONCURRENCY = 128
WINDOWS_DICT_MAX_CONCURRENCY = 72
WINDOWS_HUGE_DICT_MAX_CONCURRENCY = 48
LARGE_DICT_SIZE_MB = 8
HUGE_DICT_SIZE_MB = 32
MAX_DNS_WORKERS = 48


class CollTask(QThread):
    log_sig = Signal(str, str)
    res_sig = Signal(dict)
    summary_sig = Signal(dict, bool)
    progress_sig = Signal(int, int)
    task_done_sig = Signal(str)

    def __init__(
        self,
        ips,
        domains,
        policies,
        concurrency,
        proj_dir,
        scanned_set,
        dict_config,
    ):
        super().__init__()
        self.dynamic_dict_enabled = bool(
            dict_config
            and dict_config.get("enabled")
            and os.path.exists(dict_config.get("path", ""))
        )
        self.dict_size_mb = 0.0
        if self.dynamic_dict_enabled:
            try:
                self.dict_size_mb = os.path.getsize(dict_config.get("path", "")) / (1024 * 1024)
            except Exception:
                self.dict_size_mb = 0.0
        self.original_concurrency = max(1, int(concurrency))
        self.ips = ips
        self.domains = domains
        self.policies = policies
        self.concurrency = self._compute_safe_concurrency(self.original_concurrency)
        self.proj_dir = proj_dir
        self.scanned_set = scanned_set
        self.dict_config = dict_config
        self.stats = {"total": 0, "success": 0, "fail": 0}
        self.fail_reason_counts = {}
        self.fail_samples = []
        self._stop_flag = False
        self.domain_cache = OrderedDict()
        self.dns_cache = OrderedDict()
        self._dns_locks = {}
        self._dom_locks = {}
        self.garbage_titles = [
            "400",
            "401",
            "403",
            "404",
            "500",
            "502",
            "503",
            "error",
            "not found",
            "forbidden",
            "nginx",
            "iis",
            "apache",
            "waf",
            "block",
            "拦截",
            "找不到",
            "错误",
            "tomcat",
        ]
        self._load_dns_cache()
        self.dns_executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=self._compute_dns_workers()
        )

    def stop(self):
        self._stop_flag = True

    def _compute_safe_concurrency(self, requested):
        safe = max(1, int(requested))
        if os.name == "nt":
            safe = min(safe, WINDOWS_MAX_CONCURRENCY)
            if self.dynamic_dict_enabled:
                if self.dict_size_mb >= HUGE_DICT_SIZE_MB:
                    safe = min(safe, WINDOWS_HUGE_DICT_MAX_CONCURRENCY)
                else:
                    safe = min(safe, WINDOWS_DICT_MAX_CONCURRENCY)
        return safe

    def _compute_dns_workers(self):
        dns_workers = min(MAX_DNS_WORKERS, max(8, self.concurrency // 2))
        if os.name == "nt":
            dns_workers = min(dns_workers, 32)
            if self.dynamic_dict_enabled and self.dict_size_mb >= LARGE_DICT_SIZE_MB:
                dns_workers = min(dns_workers, 24)
        return dns_workers

    def _create_event_loop(self):
        if os.name == "nt":
            try:
                policy = asyncio.WindowsProactorEventLoopPolicy()
                asyncio.set_event_loop_policy(policy)
                loop = policy.new_event_loop()
                asyncio.set_event_loop(loop)
                return loop
            except Exception as exc:
                write_global_log("ERROR", f"创建 Proactor 事件循环失败，回退默认事件循环: {exc}")

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        return loop

    def _set_dns_cache(self, key, value):
        self.dns_cache[key] = value
        self.dns_cache.move_to_end(key)
        while len(self.dns_cache) > MAX_DNS_CACHE_SIZE:
            self.dns_cache.popitem(last=False)

    def _set_domain_cache(self, key, value):
        self.domain_cache[key] = value
        self.domain_cache.move_to_end(key)
        while len(self.domain_cache) > MAX_DOMAIN_CACHE_SIZE:
            self.domain_cache.popitem(last=False)

    def _normalize_redirect(self, location):
        raw = str(location or "").strip()
        if not raw:
            return ""
        return raw.rstrip("/").lower()

    def _same_redirect(self, left, right):
        return self._normalize_redirect(left) == self._normalize_redirect(right)

    def generate_domains(self):
        for domain in self.domains:
            yield domain

        if not (
            self.dict_config
            and self.dict_config.get("enabled")
            and os.path.exists(self.dict_config.get("path", ""))
        ):
            return

        prefixes = [
            item.strip()
            for item in self.dict_config.get("prefixes", "").split("\n")
            if item.strip()
        ]
        if not prefixes:
            prefixes = [""]

        suffixes = [
            item.strip()
            for item in self.dict_config.get("suffixes", "").split("\n")
            if item.strip()
        ]

        with open(
            self.dict_config["path"], "r", encoding="utf-8", errors="ignore"
        ) as handle:
            for line in handle:
                word = line.strip()
                if not word:
                    continue
                for prefix in prefixes:
                    for suffix in suffixes:
                        domain = (
                            f"{prefix}{word}.{suffix}" if suffix else f"{prefix}{word}"
                        )
                        yield domain.strip(".")

    def _load_dns_cache(self):
        if not self.proj_dir:
            return
        try:
            self.dns_cache = OrderedDict()
            raw_cache = load_dns_cache(self.proj_dir)
            for key, value in raw_cache.items():
                clean_key = normalize_host_value(key).split(":")[0]
                clean_ips = collect_unique_ips(value)
                if clean_key and (clean_key not in self.dns_cache or not self.dns_cache[clean_key]):
                    self._set_dns_cache(clean_key, clean_ips)
        except Exception:
            pass

    def _save_dns_cache(self):
        if not self.proj_dir:
            return
        try:
            save_dns_cache(self.proj_dir, self.dns_cache)
        except Exception:
            pass

    async def resolve_dns(self, host):
        clean_host = host.split(":")[0]
        if clean_host in self.dns_cache:
            self.dns_cache.move_to_end(clean_host)
            return self.dns_cache[clean_host]

        dns_lock = self._dns_locks.get(clean_host)
        if dns_lock is None:
            dns_lock = asyncio.Lock()
            self._dns_locks[clean_host] = dns_lock

        try:
            async with dns_lock:
                if clean_host in self.dns_cache:
                    self.dns_cache.move_to_end(clean_host)
                    return self.dns_cache[clean_host]

                if re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", clean_host):
                    self._set_dns_cache(clean_host, [clean_host])
                    return [clean_host]

                loop = asyncio.get_running_loop()
                try:
                    _, _, ips = await loop.run_in_executor(
                        self.dns_executor,
                        socket.gethostbyname_ex,
                        clean_host,
                    )
                    self._set_dns_cache(clean_host, ips)
                except Exception:
                    self._set_dns_cache(clean_host, [])

                return self.dns_cache[clean_host]
        finally:
            self._dns_locks.pop(clean_host, None)

    def _record_failure(self, url, host, exc):
        reason = type(exc).__name__
        self.fail_reason_counts[reason] = self.fail_reason_counts.get(reason, 0) + 1

        if len(self.fail_samples) < 100:
            self.fail_samples.append(
                {
                    "url": url,
                    "host": host,
                    "reason": reason,
                    "message": str(exc)[:300],
                }
            )

    def _save_failure_samples(self):
        if not self.proj_dir:
            return

        path = os.path.join(self.proj_dir, FAIL_SAMPLE_FILE)
        try:
            lines = [
                f"generated_at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                f"total_failures: {self.stats.get('fail', 0)}",
                "",
                "[reason_counts]",
            ]

            for reason, count in sorted(
                self.fail_reason_counts.items(), key=lambda item: (-item[1], item[0])
            ):
                lines.append(f"{reason}: {count}")

            lines.extend(["", "[samples]"])
            for idx, item in enumerate(self.fail_samples, start=1):
                lines.append(
                    f"{idx}. {item['reason']} | {item['url']} | Host:{item['host']}"
                )
                if item["message"]:
                    lines.append(f"   {item['message']}")

            with open(path, "w", encoding="utf-8") as handle:
                handle.write("\n".join(lines).rstrip() + "\n")
        except Exception as exc:
            self.log_sig.emit("ERROR", f"失败样本写入失败: {exc}")

    async def fetch(self, session, url, host):
        if self._stop_flag:
            return
        try:
            scheme = url.split("://")[0]

            resolved_ips = await self.resolve_dns(host)
            dns_resolved = len(resolved_ips) > 0

            async with session.get(
                url, timeout=5, allow_redirects=False, ssl=False
            ) as response_base:
                base_text = await response_base.text()
                bc = response_base.status
                bl = len(base_text)
                bt = extract_title(base_text)
                br = response_base.headers.get("Location", "")

            cache_key = f"{scheme}://{host}"
            if cache_key not in self.domain_cache:
                dom_lock = self._dom_locks.get(cache_key)
                if dom_lock is None:
                    dom_lock = asyncio.Lock()
                    self._dom_locks[cache_key] = dom_lock

                try:
                    async with dom_lock:
                        if cache_key not in self.domain_cache:
                            if not dns_resolved:
                                self._set_domain_cache(cache_key, (0, 0, "DEAD_DOMAIN", ""))
                            else:
                                try:
                                    async with session.get(
                                        cache_key,
                                        timeout=5,
                                        ssl=False,
                                        allow_redirects=False,
                                    ) as response_domain:
                                        domain_text = await response_domain.text()
                                        self._set_domain_cache(
                                            cache_key,
                                            (
                                                response_domain.status,
                                                len(domain_text),
                                                extract_title(domain_text),
                                                response_domain.headers.get("Location", ""),
                                            ),
                                        )
                                except Exception:
                                    self._set_domain_cache(cache_key, (0, 0, "HTTP_FAILED", ""))
                            if cache_key in self.domain_cache:
                                self.domain_cache.move_to_end(cache_key)
                finally:
                    self._dom_locks.pop(cache_key, None)
            else:
                self.domain_cache.move_to_end(cache_key)

            dc, dl, dt, dr = self.domain_cache[cache_key]

            headers = {"Host": host}
            if self.policies.get("waf", False):
                headers.update(
                    {
                        "X-Forwarded-For": "127.0.0.1",
                        "X-Real-IP": "127.0.0.1",
                        "X-Forwarded-Host": host,
                    }
                )

            req_url = url
            proxy_url = None

            if self.policies.get("abs", False) and scheme == "http":
                req_url = f"http://{host}"
                proxy_url = url

            sni_host = (
                host if self.policies.get("sni", False) and scheme == "https" else None
            )

            async with session.get(
                req_url,
                headers=headers,
                proxy=proxy_url,
                server_hostname=sni_host,
                timeout=5,
                allow_redirects=False,
                ssl=False,
            ) as response_host:
                host_text = await response_host.text()
                hc = response_host.status
                hl = len(host_text)
                ht = extract_title(host_text)
                hr = response_host.headers.get("Location", "")

            target_ip = url.split("://")[1].split(":")[0].split("/")[0]
            confidence, remark = self.evaluate_hit(
                bc,
                bl,
                bt,
                br,
                hc,
                hl,
                ht,
                hr,
                dc,
                dl,
                dt,
                dr,
                dns_resolved,
                target_ip,
                resolved_ips,
            )

            if confidence != "DROP":
                self.res_sig.emit(
                    {
                        "url": url,
                        "host": host,
                        "code": hc,
                        "len": hl,
                        "title": ht,
                        "conf": confidence,
                        "remark": remark,
                    }
                )
                self.stats["success"] += 1

                if confidence in {"极危", "高危"}:
                    self.log_sig.emit("SUCCESS", f"{confidence}! {url} -> Host:{host} [{remark}]")
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            self.stats["fail"] += 1
            self._record_failure(url, host, exc)
            if self.stats["fail"] <= 5 or self.stats["fail"] % 500 == 0:
                self.log_sig.emit(
                    "DEBUG",
                    f"请求失败采样: {url} -> Host:{host} [{type(exc).__name__}: {exc}]",
                )

    def run(self):
        loop = self._create_event_loop()
        loop._completed_tasks_for_ui = len(self.scanned_set)

        dict_lines = 0
        if (
            self.dict_config
            and self.dict_config.get("enabled")
            and os.path.exists(self.dict_config.get("path", ""))
        ):
            try:
                with open(self.dict_config["path"], "rb") as handle:
                    dict_lines = sum(1 for _ in handle)
            except Exception:
                pass

        url_variants_per_ip = 0
        if self.policies.get("k", True):
            url_variants_per_ip += 2
        if self.policies.get("80", True):
            url_variants_per_ip += 1
        if self.policies.get("443", True):
            url_variants_per_ip += 1
        if self.policies.get("n", True):
            url_variants_per_ip += 2
        if url_variants_per_ip == 0:
            url_variants_per_ip = 4

        dom_variants = len(self.domains)
        if dict_lines > 0:
            prefix_count = max(
                1,
                len(
                    [
                        prefix
                        for prefix in self.dict_config.get("prefixes", "").split("\n")
                        if prefix.strip()
                    ]
                ),
            )
            suffix_count = max(
                1,
                len(
                    [
                        suffix
                        for suffix in self.dict_config.get("suffixes", "").split("\n")
                        if suffix.strip()
                    ]
                ),
            )
            dom_variants += dict_lines * prefix_count * suffix_count

        self.stats["total"] = len(self.ips) * url_variants_per_ip * dom_variants
        if self.concurrency != self.original_concurrency:
            self.log_sig.emit(
                "INFO",
                f"为保证稳定性，并发已从 {self.original_concurrency} 自动调整为 {self.concurrency}。",
            )
        self.log_sig.emit(
            "INFO",
            f"智能引擎启动，评估变体池共 {self.stats['total']} 个，已过滤 {len(self.scanned_set)} 个历史任务。"
            f" loop={type(loop).__name__} dns_workers={self._compute_dns_workers()}"
            f" dict={'on' if self.dynamic_dict_enabled else 'off'} size={self.dict_size_mb:.2f}MB",
        )

        async def worker(queue, session):
            while not self._stop_flag:
                try:
                    task_data = await asyncio.wait_for(queue.get(), timeout=0.5)
                    if task_data is None:
                        queue.task_done()
                        break
                    url, host, task_key = task_data
                    await self.fetch(session, url, host)
                    self.task_done_sig.emit(task_key)
                    queue.task_done()
                    loop._completed_tasks_for_ui += 1
                    if (
                        loop._completed_tasks_for_ui % 50 == 0
                        or self.stats["total"] < 1000
                    ):
                        self.progress_sig.emit(
                            loop._completed_tasks_for_ui,
                            self.stats["total"],
                        )
                except asyncio.TimeoutError:
                    continue
                except asyncio.CancelledError:
                    break
                except Exception:
                    pass

        async def run_all():
            timeout = aiohttp.ClientTimeout(total=8, connect=4, sock_connect=4, sock_read=4)
            connector = aiohttp.TCPConnector(
                limit=self.concurrency,
                limit_per_host=max(4, min(12, self.concurrency // 6)),
                ssl=False,
                force_close=True,
                enable_cleanup_closed=True,
            )
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                queue = asyncio.Queue(maxsize=max(self.concurrency * 2, 64))
                workers = [
                    asyncio.create_task(worker(queue, session))
                    for _ in range(self.concurrency)
                ]

                async def producer():
                    recent_task_keys = OrderedDict()

                    def remember_task(task_key):
                        if task_key in recent_task_keys:
                            recent_task_keys.move_to_end(task_key)
                            return False
                        recent_task_keys[task_key] = None
                        if len(recent_task_keys) > max(20000, self.concurrency * 100):
                            recent_task_keys.popitem(last=False)
                        return True

                    for raw_ip in self.ips:
                        if self._stop_flag:
                            break

                        pure_ip = normalize_ip_value(raw_ip)
                        if not pure_ip:
                            continue
                        _, _, port = str(raw_ip).partition(":")
                        port = port if port.isdigit() else None
                        url_variants = set()
                        if self.policies.get("k", True) and port:
                            url_variants.update([f"http://{raw_ip}", f"https://{raw_ip}"])
                        if self.policies.get("80", True):
                            url_variants.add(f"http://{pure_ip}:80")
                        if self.policies.get("443", True):
                            url_variants.add(f"https://{pure_ip}:443")
                        if self.policies.get("n", True):
                            url_variants.update([f"http://{pure_ip}", f"https://{pure_ip}"])
                        if not url_variants:
                            url_variants.update(
                                [
                                    f"http://{pure_ip}:80",
                                    f"https://{pure_ip}:443",
                                    f"http://{pure_ip}",
                                    f"https://{pure_ip}",
                                ]
                            )

                        for url_variant in url_variants:
                            for domain in self.generate_domains():
                                if self._stop_flag:
                                    return

                                task_key = task_fingerprint(f"{url_variant}|{domain}")
                                if task_key in self.scanned_set or not remember_task(task_key):
                                    continue

                                await queue.put((url_variant, domain, task_key))

                                parts = url_variant.split(":")
                                if len(parts) == 3:
                                    variant_port = parts[-1]
                                    domain_with_port = f"{domain}:{variant_port}"
                                    task_key_with_port = task_fingerprint(
                                        f"{url_variant}|{domain_with_port}"
                                    )
                                    if (
                                        task_key_with_port not in self.scanned_set
                                        and remember_task(task_key_with_port)
                                    ):
                                        await queue.put(
                                            (url_variant, domain_with_port, task_key_with_port)
                                        )

                    for _ in range(self.concurrency):
                        await queue.put(None)

                producer_task = asyncio.create_task(producer())
                while workers:
                    if self._stop_flag:
                        for worker_task in workers:
                            worker_task.cancel()
                        producer_task.cancel()
                        await asyncio.gather(*workers, return_exceptions=True)
                        break
                    _, pending = await asyncio.wait(workers, timeout=0.5)
                    workers = list(pending)

        try:
            loop.run_until_complete(run_all())
            self.stats["top_fail_reasons"] = dict(
                sorted(
                    self.fail_reason_counts.items(),
                    key=lambda item: (-item[1], item[0]),
                )[:5]
            )
            self._save_failure_samples()
            self.summary_sig.emit(self.stats, self._stop_flag)
        except Exception as exc:
            write_global_log("FATAL", f"对撞引擎崩溃堆栈:\n{traceback.format_exc()}")
            self.log_sig.emit("ERROR", f"对撞引擎异常: {exc}")
            self.stats["top_fail_reasons"] = dict(
                sorted(
                    self.fail_reason_counts.items(),
                    key=lambda item: (-item[1], item[0]),
                )[:5]
            )
            self._save_failure_samples()
            self.summary_sig.emit(self.stats, True)
        finally:
            self._save_dns_cache()
            self.dns_executor.shutdown(wait=False, cancel_futures=True)
            try:
                loop.run_until_complete(loop.shutdown_asyncgens())
                loop.close()
            except Exception:
                pass

    def evaluate_hit(
        self,
        bc,
        bl,
        bt,
        br,
        hc,
        hl,
        ht,
        hr,
        dc,
        dl,
        dt,
        dr,
        dns_resolved,
        target_ip=None,
        resolved_ips=None,
    ):
        if resolved_ips is None:
            resolved_ips = []

        ht = ht or "N/A"
        bt = bt or "N/A"
        dt = dt or "N/A"
        hr = hr or ""
        br = br or ""
        dr = dr or ""
        ht_lower = ht.lower()
        is_ht_garbage = any(item in ht_lower for item in self.garbage_titles)
        juicy_keywords = [
            "管理",
            "后台",
            "内部",
            "测试",
            "api",
            "admin",
            "test",
            "platform",
            "平台",
            "系统",
            "swagger",
            "登录",
            "sso",
        ]
        is_juicy = any(keyword in ht_lower for keyword in juicy_keywords)

        if hc <= 0:
            return "DROP", ""

        bc_desc = f"{bc} {HTTP_STATUS.get(bc, '未知')}"
        hc_desc = f"{hc} {HTTP_STATUS.get(hc, '未知')}"
        dc_desc = f"{dc} {HTTP_STATUS.get(dc, '未知')}" if dc else "0 未知"
        host_redirect = self._normalize_redirect(hr)
        base_redirect = self._normalize_redirect(br)
        domain_redirect = self._normalize_redirect(dr)

        if target_ip and target_ip in resolved_ips:
            return "低危", "域名公网解析已经包含当前 IP"

        same_domain = (
            hc == dc
            and ht == dt
            and abs(hl - dl) < 500
            and self._same_redirect(host_redirect, domain_redirect)
        )
        same_ip = (
            hc == bc
            and ht == bt
            and abs(hl - bl) < 500
            and self._same_redirect(host_redirect, base_redirect)
        )

        if same_domain:
            if hc in [301, 302]:
                return "DROP", ""
            return "低危", f"Host 碰撞与域名直连一致 [{hc_desc}]"

        if same_ip:
            if hc in [301, 302]:
                return "DROP", ""
            return "低危", f"Host 碰撞与 IP 默认站一致 [{hc_desc}]"

        if dc == 0 and hc == 200:
            if not dns_resolved:
                return "极危", f"无 DNS 解析记录，但 Host 碰撞命中 [{ht}]"
            return "极危", f"域名直连失败，但 Host 碰撞可访问 [{ht}]"

        if dc in [401, 403, 400, 500, 502, 503] and hc == 200:
            return "极危", f"域名直连 [{dc_desc}]，Host 碰撞返回 200 [{ht}]"

        if hc == 200 and dc == 200 and ht != dt and dt != "N/A":
            level = "极危" if is_juicy else "高危"
            return level, f"域名直连标题 [{dt}]，Host 碰撞标题 [{ht}]"

        if hc == 200 and bc not in [200, 301, 302]:
            return "高危", f"IP 直连 [{bc_desc}]，Host 碰撞 [{hc_desc}] [{ht}]"

        if hc in [301, 302]:
            if host_redirect and (
                self._same_redirect(host_redirect, domain_redirect)
                or self._same_redirect(host_redirect, base_redirect)
            ):
                return "DROP", ""
            if not host_redirect:
                return "DROP", ""
            level = "高危" if is_juicy else "中危"
            return level, f"Host 碰撞发生差异跳转 [{hc_desc}] -> {hr or 'N/A'}"

        if hc in [401, 405, 500] and bc in [404, 403, 400]:
            return "中危", f"IP 直连 [{bc_desc}]，Host 碰撞 [{hc_desc}]"

        if hc == 200 and bc == 200:
            diff = hl - bl
            if diff > 1000:
                level = "高危" if is_juicy else "中危"
                return level, f"响应体差异 {bl} -> {hl} [{ht}]"
            if diff < -1000:
                return "低危", f"响应体缩小 {bl} -> {hl} [{ht}]"

        if hc >= 400 and bc >= 400 and hc != bc:
            return "低危", f"错误响应存在差异 [{bc_desc}] -> [{hc_desc}]"

        if is_ht_garbage:
            if hc in [200, 301, 302, 401, 403]:
                return "低危", f"标题偏通用但存在有效响应 [{hc_desc}] [{ht}]"
            return "DROP", ""

        if hc in [200, 301, 302, 401, 403, 405, 500]:
            return "低危", f"Host 碰撞存在有效响应 [{hc_desc}] [{ht}]"

        return "DROP", ""


__all__ = ["CollTask"]
