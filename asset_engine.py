import asyncio
import concurrent.futures
import json
import os
import re
import socket
from datetime import datetime

import aiohttp
from PySide6.QtCore import QThread, Signal

from asset_common import FAIL_SAMPLE_FILE, HTTP_STATUS, extract_title


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
        self.ips = ips
        self.domains = domains
        self.policies = policies
        self.concurrency = concurrency
        self.proj_dir = proj_dir
        self.scanned_set = scanned_set
        self.dict_config = dict_config
        self.stats = {"total": 0, "success": 0, "fail": 0}
        self.fail_reason_counts = {}
        self.fail_samples = []
        self._stop_flag = False
        self.domain_cache = {}
        self.dns_cache = {}
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
            max_workers=concurrency + 50
        )

    def stop(self):
        self._stop_flag = True

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

        path = os.path.join(self.proj_dir, "domain_to_ip.json")
        if not os.path.exists(path):
            return

        try:
            raw_cache = json.load(open(path, "r", encoding="utf-8"))
            self.dns_cache = {}
            for key, value in raw_cache.items():
                clean_key = key.split(":")[0]
                if clean_key not in self.dns_cache or not self.dns_cache[clean_key]:
                    self.dns_cache[clean_key] = value
        except Exception:
            pass

    def _save_dns_cache(self):
        if not self.proj_dir:
            return

        path = os.path.join(self.proj_dir, "domain_to_ip.json")
        try:
            json.dump(
                self.dns_cache,
                open(path, "w", encoding="utf-8"),
                indent=4,
                ensure_ascii=False,
            )
        except Exception:
            pass

    async def resolve_dns(self, host):
        clean_host = host.split(":")[0]
        if clean_host in self.dns_cache:
            return self.dns_cache[clean_host]

        if clean_host not in self._dns_locks:
            self._dns_locks[clean_host] = asyncio.Lock()

        async with self._dns_locks[clean_host]:
            if clean_host in self.dns_cache:
                return self.dns_cache[clean_host]

            if re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", clean_host):
                self.dns_cache[clean_host] = [clean_host]
                return [clean_host]

            loop = asyncio.get_running_loop()
            try:
                _, _, ips = await loop.run_in_executor(
                    self.dns_executor,
                    socket.gethostbyname_ex,
                    clean_host,
                )
                self.dns_cache[clean_host] = ips
            except Exception:
                self.dns_cache[clean_host] = []

            return self.dns_cache[clean_host]

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

            cache_key = f"{scheme}://{host}"
            if cache_key not in self.domain_cache:
                if cache_key not in self._dom_locks:
                    self._dom_locks[cache_key] = asyncio.Lock()

                async with self._dom_locks[cache_key]:
                    if cache_key not in self.domain_cache:
                        if not dns_resolved:
                            self.domain_cache[cache_key] = (0, 0, "DEAD_DOMAIN")
                        else:
                            try:
                                async with session.get(
                                    cache_key,
                                    timeout=5,
                                    ssl=False,
                                    allow_redirects=False,
                                ) as response_domain:
                                    domain_text = await response_domain.text()
                                    self.domain_cache[cache_key] = (
                                        response_domain.status,
                                        len(domain_text),
                                        extract_title(domain_text),
                                    )
                            except Exception:
                                self.domain_cache[cache_key] = (0, 0, "HTTP_FAILED")

            dc, dl, dt = self.domain_cache[cache_key]

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

            target_ip = url.split("://")[1].split(":")[0].split("/")[0]
            confidence, remark = self.evaluate_hit(
                bc,
                bl,
                bt,
                hc,
                hl,
                ht,
                dc,
                dl,
                dt,
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

                if "危" in confidence and "低危" not in confidence:
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
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
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
        self.log_sig.emit(
            "INFO",
            f"智能引擎启动，评估变体池共 {self.stats['total']} 个，已过滤 {len(self.scanned_set)} 个历史任务。",
        )

        async def worker(queue, session):
            while not self._stop_flag:
                try:
                    task_data = await asyncio.wait_for(queue.get(), timeout=0.5)
                    if task_data is None:
                        queue.task_done()
                        break
                    url, host = task_data
                    await self.fetch(session, url, host)
                    self.task_done_sig.emit(f"{url}|{host}")
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
            connector = aiohttp.TCPConnector(
                limit=self.concurrency,
                ssl=False,
                force_close=True,
            )
            async with aiohttp.ClientSession(connector=connector) as session:
                queue = asyncio.Queue(maxsize=self.concurrency * 2)
                workers = [
                    asyncio.create_task(worker(queue, session))
                    for _ in range(self.concurrency)
                ]

                async def producer():
                    for raw_ip in self.ips:
                        if self._stop_flag:
                            break

                        pure_ip = raw_ip.split(":")[0]
                        port = raw_ip.split(":")[1] if ":" in raw_ip else None
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

                                task_id = f"{url_variant}|{domain}"
                                if task_id in self.scanned_set:
                                    continue

                                await queue.put((url_variant, domain))

                                parts = url_variant.split(":")
                                if len(parts) == 3:
                                    variant_port = parts[-1]
                                    task_id_with_port = f"{url_variant}|{domain}:{variant_port}"
                                    if task_id_with_port not in self.scanned_set:
                                        await queue.put((url_variant, f"{domain}:{variant_port}"))

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
            self.log_sig.emit("ERROR", f"对撞引擎异常: {exc}")
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
        hc,
        hl,
        ht,
        dc,
        dl,
        dt,
        dns_resolved,
        target_ip=None,
        resolved_ips=None,
    ):
        if resolved_ips is None:
            resolved_ips = []

        ht = ht or "N/A"
        bt = bt or "N/A"
        dt = dt or "N/A"
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

        if target_ip and target_ip in resolved_ips:
            return "低危", "域名公网解析已经包含当前 IP"

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
            level = "高危" if is_juicy else "中危"
            return level, f"Host 碰撞发生跳转 [{hc_desc}] [{ht}]"

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

        same_domain = hc == dc and ht == dt and abs(hl - dl) < 500
        same_ip = hc == bc and ht == bt and abs(hl - bl) < 500

        if same_domain:
            return "低危", f"Host 碰撞与域名直连一致 [{hc_desc}]"

        if same_ip:
            return "低危", f"Host 碰撞与 IP 默认站一致 [{hc_desc}]"

        if hc in [200, 301, 302, 401, 403, 405, 500]:
            return "低危", f"Host 碰撞存在有效响应 [{hc_desc}] [{ht}]"

        return "DROP", ""


__all__ = ["CollTask"]
