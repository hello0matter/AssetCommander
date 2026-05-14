import asyncio
import faulthandler
import hashlib
import ipaddress
import json
import os
import re
import sys
import threading
import traceback
from datetime import datetime


RE_AST = r"((?:https?://|)\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?::\d+)?\b)"
RE_IP = r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?::\d+)?\b"
RE_DOM = r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}"

CONFIG_FILE = "config.json"
WORKSPACE_DIR = "workspace"
GLOBAL_LOG_FILE = "AssetCommander.log"
CRASH_DUMP_FILE = "AssetCommander-crash.log"
RESULT_FIELDS = ["url", "site", "host", "code", "len", "title", "conf", "remark"]
LOW_RISK_UI_LIMIT = 800
SCAN_PROGRESS_FILE = "scan_progress.json"
FAIL_SAMPLE_FILE = "fail_samples.log"
PROJECT_COPY_FILES = [
    "ips.txt",
    "domains.txt",
    "settings.json",
    "dict_config.json",
    "domain_to_ip.json",
    "hunter.json",
    "fission.json",
    "reverse_ip.json",
]
_TASK_FINGERPRINT_RE = re.compile(r"^[0-9a-f]{32}$")
_CRASH_DUMP_HANDLE = None


def _patch_windows_proactor_reset_noise():
    if sys.platform != "win32":
        return

    import asyncio.proactor_events

    transport_cls = asyncio.proactor_events._ProactorBasePipeTransport
    if getattr(transport_cls, "_assetcommander_reset_patch", False):
        return

    original = transport_cls._call_connection_lost

    def _silence_10054(self, exc):
        try:
            original(self, exc)
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            pass
        except OSError as err:
            if getattr(err, "winerror", None) in (10053, 10054):
                return
            raise

    transport_cls._call_connection_lost = _silence_10054
    transport_cls._assetcommander_reset_patch = True


_patch_windows_proactor_reset_noise()


HTTP_STATUS = {
    100: "Continue(继续)",
    101: "Switching Protocols(切换协议)",
    200: "OK(请求成功)",
    201: "Created(已创建)",
    202: "Accepted(已接受)",
    203: "Non-Authoritative(非权威信息)",
    204: "No Content(无内容)",
    205: "Reset Content(重置内容)",
    206: "Partial Content(部分内容)",
    300: "Multiple Choices(多种选择)",
    301: "Moved Permanently(永久重定向)",
    302: "Found(临时重定向)",
    303: "See Other(查看其他位置)",
    304: "Not Modified(未修改)",
    305: "Use Proxy(使用代理)",
    307: "Temporary Redirect(临时重定向)",
    400: "Bad Request(错误请求)",
    401: "Unauthorized(未授权)",
    402: "Payment Required(保留)",
    403: "Forbidden(禁止访问)",
    404: "Not Found(未找到)",
    405: "Method Not Allowed(方法不允许)",
    406: "Not Acceptable(不可接受)",
    407: "Proxy Auth Required(需要代理认证)",
    408: "Request Timeout(请求超时)",
    409: "Conflict(冲突)",
    410: "Gone(资源已删除)",
    411: "Length Required(需要长度)",
    412: "Precondition Failed(前置条件失败)",
    413: "Entity Too Large(实体过大)",
    414: "URI Too Large(URI 过长)",
    415: "Unsupported Media Type(不支持的媒体类型)",
    416: "Range Not Satisfiable(范围无效)",
    417: "Expectation Failed(预期失败)",
    418: "I'm a teapot(彩蛋状态码)",
    500: "Internal Server Error(服务器内部错误)",
    501: "Not Implemented(未实现)",
    502: "Bad Gateway(网关错误)",
    503: "Service Unavailable(服务不可用)",
    504: "Gateway Timeout(网关超时)",
    505: "HTTP Version Not Supported(HTTP 版本不支持)",
}


def write_global_log(level, msg):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open(GLOBAL_LOG_FILE, "a", encoding="utf-8") as handle:
            handle.write(f"[{timestamp}] [{level}] {msg}\n")
    except Exception:
        pass


def task_fingerprint(value):
    raw = str(value or "").strip().lower()
    if not raw:
        return ""
    return hashlib.blake2b(
        raw.encode("utf-8", errors="ignore"),
        digest_size=16,
    ).hexdigest()


def normalize_task_record(value):
    raw = str(value or "").strip().lower()
    if not raw:
        return ""
    if _TASK_FINGERPRINT_RE.fullmatch(raw):
        return raw
    return task_fingerprint(raw)


def install_global_crash_handlers():
    global _CRASH_DUMP_HANDLE

    if getattr(install_global_crash_handlers, "_installed", False):
        return

    def _handle_unhandled_exception(exc_type, exc_value, exc_traceback):
        if issubclass(exc_type, KeyboardInterrupt):
            return sys.__excepthook__(exc_type, exc_value, exc_traceback)

        formatted = "".join(
            traceback.format_exception(exc_type, exc_value, exc_traceback)
        ).rstrip()
        write_global_log("FATAL", f"未捕获异常:\n{formatted}")

        try:
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
        except Exception:
            pass

    sys.excepthook = _handle_unhandled_exception

    if hasattr(threading, "excepthook"):
        def _thread_excepthook(args):
            _handle_unhandled_exception(
                args.exc_type,
                args.exc_value,
                args.exc_traceback,
            )

        threading.excepthook = _thread_excepthook

    try:
        _CRASH_DUMP_HANDLE = open(CRASH_DUMP_FILE, "a", encoding="utf-8", buffering=1)
        faulthandler.enable(_CRASH_DUMP_HANDLE, all_threads=True)
    except Exception:
        pass

    install_global_crash_handlers._installed = True


def get_base_config():
    default = {
        "fscan_cmd": "fscan.exe -h {target} -p 80,443,8080,8443 -m web -np -t 100",
        "oneforall_cmd": "python oneforall.py --target {target} run",
    }
    if not os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "w", encoding="utf-8") as handle:
            json.dump(default, handle, indent=4, ensure_ascii=False)
        return default

    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as handle:
            current_config = json.load(handle)
    except Exception:
        current_config = {}

    needs_update = False
    for key, value in default.items():
        if key not in current_config:
            current_config[key] = value
            needs_update = True

    if needs_update:
        with open(CONFIG_FILE, "w", encoding="utf-8") as handle:
            json.dump(current_config, handle, indent=4, ensure_ascii=False)

    return current_config


def extract_title(html_text):
    match = re.search(r"<title>(.*?)</title>", html_text, re.I | re.S)
    if match:
        return match.group(1).strip().replace("\n", "").replace("\r", "")
    return "N/A"


def split_token_candidates(raw_text):
    return [
        token.strip()
        for token in re.split(r"[\s,;，；]+", str(raw_text or ""))
        if token.strip()
    ]


def normalize_ip_value(value):
    raw = str(value or "").strip()
    if not raw:
        return ""

    candidate = raw
    if "://" in candidate:
        candidate = candidate.split("://", 1)[1]
    candidate = candidate.split("/", 1)[0].strip("[]")
    if ":" in candidate:
        host, _, port = candidate.partition(":")
        if port.isdigit():
            candidate = host

    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return ""


def normalize_ip_target(value):
    raw = str(value or "").strip()
    if not raw:
        return ""

    candidate = raw
    if "://" in candidate:
        candidate = candidate.split("://", 1)[1]
    candidate = candidate.split("/", 1)[0].strip().strip("[]")

    host = candidate
    port = ""
    if ":" in candidate:
        maybe_host, _, maybe_port = candidate.partition(":")
        if maybe_port.isdigit():
            host = maybe_host
            port = maybe_port

    normalized_host = normalize_ip_value(host)
    if not normalized_host:
        return ""
    if port:
        return f"{normalized_host}:{port}"
    return normalized_host


def collect_unique_ips(raw_values):
    seen = set()
    items = []
    for raw_value in raw_values or []:
        for token in split_token_candidates(raw_value):
            normalized = normalize_ip_target(token)
            if normalized and normalized not in seen:
                seen.add(normalized)
                items.append(normalized)
    return items


def normalize_host_value(value):
    raw = str(value or "").strip().lower()
    if not raw:
        return ""
    if "://" in raw:
        raw = raw.split("://", 1)[1]
    raw = raw.split("/", 1)[0].strip().strip("[]")
    return raw


def collect_unique_hosts(raw_values):
    seen = set()
    items = []
    for raw_value in raw_values or []:
        for token in split_token_candidates(raw_value):
            normalized = normalize_host_value(token)
            if normalized and normalized not in seen:
                seen.add(normalized)
                items.append(normalized)
    return items


def derive_site_label(url, host):
    clean_url = str(url or "").strip()
    clean_host = normalize_host_value(host)
    if not clean_host and clean_url:
        target = clean_url.split("://", 1)[-1].split("/", 1)[0]
        clean_host = normalize_host_value(target)

    if not clean_host:
        return clean_url

    scheme = ""
    if "://" in clean_url:
        scheme = clean_url.split("://", 1)[0].strip().lower()
    if scheme:
        return f"{scheme}://{clean_host}"
    return clean_host


__all__ = [
    "CRASH_DUMP_FILE",
    "CONFIG_FILE",
    "FAIL_SAMPLE_FILE",
    "GLOBAL_LOG_FILE",
    "HTTP_STATUS",
    "install_global_crash_handlers",
    "LOW_RISK_UI_LIMIT",
    "normalize_task_record",
    "PROJECT_COPY_FILES",
    "RE_AST",
    "RE_DOM",
    "RE_IP",
    "RESULT_FIELDS",
    "SCAN_PROGRESS_FILE",
    "WORKSPACE_DIR",
    "extract_title",
    "get_base_config",
    "task_fingerprint",
    "write_global_log",
]
