import json
import os

from asset_common import collect_unique_ips, normalize_host_value, normalize_ip_value


BINDINGS_FILE = "domain_to_ip.json"
DNS_CACHE_FILE = "dns_cache.json"


def bindings_path(proj_dir):
    if not proj_dir:
        return ""
    return os.path.join(proj_dir, BINDINGS_FILE)


def dns_cache_path(proj_dir):
    if not proj_dir:
        return ""
    return os.path.join(proj_dir, DNS_CACHE_FILE)


def _load_json(path):
    if not path or not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_json(path, payload):
    if not path:
        return
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=4, ensure_ascii=False)


def load_domain_bindings(proj_dir):
    raw_cache = _load_json(bindings_path(proj_dir))
    cleaned = {}
    for domain, ips in raw_cache.items():
        clean_domain = normalize_host_value(domain)
        if not clean_domain or normalize_ip_value(clean_domain):
            continue
        clean_ips = collect_unique_ips(ips if isinstance(ips, list) else [ips])
        cleaned[clean_domain] = clean_ips
    return cleaned


def save_domain_bindings(proj_dir, bindings):
    cleaned = {}
    for domain, ips in (bindings or {}).items():
        clean_domain = normalize_host_value(domain)
        if not clean_domain or normalize_ip_value(clean_domain):
            continue
        cleaned[clean_domain] = collect_unique_ips(ips if isinstance(ips, list) else [ips])
    _save_json(bindings_path(proj_dir), cleaned)


def append_domain_bindings(proj_dir, bindings_to_merge):
    cache = load_domain_bindings(proj_dir)
    for domain, ips in (bindings_to_merge or {}).items():
        clean_domain = normalize_host_value(domain)
        if not clean_domain or normalize_ip_value(clean_domain):
            continue
        cache.setdefault(clean_domain, [])
        for ip in collect_unique_ips(ips if isinstance(ips, list) else [ips]):
            if ip not in cache[clean_domain]:
                cache[clean_domain].append(ip)
    save_domain_bindings(proj_dir, cache)
    return cache


def load_dns_cache(proj_dir):
    raw_cache = _load_json(dns_cache_path(proj_dir))
    cleaned = {}
    for host, ips in raw_cache.items():
        clean_host = normalize_host_value(host).split(":")[0]
        if not clean_host:
            continue
        cleaned[clean_host] = collect_unique_ips(ips if isinstance(ips, list) else [ips])
    return cleaned


def save_dns_cache(proj_dir, dns_cache):
    cleaned = {}
    for host, ips in (dns_cache or {}).items():
        clean_host = normalize_host_value(host).split(":")[0]
        if clean_host:
            cleaned[clean_host] = collect_unique_ips(ips if isinstance(ips, list) else [ips])
    _save_json(dns_cache_path(proj_dir), cleaned)
