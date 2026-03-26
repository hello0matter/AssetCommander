import csv
import json
import os
import subprocess
import sys
from datetime import datetime


def save_text_file(project_dir, filename, content):
    if not project_dir:
        return
    path = os.path.join(project_dir, filename)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)


def overwrite_csv_rows(csv_path, fieldnames, rows):
    with open(csv_path, "w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def append_csv_rows(csv_path, fieldnames, rows):
    file_exists = os.path.exists(csv_path)
    with open(csv_path, "a", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        if not file_exists:
            writer.writeheader()
        writer.writerows(rows)


def append_lines(path, lines):
    if not lines:
        return
    with open(path, "a", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


def default_project_root(project_dir, workspace_dir):
    if project_dir and os.path.isdir(project_dir):
        return os.path.dirname(project_dir)
    return os.path.abspath(workspace_dir)


def fail_sample_path(project_dir, fail_sample_file):
    if not project_dir:
        return ""
    return os.path.join(project_dir, fail_sample_file)


def is_subpath(candidate, parent):
    try:
        candidate_abs = os.path.abspath(candidate)
        parent_abs = os.path.abspath(parent)
        return os.path.commonpath([candidate_abs, parent_abs]) == parent_abs
    except Exception:
        return False


def open_local_path(path):
    if sys.platform == "win32":
        os.startfile(path)
    elif sys.platform == "darwin":
        subprocess.Popen(["open", path])
    else:
        subprocess.Popen(["xdg-open", path])


def progress_state_path(project_dir, progress_file):
    if not project_dir:
        return ""
    return os.path.join(project_dir, progress_file)


def read_progress_state(project_dir, progress_file):
    path = progress_state_path(project_dir, progress_file)
    if not path or not os.path.exists(path):
        return {}

    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    return data if isinstance(data, dict) else {}


def write_progress_state(
    project_dir,
    progress_file,
    scanned_current,
    current=None,
    total=None,
    bar_total=0,
    active=None,
    stats=None,
):
    if not project_dir:
        return {}

    state = read_progress_state(project_dir, progress_file)

    if current is None:
        current = max(scanned_current, int(state.get("current", 0) or 0))
    else:
        current = max(scanned_current, int(current))

    existing_total = int(state.get("total", 0) or 0)
    if total is None:
        total = max(existing_total, int(bar_total or 0), current, 1)
    else:
        total = max(int(total), current, 1)

    state["current"] = current
    state["total"] = total
    if active is not None:
        state["active"] = bool(active)
    if isinstance(stats, dict):
        state["stats"] = {
            "total": int(stats.get("total", 0) or 0),
            "success": int(stats.get("success", 0) or 0),
            "fail": int(stats.get("fail", 0) or 0),
        }
        if isinstance(stats.get("top_fail_reasons"), dict):
            state["stats"]["top_fail_reasons"] = dict(stats.get("top_fail_reasons"))

    state["updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    path = progress_state_path(project_dir, progress_file)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(state, handle, ensure_ascii=False, indent=2)
    return state


def save_settings(project_dir, settings):
    if not project_dir:
        return
    path = os.path.join(project_dir, "settings.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(settings, handle, ensure_ascii=False, indent=4)
