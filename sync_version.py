#!/usr/bin/env python3
"""
Sync latest ZySentinel release version from GitHub to sec.zysens.com/version.json
"""
import urllib.request
import json
import os
import tempfile
import datetime

TARGET_FILE = "/www/wwwroot/sec.zysens.com/version.json"
REPO = "omysurya/zysentinel"
URL = f"https://api.github.com/repos/{REPO}/releases/latest"

def sync_version():
    tag = "v1.6.2"
    ver = "1.6.2"
    name = "ZySentinel v1.6.2"
    published_at = ""
    html_url = f"https://github.com/{REPO}/releases/latest"
    zip_name = "zysentinel-v1.6.2.zip"
    zip_url = f"https://github.com/{REPO}/releases/download/v1.6.2/{zip_name}"
    tarball_url = f"https://api.github.com/repos/{REPO}/tarball/v1.6.2"

    headers = {
        "User-Agent": "ZySentinel-Web-Sync/1.0",
        "Accept": "application/vnd.github.v3+json"
    }

    try:
        req = urllib.request.Request(URL, headers=headers)
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            tag = data.get("tag_name", tag).strip()
            if not tag.startswith("v") and tag[0].isdigit():
                ver = tag
                tag = f"v{tag}"
            else:
                ver = tag.lstrip("v")
            name = data.get("name", f"ZySentinel {tag}")
            published_at = data.get("published_at", "")
            html_url = data.get("html_url", f"https://github.com/{REPO}/releases/tag/{tag}")
            tarball_url = data.get("tarball_url", f"https://api.github.com/repos/{REPO}/tarball/{tag}")

            # Find matching zip asset
            zip_name = f"zysentinel-{tag}.zip"
            zip_url = f"https://github.com/{REPO}/releases/download/{tag}/{zip_name}"
            for asset in data.get("assets", []):
                a_name = asset.get("name", "")
                if a_name.startswith("zysentinel-") and a_name.endswith(".zip"):
                    zip_name = a_name
                    zip_url = asset.get("browser_download_url", zip_url)
                    break
    except Exception as e:
        # Fallback to local plugin info.json if GitHub API is unreachable
        info_path = "/www/server/panel/plugin/sentinel/info.json"
        if os.path.exists(info_path):
            try:
                with open(info_path, "r", encoding="utf-8") as f:
                    local_info = json.load(f)
                    ver = local_info.get("versions", "1.6.2")
                    tag = f"v{ver}" if not ver.startswith("v") else ver
                    name = f"ZySentinel {tag}"
                    zip_name = f"zysentinel-{tag}.zip"
                    zip_url = f"https://github.com/{REPO}/releases/download/{tag}/{zip_name}"
            except Exception:
                pass

    out_data = {
        "tag_name": tag,
        "version": ver,
        "name": name,
        "published_at": published_at,
        "html_url": html_url,
        "zip_url": zip_url,
        "zip_name": zip_name,
        "tarball_url": tarball_url,
        "synced_at": datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=7))).isoformat()
    }

    os.makedirs(os.path.dirname(TARGET_FILE), exist_ok=True)
    dir_name = os.path.dirname(TARGET_FILE)
    with tempfile.NamedTemporaryFile("w", dir=dir_name, delete=False, encoding="utf-8") as tf:
        json.dump(out_data, tf, indent=2)
        temp_name = tf.name

    os.replace(temp_name, TARGET_FILE)
    try:
        import shutil
        os.chmod(TARGET_FILE, 0o644)
        # chown nobody:nogroup if possible
        import pwd, grp
        uid = pwd.getpwnam("nobody").pw_uid
        gid = grp.getgrnam("nogroup").gr_gid
        os.chown(TARGET_FILE, uid, gid)
    except Exception:
        pass

    return out_data

if __name__ == "__main__":
    result = sync_version()
    print(f"Synced version {result['tag_name']} ({result['version']}) successfully.")
