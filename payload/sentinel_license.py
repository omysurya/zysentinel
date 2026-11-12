#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PT. StudioNet Indonesia Jaya (ZySens).
"""ZySentinel EDISI FREE: modul paket (pengganti modul lisensi edisi Pro).

Edisi Free tidak memuat pemverifikasi lisensi, agen lisensi, maupun modul premium. Paket SELALU "free"; konstanta fitur, paket
minimum per fitur, dan batas Free DIBANGKITKAN dari edisi Pro saat ekspor (edition/export-free.py), sehingga perilaku paket Free di
edisi ini sama dengan edisi Pro yang berlisensi Free. Pembelian (checkout) tetap memakai server zysens; kode lisensi diaktifkan di
ZySentinel Pro (rilis pro-vX.Y.Z di https://github.com/omysurya/zysentinel/releases). Berkas ini dibangkitkan: jangan disunting di repositori Free."""
import hashlib
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

ENFORCE = True
CHANNEL = "free"
EDITION = "free"
BASE = os.environ.get("ZYS_LICENSE_BASE", "/www/server/sentinel")
SERVER = os.environ.get("ZYS_LICENSE_SERVER", "https://sec.zysens.com")
VERSION = "2.0.1"
PRO_RELEASES = "https://github.com/omysurya/zysentinel/releases"

FEATURES = ["enforce", "learn", "geo_ban", "threat_sync", "waf_full", "waf_premium", "upload_scan", "upload_gate", "av_scheduled", "av_engines", "sweeper", "sweeper_auto", "proc_enforce", "egress", "integ_web", "notify", "notify_multi", "selfheal", "ports_unlimited", "fw_advanced", "thresholds", "fw_global", "threat_feed", "memscan", "recon_guard", "cve_feed", "cve_vpatch", "platform_standalone", "platform_panels", "event_feed", "edr_anomaly", "vhosts", "review_queue", "origin", "cve_advisor", "ports_ext", "av_crypto_judol", "fw_rules", "attack_dialogs"]
_PRO = set(["av_crypto_judol", "av_scheduled", "egress", "enforce", "event_feed", "fw_advanced", "geo_ban", "integ_web", "memscan", "notify", "origin", "platform_panels", "platform_standalone", "ports_ext", "proc_enforce", "review_queue", "selfheal", "threat_sync", "vhosts"])
FREE_FEATURES = tuple(["waf_full"])      # fitur semua paket (mis. WAF + aturan ZySentinel); jumlah vhost dibatasi FREE_LIMITS
PLAN_NEEDED = {n: ("free" if n in FREE_FEATURES else ("pro" if n in _PRO else "max")) for n in FEATURES}
FREE_LIMITS = {"port_rules": 10, "upload_vhosts": 0, "waf_vhosts": 1}


def p(*parts):
    return os.path.join(BASE, *parts)


def machine_id():
    f = os.environ.get("ZYS_MACHINE_ID_FILE", "/etc/machine-id")
    try:
        with open(f) as fh:
            raw = fh.readline().strip()
    except OSError:
        raw = ""
    return hashlib.sha256(("zys|" + raw).encode()).hexdigest()


def status(force=False):
    return {"mode": "enforce", "valid": 0, "reason": "edisi_free", "plan": "free", "state": "", "lic": "", "ip": "",
            "exp": 0, "paid": 0, "feat": 0, "allow": 0, "features": list(FREE_FEATURES), "edition": EDITION}


def transient(st):
    return False


def status_tampil():
    return dict(status(), stale=False)


# Edisi Free hanya kompatibel dengan aaPanel; platform lain membutuhkan edisi berlisensi.
PLATFORM_FEATURE = {"aapanel": None, "standalone": "platform_standalone", "cpanel": "platform_panels", "directadmin": "platform_panels",
                    "cyberpanel": "platform_panels"}


def platform_izin(nama):
    if nama == "aapanel":
        return True, None, "free"
    return False, PLATFORM_FEATURE.get(nama) or "platform_panels", "pro"


def platforms_diizinkan():
    return ["aapanel"]


def allowed(feature):
    return feature in FREE_FEATURES


def plan():
    return "free"


def limit(name):
    return FREE_LIMITS.get(name)


def needed_plan(feature):
    return PLAN_NEEDED.get(feature, "pro")


def _write(path, data, mode=0o600):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode), "w") as f:
        f.write(data)
    os.replace(tmp, path)


def get_code():
    try:
        return open(p("etc", "license.code")).read().strip()
    except OSError:
        return ""


def set_code(code):
    _write(p("etc", "license.code"), code.strip() + "\n")


def state_info():
    try:
        return json.load(open(p("etc", "license.state.json")))
    except Exception:
        return {}


def remove_token():
    return None


def refresh(code=None):
    """Edisi Free tidak dapat memverifikasi lisensi: arahkan ke ZySentinel Pro (kode tetap disimpan agar bisa dipakai setelah pindah)."""
    code = (code or get_code()).strip()
    if code:
        set_code(code)
    return {"ok": False, "state": "edisi_free", "http": 0, "plan": "free", "paid_until": 0, "ip": "", "ts": int(time.time()),
            "message": "Kode lisensi diaktifkan di ZySentinel Pro. Pasang rilis pro-v terbaru dari %s lalu masukkan kode Anda." % PRO_RELEASES}


def _post(path, body, timeout=12):
    data = json.dumps(body).encode()
    req = urllib.request.Request(SERVER.rstrip("/") + path, data=data, headers={"Content-Type": "application/json", "User-Agent": "ZySentinel-Free/" + VERSION}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read(1 << 20) or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read(1 << 16) or b"{}")
        except Exception:
            return e.code, {}
    except Exception as e:
        return 0, {"state": "offline", "message": str(e)[:120]}


def checkout(email, plan_, period, gateway="auto", currency="", promo="", lang="", name="", phone=""):
    """Harga dan diskon dihitung server; klien hanya menyebut paket, periode, dan kode promo (opsional)."""
    body = {"email": email, "plan": plan_, "period": period, "gateway": gateway, "currency": currency,
            "name": name, "phone": phone, "mid": machine_id(), "code": get_code()}
    if promo:
        body["promo"] = promo
    st, js = _post("/api/v1/checkout", body)
    if st == 200 and js.get("code"):
        set_code(js["code"])
    return st, js


def checkout_status(order_id):
    return _post("/api/v1/checkout/status", {"code": get_code(), "order_id": order_id})

ALASAN_KODE = ("too_expensive", "missing_features", "not_needed", "switching_server", "alternative", "problems", "testing", "other")   # sama dengan feedback.REASONS di server


def cancel_subscription(reason="", note=""):
    """Stop langganan (tanpa refund): server menghentikan perpanjangan otomatis; paket tetap aktif sampai paid_until. Alasan wajib (dicatat server)."""
    return _post("/api/v1/subscription/cancel", {"code": get_code(), "mid": machine_id(), "reason": reason, "note": note})


def release_license(reason="", note=""):
    """Uninstall License: beri tahu server alasan dan catatan pelanggan sebelum lisensi dilepas dari server ini (ikatan IP dan langganan tidak berubah)."""
    return _post("/api/v1/license/release", {"code": get_code(), "mid": machine_id(), "reason": reason, "note": note}, timeout=8)


def fetch_plans(currency="USD", promo=""):
    q = "?currency=" + urllib.parse.quote(currency) + (("&promo=" + urllib.parse.quote(promo)) if promo else "")
    try:
        # User-Agent wajib: Cloudflare menolak "Python-urllib" (403, error code 1010); perbaikan Pro 24 Okt 2026 belum ikut ke Free
        req = urllib.request.Request(SERVER.rstrip("/") + "/api/v1/plans" + q, headers={"User-Agent": "ZySentinel-Free/" + VERSION})
        with urllib.request.urlopen(req, timeout=8) as r:
            return json.loads(r.read(1 << 18))
    except Exception:
        return None


def mask_code(c):
    return (c[:8] + "-...-" + c[-5:]) if len(c) > 14 else c
