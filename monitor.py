"""Monitor a Tuya water TDS sensor and notify two Telegram groups.

The GitHub Actions workflow supplies all secrets via environment variables.
The encrypted state file is committed by the workflow after each run.

IMPORTANT: Do NOT call Manager.unload(): it expires the Tuya terminal token.
"""

import json
import os
import re
import sys
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from cryptography.fernet import Fernet
from tuya_sharing import Manager
from tuya_sharing.customerapi import SharingTokenListener


STATE_FILE = Path("tds_state.enc")
CLIENT_ID = "HA_3y9q4ak7g4ephrvke"


def now():
    return datetime.now(ZoneInfo("Asia/Baghdad")).strftime("%Y-%m-%d %H:%M")


def send_message(group, message):
    """Send to the selected group; never reveal Telegram credentials in logs."""
    try:
        token = os.environ["TELEGRAM_BOT_TOKEN"]
        env_key = (
            "TELEGRAM_TDS_GROUP_ID"
            if group == "tds"
            else "TELEGRAM_ALERTS_GROUP_ID"
        )
        chat_id = os.environ[env_key]
        data = urllib.parse.urlencode(
            {"chat_id": chat_id, "text": message}
        ).encode("utf-8")
        request = urllib.request.Request(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data=data,
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=25) as response:
            result = json.load(response)
        return result.get("ok") is True
    except Exception:
        print(f"TELEGRAM_SEND_FAILED_{group.upper()}")
        return False


def save_state(state, cipher):
    data = json.dumps(
        state, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    temp = STATE_FILE.with_suffix(".enc.tmp")
    temp.write_bytes(cipher.encrypt(data))
    temp.replace(STATE_FILE)


def load_state():
    cipher = Fernet(os.environ["TUYA_FERNET_KEY"].encode("utf-8"))
    if STATE_FILE.is_file():
        state = json.loads(cipher.decrypt(STATE_FILE.read_bytes()))
    else:
        state = {"session": json.loads(os.environ["TUYA_BOOTSTRAP_SESSION"])}

    defaults = {
        "band": None,
        "sent_tds": False,
        "sent_alerts": False,
        "last_value": None,
        "same_count": 0,
        "stuck_alert_sent": False,
        "stuck_value": None,
        "read_error_sent": False,
        "last_success_at": None,
    }
    for key, default_value in defaults.items():
        state.setdefault(key, default_value)
    return state, cipher


class TokenListener(SharingTokenListener):
    """Persist refreshed Tuya tokens using Fernet encryption."""

    def __init__(self, state, cipher):
        super().__init__()
        self.state = state
        self.cipher = cipher

    def update_token(self, new_token_info):
        self.state["session"]["token_info"] = new_token_info
        save_state(self.state, self.cipher)


def read_tds(state, cipher):
    session = state["session"]
    manager = Manager(
        session.get("client_id", CLIENT_ID),
        session["user_code"],
        session["terminal_id"],
        session["endpoint"],
        session["token_info"],
        TokenListener(state, cipher),
    )

    # Do not call manager.unload() here (or in a finally block).
    # Manager.unload() requests /v1.0/m/token/terminal/expire, which can
    # invalidate the terminal session needed by the next scheduled run.
    manager.update_device_cache()

    devices = [
        device
        for device in manager.device_map.values()
        if "tds_in" in (device.status or {})
    ]
    if len(devices) != 1:
        raise RuntimeError(
            "TDS_SENSOR_NOT_FOUND" if not devices else "MULTIPLE_TDS_SENSORS"
        )

    device = devices[0]
    if not device.online:
        raise RuntimeError("TDS_SENSOR_OFFLINE")

    raw_value = device.status["tds_in"]
    if raw_value is None or isinstance(raw_value, bool):
        raise RuntimeError("INVALID_TDS")

    try:
        value = float(raw_value)
    except (ValueError, TypeError) as exc:
        raise RuntimeError("INVALID_TDS") from exc
    if not value.is_integer() or value < 0:
        raise RuntimeError("INVALID_TDS")
    return int(value)


def classify(value):
    if value <= 100:
        return "silent", ""
    if value <= 700:
        return "very_sweet", "الماء جداً حلو"
    if value <= 1200:
        return "sweet", "الماء حلو"
    if value <= 2000:
        return "medium", "الماء متوسط الملوحة"
    if value <= 3200:
        return "salty", "الماء مالح"
    return "very_salty", "الماء شديد الملوحة"


def safe_error_details(error):
    """Provide actionable log data without printing tokens or session JSON."""
    raw_message = str(error).lower()
    if "sign invalid" in raw_message:
        kind = "SIGN_INVALID"
    elif "token is expired" in raw_message or "token expired" in raw_message:
        kind = "TOKEN_EXPIRED"
    elif "qps" in raw_message or "rate limit" in raw_message:
        kind = "RATE_LIMIT"
    elif "permission deny" in raw_message:
        kind = "PERMISSION_DENIED"
    elif "timed out" in raw_message or "timeout" in raw_message:
        kind = "TIMEOUT"
    else:
        kind = type(error).__name__

    # Extract a numeric error code, never echo the whole exception.
    match = re.search(r"(?<!\d)-?\d{4,}(?!\d)", raw_message)
    code = match.group(0) if match else "UNKNOWN"
    return code, kind


def monitor():
    state, cipher = load_state()
    delivery_failed = False

    try:
        value = read_tds(state, cipher)
    except Exception as error:
        # Failed attempts do not count as successful identical readings.
        state["same_count"] = 0
        code, kind = safe_error_details(error)
        print(f"TUYA_ERROR_CODE={code}")
        print(f"TUYA_ERROR_KIND={kind}")

        if not state["read_error_sent"]:
            message = (
                "⚠️ عطل في مراقبة TDS\n"
                "تعذرت قراءة المستشعر عبر Tuya.\n"
                f"نوع الخطأ: {kind}\n"
                f"رمز الخطأ: {code}\n"
                f"آخر قراءة ناجحة: {state['last_value']}\n"
                f"وقتها: {state['last_success_at']}\n"
                f"وقت اكتشاف العطل: {now()}"
            )
            if send_message("alerts", message):
                state["read_error_sent"] = True
            else:
                delivery_failed = True

        save_state(state, cipher)
        print("SENSOR_READ_FAILED")
        sys.exit(2 if not delivery_failed else 3)

    # Inform the technical group once when communication resumes.
    if state["read_error_sent"]:
        if send_message(
            "alerts",
            "✅ تمت استعادة قراءة مستشعر TDS.\n"
            f"القراءة الحالية: {value} ppm\n"
            f"الوقت: {now()}",
        ):
            state["read_error_sent"] = False
        else:
            delivery_failed = True

    previous_value = state["last_value"]
    if previous_value == value:
        state["same_count"] += 1
    else:
        state["same_count"] = 1

    # The warning clears only after an actual numerical change.
    if state["stuck_alert_sent"] and value != state["stuck_value"]:
        if send_message(
            "alerts",
            "✅ انتهت حالة ثبات قراءة TDS.\n"
            f"القيمة السابقة: {state['stuck_value']} ppm\n"
            f"القيمة الحالية: {value} ppm\n"
            f"الوقت: {now()}",
        ):
            state["stuck_alert_sent"] = False
            state["stuck_value"] = None
        else:
            delivery_failed = True

    if state["same_count"] > 10 and not state["stuck_alert_sent"]:
        if send_message(
            "alerts",
            "⚠️ تنبيه: قيمة TDS ثابتة!\n"
            f"القيمة: {value} ppm\n"
            f"عدد الفحوصات المتطابقة: {state['same_count']}\n"
            "يرجى التأكد من أن المستشعر يعمل بصورة صحيحة.\n"
            f"الوقت: {now()}",
        ):
            state["stuck_alert_sent"] = True
            state["stuck_value"] = value
        else:
            delivery_failed = True

    state["last_value"] = value
    state["last_success_at"] = now()
    band, description = classify(value)

    if band != state["band"]:
        state["band"] = band
        state["sent_tds"] = False
        state["sent_alerts"] = False

    # No public messages for 0-100 ppm.
    if band == "silent":
        state["sent_tds"] = True
        state["sent_alerts"] = True
    else:
        message = (
            f"💧 قيمة TDS: {value} ppm\n"
            f"🌊 حالة الماء: {description}\n"
            f"🕒 الوقت: {now()}"
        )
        if not state["sent_tds"]:
            if send_message("tds", message):
                state["sent_tds"] = True
            else:
                delivery_failed = True
        if not state["sent_alerts"]:
            if send_message("alerts", message):
                state["sent_alerts"] = True
            else:
                delivery_failed = True

    save_state(state, cipher)
    print(f"CHECK_FINISHED band={band} same_count={state['same_count']}")
    if delivery_failed:
        sys.exit(3)


if __name__ == "__main__":
    try:
        monitor()
    except SystemExit:
        raise
    except Exception as error:
        # Never print exception strings containing possible credentials.
        print(f"MONITOR_FATAL_{type(error).__name__}")
        send_message(
            "alerts",
            "🚨 خطأ غير متوقع في برنامج مراقبة TDS.\n"
            f"نوع الخطأ: {type(error).__name__}\n"
            f"الوقت: {now()}",
        )
        sys.exit(1)
