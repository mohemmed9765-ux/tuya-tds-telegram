import json
import os
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
    try:
        token = os.environ["TELEGRAM_BOT_TOKEN"]
        chat_id = os.environ[
            "TELEGRAM_TDS_GROUP_ID"
            if group == "tds"
            else "TELEGRAM_ALERTS_GROUP_ID"
        ]

        data = urllib.parse.urlencode({
            "chat_id": chat_id,
            "text": message,
        }).encode()

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
    content = json.dumps(
        state, ensure_ascii=False, separators=(",", ":")
    ).encode()

    temp_file = Path("tds_state.enc.tmp")
    temp_file.write_bytes(cipher.encrypt(content))
    temp_file.replace(STATE_FILE)


def load_state():
    cipher = Fernet(os.environ["TUYA_FERNET_KEY"].encode())

    if STATE_FILE.exists():
        state = json.loads(cipher.decrypt(STATE_FILE.read_bytes()))
    else:
        session = json.loads(os.environ["TUYA_BOOTSTRAP_SESSION"])
        state = {
            "session": session,
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

    return state, cipher


class TokenListener(SharingTokenListener):
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

    try:
        manager.update_device_cache()

        devices = [
            device
            for device in manager.device_map.values()
            if "tds_in" in (device.status or {})
        ]

        if len(devices) != 1:
            raise RuntimeError("TDS_SENSOR_NOT_UNIQUE")

        device = devices[0]

        if not device.online:
            raise RuntimeError("TDS_SENSOR_OFFLINE")

        raw = device.status["tds_in"]

        if raw is None or isinstance(raw, bool):
            raise RuntimeError("INVALID_TDS")

        value = float(raw)

        if not value.is_integer() or value < 0:
            raise RuntimeError("INVALID_TDS")

        return int(value)

    finally:
        try:
            manager.unload()
        except Exception:
            pass


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


def monitor():
    state, cipher = load_state()
    delivery_failed = False

    try:
        value = read_tds(state, cipher)

    except Exception as error:
        error_code = str(getattr(error, "error_code", "UNKNOWN"))

        if not error_code.lstrip("-").isdigit():
            error_code = "UNKNOWN"

        print(f"TUYA_ERROR_CODE={error_code}")
                reason = str(getattr(error, "error_message", "")).lower()

        if "sign invalid" in reason:
            error_kind = "SIGN_INVALID"
        elif "qps" in reason or "degrade" in reason:
            error_kind = "RATE_LIMIT_OR_DEGRADE"
        elif "token" in reason:
            error_kind = "TOKEN_ERROR"
        elif "uri path invalid" in reason:
            error_kind = "INVALID_API_PATH"
        else:
            error_kind = "OTHER"

        print(f"TUYA_ERROR_KIND={error_kind}")

        # لا نعتبر الفحص الفاشل قراءة ناجحة متتالية.
        state["same_count"] = 0

        if not state.get("read_error_sent"):
            message = (
                "⚠️ عطل في مراقبة TDS\n"
                "تعذرت قراءة المستشعر عبر Tuya.\n"
                f"نوع الخطأ: {type(error).__name__}\n"
                f"آخر قراءة ناجحة: {state.get('last_value')}\n"
                f"وقتها: {state.get('last_success_at')}\n"
                f"وقت اكتشاف العطل: {now()}"
            )

            if send_message("alerts", message):
                state["read_error_sent"] = True
            else:
                delivery_failed = True

        save_state(state, cipher)
        print("SENSOR_READ_FAILED")

        if delivery_failed:
            sys.exit(1)

        return

    # استعادة الاتصال بعد مشكلة سابقة.
    if state.get("read_error_sent"):
        if send_message(
            "alerts",
            f"✅ تمت استعادة قراءة مستشعر TDS.\n"
            f"القراءة الحالية: {value} ppm\n"
            f"الوقت: {now()}",
        ):
            state["read_error_sent"] = False
        else:
            delivery_failed = True

    previous_value = state.get("last_value")

    # حساب عدد القراءات الرقمية المتطابقة.
    if previous_value == value:
        state["same_count"] = state.get("same_count", 0) + 1
    else:
        state["same_count"] = 1

    # إلغاء حالة الثبات عند تغير القيمة.
    if (
        state.get("stuck_alert_sent")
        and value != state.get("stuck_value")
    ):
        if send_message(
            "alerts",
            "✅ انتهت حالة ثبات قراءة TDS.\n"
            f"القيمة السابقة: {state.get('stuck_value')} ppm\n"
            f"القيمة الحالية: {value} ppm\n"
            f"الوقت: {now()}",
        ):
            state["stuck_alert_sent"] = False
            state["stuck_value"] = None
        else:
            delivery_failed = True

    # إنذار واحد عند القراءة المتطابقة رقم 11.
    if (
        state["same_count"] > 10
        and not state.get("stuck_alert_sent")
    ):
        message = (
            "⚠️ تنبيه: قيمة TDS ثابتة!\n"
            f"القيمة: {value} ppm\n"
            f"عدد الفحوصات المتطابقة: {state['same_count']}\n"
            "يرجى التأكد من أن المستشعر يعمل بصورة صحيحة.\n"
            f"الوقت: {now()}"
        )

        if send_message("alerts", message):
            state["stuck_alert_sent"] = True
            state["stuck_value"] = value
        else:
            delivery_failed = True

    state["last_value"] = value
    state["last_success_at"] = now()

    band, description = classify(value)

    # عند تغير نطاق الملوحة، جهز إشعارًا جديدًا للمجموعتين.
    if band != state.get("band"):
        state["band"] = band
        state["sent_tds"] = False
        state["sent_alerts"] = False

    # النطاق 0–100 صامت.
    if band == "silent":
        state["sent_tds"] = True
        state["sent_alerts"] = True

    else:
        message = (
            f"💧 قيمة TDS: {value} ppm\n"
            f"🌊 حالة الماء: {description}\n"
            f"🕒 الوقت: {now()}"
        )

        # الإرسال مستقل لكل مجموعة لمنع تكرار الرسالة
        # في المجموعة التي نجح الإرسال إليها بالفعل.
        if not state.get("sent_tds"):
            if send_message("tds", message):
                state["sent_tds"] = True
            else:
                delivery_failed = True

        if not state.get("sent_alerts"):
            if send_message("alerts", message):
                state["sent_alerts"] = True
            else:
                delivery_failed = True

    save_state(state, cipher)

    print(
        f"CHECK_FINISHED band={band} "
        f"same_count={state['same_count']}"
    )

    if delivery_failed:
        sys.exit(1)


if __name__ == "__main__":
    try:
        monitor()
    except Exception as error:
        send_message(
            "alerts",
            "🚨 خطأ غير متوقع في برنامج مراقبة TDS.\n"
            f"نوع الخطأ: {type(error).__name__}\n"
            f"الوقت: {now()}",
        )
        print(f"MONITOR_FATAL_{type(error).__name__}")
        sys.exit(1)
