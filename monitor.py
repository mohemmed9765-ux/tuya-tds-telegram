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


# ==========================================
# SETTINGS
# ==========================================

STATE_FILE = Path("tds_state.enc")
CLIENT_ID = "HA_3y9q4ak7g4ephrvke"

STABLE_READING_LIMIT = 10


def now():
    return datetime.now(
        ZoneInfo("Asia/Baghdad")
    ).strftime("%Y-%m-%d %H:%M")


# ==========================================
# TELEGRAM
# ==========================================

def send_message(group, message):
    try:
        token = os.environ["TELEGRAM_BOT_TOKEN"]

        if group == "tds":
            chat_id = os.environ["TELEGRAM_TDS_GROUP_ID"]
        else:
            chat_id = os.environ["TELEGRAM_ALERTS_GROUP_ID"]

        data = urllib.parse.urlencode({
            "chat_id": chat_id,
            "text": message
        }).encode("utf-8")

        request = urllib.request.Request(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data=data,
            method="POST"
        )

        with urllib.request.urlopen(
            request, timeout=25
        ) as response:
            result = json.load(response)

        return result.get("ok") is True

    except Exception:
        print(f"TELEGRAM_SEND_FAILED_{group.upper()}")
        return False


# ==========================================
# ENCRYPTED STATE
# ==========================================

def save_state(state, cipher):
    content = json.dumps(
        state,
        ensure_ascii=False,
        separators=(",", ":")
    ).encode("utf-8")

    encrypted_content = cipher.encrypt(content)

    temporary_file = Path("tds_state.enc.tmp")

    temporary_file.write_bytes(encrypted_content)
    temporary_file.replace(STATE_FILE)


def load_state():
    encryption_key = os.environ["TUYA_FERNET_KEY"]

    cipher = Fernet(encryption_key.encode())

    if STATE_FILE.exists():
        encrypted_content = STATE_FILE.read_bytes()

        decrypted_content = cipher.decrypt(
            encrypted_content
        )

        state = json.loads(decrypted_content)

    else:
        session = json.loads(
            os.environ["TUYA_BOOTSTRAP_SESSION"]
        )

        state = {
            "session": session,

            "band": None,
            "sent_tds": False,
            "sent_alerts": False,

            "last_value": None,
            "last_success_at": None,

            "same_count": 0,
            "stuck_alert_sent": False,
            "stuck_value": None,

            "read_error_sent": False
        }

    return state, cipher


# ==========================================
# TUYA SESSION TOKEN REFRESH
# ==========================================

class TokenListener(SharingTokenListener):

    def __init__(self, state, cipher):
        super().__init__()

        self.state = state
        self.cipher = cipher

    def update_token(self, new_token_info):
        self.state["session"]["token_info"] = (
            new_token_info
        )

        save_state(
            self.state,
            self.cipher
        )

        print("TUYA_TOKEN_UPDATED")


# ==========================================
# READ TDS
# ==========================================

def read_tds(state, cipher):

    session = state["session"]

    manager = Manager(
        session.get("client_id", CLIENT_ID),
        session["user_code"],
        session["terminal_id"],
        session["endpoint"],
        session["token_info"],
        TokenListener(state, cipher)
    )

    try:
        manager.update_device_cache()

        devices = [
            device
            for device in manager.device_map.values()
            if "tds_in" in (device.status or {})
        ]

        if len(devices) == 0:
            raise RuntimeError("TDS_SENSOR_NOT_FOUND")

        if len(devices) > 1:
            raise RuntimeError("MULTIPLE_TDS_SENSORS")

        device = devices[0]

        if not device.online:
            raise RuntimeError("TDS_SENSOR_OFFLINE")

        raw_value = device.status["tds_in"]

        if raw_value is None:
            raise RuntimeError("TDS_VALUE_MISSING")

        if isinstance(raw_value, bool):
            raise RuntimeError("INVALID_TDS_VALUE")

        value = float(raw_value)

        if not value.is_integer():
            raise RuntimeError("INVALID_TDS_VALUE")

        if value < 0:
            raise RuntimeError("INVALID_TDS_VALUE")

        return int(value)

    finally:
        try:
            manager.unload()
        except Exception:
            pass


# ==========================================
# WATER CLASSIFICATION
# ==========================================

def classify(value):

    if value <= 100:
        return "silent", ""

    elif value <= 700:
        return "very_sweet", "الماء جداً حلو"

    elif value <= 1200:
        return "sweet", "الماء حلو"

    elif value <= 2000:
        return "medium", "الماء متوسط الملوحة"

    elif value <= 3200:
        return "salty", "الماء مالح"

    else:
        return "very_salty", "الماء شديد الملوحة"


# ==========================================
# SAFE ERROR CLASSIFICATION
# ==========================================

def classify_error(error):

    error_code = str(
        getattr(error, "error_code", "UNKNOWN")
    )

    if not error_code.lstrip("-").isdigit():
        error_code = "UNKNOWN"

    reason = str(
        getattr(error, "error_message", "")
    ).lower()

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

    return error_code, error_kind


# ==========================================
# MAIN MONITOR
# ==========================================

def monitor():

    state, cipher = load_state()

    delivery_failed = False

    # --------------------------------------
    # READ SENSOR
    # --------------------------------------

    try:
        value = read_tds(state, cipher)

    except Exception as error:

        error_code, error_kind = classify_error(error)

        print(f"TUYA_ERROR_CODE={error_code}")
        print(f"TUYA_ERROR_KIND={error_kind}")

        state["same_count"] = 0

        # Send a fault notification only once.
        if not state.get("read_error_sent"):

            message = (
                "⚠️ عطل في مراقبة TDS\n"
                "تعذرت قراءة المستشعر عبر Tuya.\n"
                f"نوع الخطأ: {type(error).__name__}\n"
                f"رمز الخطأ: {error_code}\n"
                f"تصنيف الخطأ: {error_kind}\n"
                f"آخر قراءة ناجحة: "
                f"{state.get('last_value')} ppm\n"
                f"وقتها: {state.get('last_success_at')}\n"
                f"وقت اكتشاف العطل: {now()}"
            )

            if send_message("alerts", message):
                state["read_error_sent"] = True

        save_state(state, cipher)

        print("SENSOR_READ_FAILED")

        # The GitHub job must indicate sensor failure.
        sys.exit(2)

    # --------------------------------------
    # RECOVERY AFTER CONNECTION FAILURE
    # --------------------------------------

    if state.get("read_error_sent"):

        message = (
            "✅ تمت استعادة الاتصال بمستشعر TDS.\n"
            f"القراءة الحالية: {value} ppm\n"
            f"الوقت: {now()}"
        )

        if send_message("alerts", message):
            state["read_error_sent"] = False

        else:
            delivery_failed = True

    # --------------------------------------
    # COUNT IDENTICAL READINGS
    # --------------------------------------

    previous_value = state.get("last_value")

    if previous_value == value:
        state["same_count"] = (
            state.get("same_count", 0) + 1
        )

    else:
        state["same_count"] = 1

    # --------------------------------------
    # RECOVERY FROM STUCK READING
    # --------------------------------------

    if (
        state.get("stuck_alert_sent")
        and value != state.get("stuck_value")
    ):

        message = (
            "✅ انتهت حالة ثبات قراءة TDS.\n"
            f"القيمة السابقة: "
            f"{state.get('stuck_value')} ppm\n"
            f"القيمة الحالية: {value} ppm\n"
            f"الوقت: {now()}"
        )

        if send_message("alerts", message):

            state["stuck_alert_sent"] = False
            state["stuck_value"] = None

        else:
            delivery_failed = True

    # --------------------------------------
    # STUCK READING ALERT
    # --------------------------------------

    if (
        state["same_count"] > STABLE_READING_LIMIT
        and not state.get("stuck_alert_sent")
    ):

        message = (
            "⚠️ تنبيه: قيمة TDS ثابتة!\n"
            f"القيمة: {value} ppm\n"
            f"عدد الفحوصات المتطابقة: "
            f"{state['same_count']}\n"
            "يرجى التأكد من عمل المستشعر.\n"
            f"الوقت: {now()}"
        )

        if send_message("alerts", message):

            state["stuck_alert_sent"] = True
            state["stuck_value"] = value

        else:
            delivery_failed = True

    # --------------------------------------
    # UPDATE LAST SUCCESSFUL READING
    # --------------------------------------

    state["last_value"] = value
    state["last_success_at"] = now()

    # --------------------------------------
    # CLASSIFY WATER
    # --------------------------------------

    band, description = classify(value)

    # Reset delivery status only when band changes.
    if band != state.get("band"):

        state["band"] = band

        state["sent_tds"] = False
        state["sent_alerts"] = False

    # --------------------------------------
    # SILENT RANGE: 0 - 100
    # --------------------------------------

    if band == "silent":

        state["sent_tds"] = True
        state["sent_alerts"] = True

    # --------------------------------------
    # SEND WATER STATUS
    # --------------------------------------

    else:

        message = (
            f"💧 قيمة TDS: {value} ppm\n"
            f"🌊 حالة الماء: {description}\n"
            f"🕒 الوقت: {now()}"
        )

        # First group: water readings only.
        if not state.get("sent_tds"):

            if send_message("tds", message):
                state["sent_tds"] = True

            else:
                delivery_failed = True

        # Second group: readings and faults.
        if not state.get("sent_alerts"):

            if send_message("alerts", message):
                state["sent_alerts"] = True

            else:
                delivery_failed = True

    # --------------------------------------
    # SAVE ENCRYPTED STATE
    # --------------------------------------

    save_state(state, cipher)

    print(f"TDS_VALUE={value}")
    print(f"TDS_BAND={band}")
    print(f"SAME_COUNT={state['same_count']}")
    print("CHECK_FINISHED")

    if delivery_failed:
        print("MESSAGE_DELIVERY_FAILED")
        sys.exit(1)


# ==========================================
# PROGRAM ENTRY
# ==========================================

if __name__ == "__main__":

    try:
        monitor()

    except Exception as error:

        message = (
            "🚨 خطأ غير متوقع في برنامج مراقبة TDS.\n"
            f"نوع الخطأ: {type(error).__name__}\n"
            f"الوقت: {now()}"
        )

        send_message("alerts", message)

        print(
            f"MONITOR_FATAL_{type(error).__name__}"
        )

        sys.exit(1)