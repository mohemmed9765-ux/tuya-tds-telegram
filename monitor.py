"""Tuya TDS monitor with scheduled and on-demand Telegram readings."""

import hashlib
import json
import os
import re
import sys
import time
import traceback
import urllib.error
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
DEFAULT_CONTROL_URL = (
    "https://tuya-tds-scheduler.mohemmed9765.workers.dev/control-state"
)

# The Cloudflare control state is authoritative for maintenance operations.

READ_ATTEMPTS = 3
RETRY_DELAYS = (10, 20)

SUDDEN_MIN_PPM = 300
SUDDEN_MIN_PERCENT = 20.0


def now():
    return datetime.now(
        ZoneInfo("Asia/Baghdad")
    ).strftime("%Y-%m-%d %H:%M")


def read_control_state():
    """Fetch maintenance switches securely before reading Tuya."""
    secret = os.environ.get("TDS_CONTROL_SECRET", "")
    if not secret:
        raise RuntimeError("CONTROL_SECRET_MISSING")

    url = os.environ.get("TDS_CONTROL_URL", DEFAULT_CONTROL_URL)
    # Log only whether the destination was overridden; never log credentials.
    print(
        "CONTROL_ENDPOINT_DEFAULT"
        if url == DEFAULT_CONTROL_URL
        else "CONTROL_ENDPOINT_OVERRIDE"
    )
    request = urllib.request.Request(
        url,
        headers={"Authorization": f"Bearer {secret}"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            data = json.load(response)
    except urllib.error.HTTPError as error:
        # Identify the source of a 403 without printing response contents,
        # request headers, tokens, or other sensitive information.
        if error.code == 403:
            body = error.read(512).strip().lower()
            if body == b"unauthorized":
                print("CONTROL_403_WORKER_UNAUTHORIZED")
            elif b"error 1020" in body or b"access denied" in body:
                print("CONTROL_403_ACCESS_DENIED_PAGE")
            elif b"<html" in body or b"<!doctype html" in body:
                print("CONTROL_403_HTML_PAGE")
            else:
                print("CONTROL_403_OTHER_RESPONSE")
            content_type = error.headers.get("Content-Type", "").lower()
            if "text/html" in content_type:
                print("CONTROL_403_CONTENT_TYPE_HTML")
            elif "text/plain" in content_type:
                print("CONTROL_403_CONTENT_TYPE_PLAIN")
            else:
                print("CONTROL_403_CONTENT_TYPE_OTHER")
        raise RuntimeError(f"CONTROL_HTTP_{int(error.code)}") from None
    except (urllib.error.URLError, TimeoutError):
        raise RuntimeError("CONTROL_NETWORK_ERROR") from None
    except ValueError:
        raise RuntimeError("CONTROL_RESPONSE_INVALID") from None
    except Exception:
        raise RuntimeError("CONTROL_STATUS_UNAVAILABLE") from None

    if not isinstance(data, dict) or not all(
        isinstance(data.get(key), bool)
        for key in ("system_paused", "tds_muted")
    ):
        raise RuntimeError("CONTROL_STATUS_INVALID")
    return data


def mark_system_paused_output():
    """Tell GitHub Actions not to ping Healthchecks for a skipped run."""
    output_path = os.environ.get("GITHUB_OUTPUT")
    if output_path:
        with open(output_path, "a", encoding="utf-8") as output:
            output.write("system_paused=true\n")


def run_link():
    """Construct a safe link without using credentials or exception text."""
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    if re.fullmatch(r"[\w.-]+/[\w.-]+", repository) and run_id.isdigit():
        return f"https://github.com/{repository}/actions/runs/{run_id}"
    return "غير متاح"


def failure_location(error):
    """Report filename, function and line; never export source or locals."""
    frames = traceback.extract_tb(error.__traceback__)
    if not frames:
        return "غير محدد", "غير محددة", "غير محدد"
    app_frames = [f for f in frames if Path(f.filename).name == "monitor.py"]
    frame = (app_frames or frames)[-1]
    return Path(frame.filename).name, frame.name, frame.lineno


def error_guidance(kind):
    guidance = {
        "SIGN_INVALID": "تعذر قبول تفويض Tuya؛ تحقق من الجلسة أو أعد الربط إذا استمر الخطأ.",
        "TOKEN_EXPIRED": "فشل تجديد رمز Tuya؛ تحقق من الجلسة ورمز التجديد.",
        "RATE_LIMIT": "قيود على طلبات Tuya؛ انتظر حتى موعد الفحص القادم.",
        "PERMISSION_DENIED": "طلب Tuya مرفوض؛ راجع صلاحيات الحساب والتفويض.",
        "TIMEOUT": "انتهت مهلة الاتصال؛ تحقق من الشبكة وخدمات Tuya.",
        "TDS_SENSOR_NOT_FOUND": "لا يظهر مستشعر TDS في الحساب المرتبط.",
        "MULTIPLE_TDS_SENSORS": "ظهر أكثر من مستشعر؛ يجب تحديد المستشعر المقصود.",
        "TDS_SENSOR_OFFLINE": "المستشعر غير متصل؛ تحقق من الكهرباء والاتصال بالشبكة.",
        "INVALID_TDS": "أعاد المستشعر قراءة غير صالحة؛ تحقق من بيانات الجهاز.",
    }
    return guidance.get(kind, "راجع رابط التشغيل في GitHub لتحديد السبب التقني.")


def diagnostic_message(error, attempts=None, state=None):
    code, kind = safe_error_details(error)
    filename, function, line = failure_location(error)
    last_value = state.get("last_value") if state else None
    last_time = state.get("last_success_at") if state else None
    return (
        "🚨 تقرير عطل نظام TDS\n"
        f"النوع: {kind}\n"
        f"رمز الخطأ: {code}\n"
        f"الاستثناء: {type(error).__name__}\n"
        f"الملف: {filename}\n"
        f"الدالة: {function}\n"
        f"السطر: {line}\n"
        f"المحاولات: {attempts if attempts is not None else 'غير محدد'}\n"
        f"آخر قراءة ناجحة: {last_value if last_value is not None else 'غير متاحة'} ppm\n"
        f"وقتها: {last_time or 'غير متاح'}\n"
        f"وقت اكتشاف العطل: {now()}\n"
        f"الإجراء المقترح: {error_guidance(kind)}\n"
        f"تفاصيل التشغيل: {run_link()}"
    )


def send_message(group, message):
    try:
        # Refresh control just before delivery: maintenance can start mid-run.
        control = read_control_state()
    except Exception:
        print("TELEGRAM_SEND_SKIPPED_CONTROL_UNAVAILABLE")
        return False

    if control["system_paused"] or (group == "tds" and control["tds_muted"]):
        # A maintenance mute is an intentional skip, not a Telegram failure.
        print(f"TELEGRAM_SEND_SKIPPED_MAINTENANCE_{group.upper()}")
        return True

    try:
        token = os.environ["TELEGRAM_BOT_TOKEN"]

        group_key = (
            "TELEGRAM_TDS_GROUP_ID"
            if group == "tds"
            else "TELEGRAM_ALERTS_GROUP_ID"
        )

        data = urllib.parse.urlencode({
            "chat_id": os.environ[group_key],
            "text": message,
        }).encode("utf-8")

        request = urllib.request.Request(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data=data,
            method="POST",
        )

        with urllib.request.urlopen(
            request, timeout=25
        ) as response:
            result = json.load(response)

        return result.get("ok") is True

    except Exception:
        print(f"TELEGRAM_SEND_FAILED_{group.upper()}")
        return False


def save_state(state, cipher):
    content = json.dumps(
        state,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")

    temp = STATE_FILE.with_suffix(".enc.tmp")
    temp.write_bytes(cipher.encrypt(content))
    temp.replace(STATE_FILE)


def load_state():
    cipher = Fernet(
        os.environ["TUYA_FERNET_KEY"].encode("utf-8")
    )

    bootstrap_json = os.environ["TUYA_BOOTSTRAP_SESSION"]

    fingerprint = hashlib.sha256(
        bootstrap_json.encode("utf-8")
    ).hexdigest()

    if STATE_FILE.exists():
        state = json.loads(
            cipher.decrypt(STATE_FILE.read_bytes())
        )
    else:
        state = {
            "session": json.loads(bootstrap_json),
            "bootstrap_fingerprint": fingerprint,
        }

    session_changed = False

    if state.get("bootstrap_fingerprint") != fingerprint:
        fresh = json.loads(bootstrap_json)

        required = (
            "user_code",
            "terminal_id",
            "endpoint",
            "token_info",
        )

        if not isinstance(fresh, dict) or any(
            item not in fresh for item in required
        ):
            raise RuntimeError("INVALID_BOOTSTRAP_SESSION")

        state["session"] = fresh
        state["bootstrap_fingerprint"] = fingerprint
        session_changed = True

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
        "pending_sudden_alert": None,
    }

    for key, value in defaults.items():
        state.setdefault(key, value)

    if session_changed:
        save_state(state, cipher)
        print("TUYA_SESSION_UPDATED_FROM_SECRET")

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

    # Do not call manager.unload().
    # It may invalidate the Tuya terminal token.
    manager.update_device_cache()

    devices = [
        device
        for device in manager.device_map.values()
        if "tds_in" in (device.status or {})
    ]

    if len(devices) != 1:
        raise RuntimeError(
            "TDS_SENSOR_NOT_FOUND"
            if not devices
            else "MULTIPLE_TDS_SENSORS"
        )

    device = devices[0]

    if not device.online:
        raise RuntimeError("TDS_SENSOR_OFFLINE")

    raw = device.status["tds_in"]

    if raw is None or isinstance(raw, bool):
        raise RuntimeError("INVALID_TDS")

    try:
        value = float(raw)
    except (ValueError, TypeError) as error:
        raise RuntimeError("INVALID_TDS") from error

    if not value.is_integer() or value < 0:
        raise RuntimeError("INVALID_TDS")

    return int(value)


def read_tds_with_retries(state, cipher):
    last_error = None

    for attempt in range(1, READ_ATTEMPTS + 1):
        try:
            value = read_tds(state, cipher)
            print(f"TUYA_READ_SUCCESS_ATTEMPT={attempt}")
            return value

        except Exception as error:
            last_error = error
            print(
                f"TUYA_READ_ATTEMPT_FAILED={attempt} "
                f"TYPE={type(error).__name__}"
            )

            if attempt < READ_ATTEMPTS:
                delay = RETRY_DELAYS[attempt - 1]
                print(f"TUYA_RETRY_WAIT_SECONDS={delay}")
                time.sleep(delay)

    raise last_error


def classify(value):
    if value < 100:
        return "silent", ""

    if value <= 1100:
        return (
            "very_sweet",
            "\u0627\u0644\u0645\u0627\u0621 \u062d\u0644\u0648 \u062c\u062f\u0627",
        )

    if value <= 2100:
        return (
            "sweet",
            "\u0627\u0644\u0645\u0627\u0621 \u062d\u0644\u0648",
        )

    if value <= 2800:
        return (
            "medium",
            "\u0627\u0644\u0645\u0627\u0621 \u0645\u062a\u0648\u0633\u0637 \u0627\u0644\u0645\u0644\u0648\u062d\u0629",
        )

    if value <= 3500:
        return (
            "salty",
            "\u0627\u0644\u0645\u0627\u0621 \u0645\u0627\u0644\u062d",
        )

    return (
        "very_salty",
        "\u0627\u0644\u0645\u0627\u0621 \u0645\u0627\u0644\u062d \u062c\u062f\u0627",
    )


def safe_error_details(error):
    message = str(error).lower()

    if "sign invalid" in message:
        kind = "SIGN_INVALID"
    elif "token expired" in message or "token is expired" in message:
        kind = "TOKEN_EXPIRED"
    elif "rate limit" in message or "qps" in message:
        kind = "RATE_LIMIT"
    elif "permission deny" in message:
        kind = "PERMISSION_DENIED"
    elif "timeout" in message or "timed out" in message:
        kind = "TIMEOUT"
    elif str(error) in {
        "TDS_SENSOR_NOT_FOUND", "MULTIPLE_TDS_SENSORS",
        "TDS_SENSOR_OFFLINE", "INVALID_TDS",
    }:
        kind = str(error)
    else:
        kind = type(error).__name__

    # Restrict extracted error codes; never echo long numeric credentials.
    match = re.search(r"(?<![\w-])-?\d{4,7}(?!\w)", message)
    code = match.group(0) if match else "UNKNOWN"

    return code, kind


def sudden_change(previous, current):
    if previous is None:
        return None

    previous = int(previous)
    current = int(current)

    difference = current - previous
    absolute_difference = abs(difference)

    if previous == 0:
        # Percentage relative to zero is undefined.
        return None

    percent = absolute_difference / previous * 100.0

    if (
        absolute_difference >= SUDDEN_MIN_PPM
        and percent >= SUDDEN_MIN_PERCENT
    ):
        return {
            "previous": previous,
            "current": current,
            "difference": difference,
            "percent": percent,
            "detected_at": now(),
            "sent_tds": False,
            "sent_alerts": False,
        }

    return None


def sudden_change_message(alert):
    direction = (
        "\u0627\u0631\u062a\u0641\u0627\u0639"
        if alert["difference"] > 0
        else "\u0627\u0646\u062e\u0641\u0627\u0636"
    )

    signed_difference = f"{alert['difference']:+d}"

    signed_percent = (
        f"{alert['percent']:+.2f}"
        if alert["difference"] > 0
        else f"{-alert['percent']:+.2f}"
    )

    return (
        "\U0001f6a8 \u062a\u0646\u0628\u064a\u0647: \u062a\u063a\u064a\u0631 \u0645\u0641\u0627\u062c\u0626 \u0641\u064a TDS!\n"
        f"\U0001f4a7 \u0627\u0644\u0642\u0631\u0627\u0621\u0629 \u0627\u0644\u0633\u0627\u0628\u0642\u0629: {alert['previous']} ppm\n"
        f"\U0001f4a7 \u0627\u0644\u0642\u0631\u0627\u0621\u0629 \u0627\u0644\u062d\u0627\u0644\u064a\u0629: {alert['current']} ppm\n"
        f"\U0001f4c8 \u0645\u0642\u062f\u0627\u0631 \u0627\u0644\u062a\u063a\u064a\u0631: {signed_difference} ppm\n"
        f"\U0001f4ca \u0646\u0633\u0628\u0629 \u0627\u0644\u062a\u063a\u064a\u0631: {signed_percent}%\n"
        f"\u0627\u062a\u062c\u0627\u0647 \u0627\u0644\u062a\u063a\u064a\u0631: {direction}\n"
        f"\U0001f552 \u0648\u0642\u062a \u0627\u0644\u0641\u062d\u0635: {alert['detected_at']}"
    )


def deliver_pending_sudden_alert(state):
    alert = state.get("pending_sudden_alert")

    if not alert:
        return True

    message = sudden_change_message(alert)
    success = True

    if not alert["sent_tds"]:
        if send_message("tds", message):
            alert["sent_tds"] = True
        else:
            success = False

    if not alert["sent_alerts"]:
        if send_message("alerts", message):
            alert["sent_alerts"] = True
        else:
            success = False

    if alert["sent_tds"] and alert["sent_alerts"]:
        state["pending_sudden_alert"] = None
    else:
        state["pending_sudden_alert"] = alert

    return success


def monitor():
    control = read_control_state()
    if control["system_paused"]:
        mark_system_paused_output()
        print("SYSTEM_PAUSED_MAINTENANCE_NO_READING")
        return

    state, cipher = load_state()
    delivery_failed = False

    manual_read = os.environ.get("FORCE_READ") == "1"

    if state.get("message_encoding_version") != 2:
        state["message_encoding_version"] = 2
        state["sent_tds"] = False
        state["sent_alerts"] = False

    try:
        value = read_tds_with_retries(state, cipher)

    except Exception as error:
        if not manual_read:
            state["same_count"] = 0

        code, kind = safe_error_details(error)

        print(f"TUYA_ERROR_CODE={code}")
        print(f"TUYA_ERROR_KIND={kind}")

        if not state["read_error_sent"]:
            message = diagnostic_message(error, READ_ATTEMPTS, state)

            if send_message("alerts", message):
                state["read_error_sent"] = True
            else:
                delivery_failed = True

        save_state(state, cipher)
        print("SENSOR_READ_FAILED")
        sys.exit(3 if delivery_failed else 2)

    if state["read_error_sent"]:
        message = (
            "✅ تمت استعادة نظام قراءة TDS بعد العطل.\n"
            f"\u0627\u0644\u0642\u0631\u0627\u0621\u0629 \u0627\u0644\u062d\u0627\u0644\u064a\u0629: {value} ppm\n"
            f"\u0627\u0644\u0648\u0642\u062a: {now()}"
        )

        if send_message("alerts", message):
            state["read_error_sent"] = False
        else:
            delivery_failed = True

    # Manual reading:
    # Send result to maintenance group only.
    # Do not change automatic counters or last_value.
    if manual_read:
        band, description = classify(value)

        if band == "silent":
            description = (
                "\u0627\u0644\u0645\u0627\u0621 \u0636\u0645\u0646 \u0627\u0644\u0646\u0637\u0627\u0642 "
                "0-99 ppm"
            )

        message = (
            "\U0001f4a7 \u0646\u062a\u064a\u062c\u0629 \u0641\u062d\u0635 TDS \u0627\u0644\u064a\u062f\u0648\u064a\n"
            f"\U0001f4a7 \u0642\u064a\u0645\u0629 TDS: {value} ppm\n"
            f"\U0001f30a \u062d\u0627\u0644\u0629 \u0627\u0644\u0645\u0627\u0621: {description}\n"
            f"\U0001f552 \u0648\u0642\u062a \u0627\u0644\u0641\u062d\u0635: {now()}"
        )

        if not send_message("alerts", message):
            delivery_failed = True

        save_state(state, cipher)

        print(f"MANUAL_CHECK_FINISHED band={band}")

        if delivery_failed:
            sys.exit(3)

        return

    # Automatic monitoring:
    previous_value = state["last_value"]

    # First retry any pending sudden-change alert.
    if not deliver_pending_sudden_alert(state):
        delivery_failed = True

    # Compare the current automatic reading with
    # the previous successful automatic reading.
    new_alert = sudden_change(previous_value, value)

    if new_alert:
        print(
            "SUDDEN_CHANGE_DETECTED "
            f"previous={previous_value} current={value}"
        )

        # Preserve an older undelivered alert.
        if state.get("pending_sudden_alert") is None:
            state["pending_sudden_alert"] = new_alert

            if not deliver_pending_sudden_alert(state):
                delivery_failed = True

        else:
            print("SUDDEN_CHANGE_PENDING_PREVIOUS_ALERT")

    # Count identical successful automatic readings.
    if previous_value == value:
        state["same_count"] += 1
    else:
        state["same_count"] = 1

    if state["stuck_alert_sent"] and value != state["stuck_value"]:
        message = (
            "\u2705 \u0627\u0646\u062a\u0647\u062a \u062d\u0627\u0644\u0629 \u062b\u0628\u0627\u062a \u0642\u0631\u0627\u0621\u0629 TDS.\n"
            f"\u0627\u0644\u0642\u064a\u0645\u0629 \u0627\u0644\u0633\u0627\u0628\u0642\u0629: {state['stuck_value']} ppm\n"
            f"\u0627\u0644\u0642\u064a\u0645\u0629 \u0627\u0644\u062d\u0627\u0644\u064a\u0629: {value} ppm\n"
            f"\u0627\u0644\u0648\u0642\u062a: {now()}"
        )

        if send_message("alerts", message):
            state["stuck_alert_sent"] = False
            state["stuck_value"] = None
        else:
            delivery_failed = True

    if state["same_count"] > 10 and not state["stuck_alert_sent"]:
        message = (
            "\u26a0\ufe0f \u062a\u0646\u0628\u064a\u0647: \u0642\u064a\u0645\u0629 TDS \u062b\u0627\u0628\u062a\u0629!\n"
            f"\u0627\u0644\u0642\u064a\u0645\u0629: {value} ppm\n"
            f"\u0639\u062f\u062f \u0627\u0644\u0641\u062d\u0648\u0635\u0627\u062a \u0627\u0644\u0645\u062a\u0637\u0627\u0628\u0642\u0629: {state['same_count']}\n"
            "\u064a\u0631\u062c\u0649 \u0627\u0644\u062a\u0623\u0643\u062f \u0645\u0646 \u0623\u0646 \u0627\u0644\u0645\u0633\u062a\u0634\u0639\u0631 \u064a\u0639\u0645\u0644 \u0628\u0635\u0648\u0631\u0629 \u0635\u062d\u064a\u062d\u0629.\n"
            f"\u0627\u0644\u0648\u0642\u062a: {now()}"
        )

        if send_message("alerts", message):
            state["stuck_alert_sent"] = True
            state["stuck_value"] = value
        else:
            delivery_failed = True

    state["last_value"] = value
    state["last_success_at"] = now()

    band, description = classify(value)

    # Send notifications when the salinity category changes.
    if band != state["band"]:
        state["band"] = band
        state["sent_tds"] = False
        state["sent_alerts"] = False

    # Keep the 0-99 ppm automatic range silent.
    if band == "silent":
        state["sent_tds"] = True
        state["sent_alerts"] = True

    else:
        message = (
            f"\U0001f4a7 \u0642\u064a\u0645\u0629 TDS: {value} ppm\n"
            f"\U0001f30a \u062d\u0627\u0644\u0629 \u0627\u0644\u0645\u0627\u0621: {description}\n"
            f"\U0001f552 \u0627\u0644\u0648\u0642\u062a: {now()}"
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

    print(
        f"CHECK_FINISHED band={band} "
        f"same_count={state['same_count']}"
    )

    if delivery_failed:
        sys.exit(3)


if __name__ == "__main__":
    try:
        monitor()

    except SystemExit:
        raise

    except Exception as error:
        # Diagnostic whitelist: no credentials, exception messages or source.
        safe_codes = {
            "CONTROL_SECRET_MISSING", "CONTROL_NETWORK_ERROR",
            "CONTROL_RESPONSE_INVALID", "CONTROL_STATUS_UNAVAILABLE",
            "CONTROL_STATUS_INVALID", "INVALID_BOOTSTRAP_SESSION",
        }
        reason = str(error)
        if isinstance(error, RuntimeError) and (
            reason in safe_codes
            or re.fullmatch(r"CONTROL_HTTP_[1-5][0-9]{2}", reason)
        ):
            print(f"MONITOR_FATAL_{reason}")
        else:
            print(f"MONITOR_FATAL_{type(error).__name__}")

        filename, function, line = failure_location(error)
        if filename in {"monitor.py", "monitor_diagnostic.py"}:
            print(f"MONITOR_FATAL_LOCATION_{function}_LINE_{line}")

        if not reason.startswith("CONTROL_"):
            send_message("alerts", diagnostic_message(error))

        sys.exit(1)