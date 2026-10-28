"""Tuya TDS monitor with scheduled and on-demand Telegram readings."""

import hashlib
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
    return datetime.now(
        ZoneInfo("Asia/Baghdad")
    ).strftime("%Y-%m-%d %H:%M")


def send_message(group, message):
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

    # Never call manager.unload():
    # it may invalidate the reusable Tuya terminal token.
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


def classify(value):
    if value <= 100:
        return "silent", ""

    if value <= 700:
        return "very_sweet", "\u0627\u0644\u0645\u0627\u0621 \u062c\u062f\u0627\u064b \u062d\u0644\u0648"

    if value <= 1200:
        return "sweet", "\u0627\u0644\u0645\u0627\u0621 \u062d\u0644\u0648"

    if value <= 2000:
        return "medium", "\u0627\u0644\u0645\u0627\u0621 \u0645\u062a\u0648\u0633\u0637 \u0627\u0644\u0645\u0644\u0648\u062d\u0629"

    if value <= 3200:
        return "salty", "\u0627\u0644\u0645\u0627\u0621 \u0645\u0627\u0644\u062d"

    return "very_salty", "\u0627\u0644\u0645\u0627\u0621 \u0634\u062f\u064a\u062f \u0627\u0644\u0645\u0644\u0648\u062d\u0629"


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
    else:
        kind = type(error).__name__

    match = re.search(r"(?<!\d)-?\d{4,}(?!\d)", message)
    code = match.group(0) if match else "UNKNOWN"

    return code, kind


def monitor():
    state, cipher = load_state()
    delivery_failed = False
    manual_read = os.environ.get("FORCE_READ") == "1"

    if state.get("message_encoding_version") != 2:
        state["message_encoding_version"] = 2
        state["sent_tds"] = False
        state["sent_alerts"] = False

    try:
        value = read_tds(state, cipher)

    except Exception as error:
        if not manual_read:
            state["same_count"] = 0

        code, kind = safe_error_details(error)

        print(f"TUYA_ERROR_CODE={code}")
        print(f"TUYA_ERROR_KIND={kind}")

        if not state["read_error_sent"]:
            message = (
                "\u26a0\ufe0f \u0639\u0637\u0644 \u0641\u064a \u0645\u0631\u0627\u0642\u0628\u0629 TDS\n"
                "\u062a\u0639\u0630\u0631\u062a \u0642\u0631\u0627\u0621\u0629 \u0627\u0644\u0645\u0633\u062a\u0634\u0639\u0631 \u0639\u0628\u0631 Tuya.\n"
                f"\u0646\u0648\u0639 \u0627\u0644\u062e\u0637\u0623: {kind}\n"
                f"\u0631\u0645\u0632 \u0627\u0644\u062e\u0637\u0623: {code}\n"
                f"\u0622\u062e\u0631 \u0642\u0631\u0627\u0621\u0629 \u0646\u0627\u062c\u062d\u0629: {state['last_value']}\n"
                f"\u0648\u0642\u062a\u0647\u0627: {state['last_success_at']}\n"
                f"\u0648\u0642\u062a \u0627\u0643\u062a\u0634\u0627\u0641 \u0627\u0644\u0639\u0637\u0644: {now()}"
            )

            if send_message("alerts", message):
                state["read_error_sent"] = True
            else:
                delivery_failed = True

        save_state(state, cipher)
        print("SENSOR_READ_FAILED")
        sys.exit(3 if delivery_failed else 2)

    if state["read_error_sent"]:
        message = (
            "\u2705 \u062a\u0645\u062a \u0627\u0633\u062a\u0639\u0627\u062f\u0629 \u0642\u0631\u0627\u0621\u0629 \u0645\u0633\u062a\u0634\u0639\u0631 TDS.\n"
            f"\u0627\u0644\u0642\u0631\u0627\u0621\u0629 \u0627\u0644\u062d\u0627\u0644\u064a\u0629: {value} ppm\n"
            f"\u0627\u0644\u0648\u0642\u062a: {now()}"
        )

        if send_message("alerts", message):
            state["read_error_sent"] = False
        else:
            delivery_failed = True

    # On-demand reading:
    # Send a fresh result only to the maintenance group.
    # Do not affect automatic bands, counters, or last_value.
    if manual_read:
        band, description = classify(value)

        if band == "silent":
            description = (
                "\u0627\u0644\u0645\u0627\u0621 \u0636\u0645\u0646 \u0627\u0644\u0646\u0637\u0627\u0642 "
                "0-100 ppm"
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

    previous_value = state["last_value"]

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

    if band != state["band"]:
        state["band"] = band
        state["sent_tds"] = False
        state["sent_alerts"] = False

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
        print(f"MONITOR_FATAL_{type(error).__name__}")

        send_message(
            "alerts",
            "\U0001f6a8 \u062e\u0637\u0623 \u063a\u064a\u0631 \u0645\u062a\u0648\u0642\u0639 \u0641\u064a \u0628\u0631\u0646\u0627\u0645\u062c \u0645\u0631\u0627\u0642\u0628\u0629 TDS.\n"
            f"\u0646\u0648\u0639 \u0627\u0644\u062e\u0637\u0623: {type(error).__name__}\n"
            f"\u0627\u0644\u0648\u0642\u062a: {now()}",
        )

        sys.exit(1)
