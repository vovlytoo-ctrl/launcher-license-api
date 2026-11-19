from datetime import datetime, timedelta
import json
import os
from threading import Lock
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()
DB_PATH = "keys_db.json"
DB_LOCK = Lock()


class KeyRequest(BaseModel):
    key: str
    hwid: str


def load_db():
    if not os.path.isfile(DB_PATH):
        return {"keys": []}
    with open(DB_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def save_db(data):
    with open(DB_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def verify_entry(item: dict, hwid: str):
    if item.get("revoked"):
        return False, "KEY REVOKED"
    if item.get("hwid") and item.get("hwid") != hwid:
        return False, "HWID MISMATCH"
    expires_at = item.get("expires_at")
    if not expires_at:
        return False, "NOT ACTIVATED"
    exp = datetime.fromisoformat(expires_at)
    rem = exp - datetime.now()
    if rem.total_seconds() <= 0:
        return False, "KEY EXPIRED"
    return True, f"ACTIVE: {rem.days}d {rem.seconds // 3600}h left"


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/api/activate")
def activate_key(req: KeyRequest):
    key = req.key.strip().upper()
    hwid = req.hwid.strip().upper()
    if not key or not hwid:
        return {"ok": False, "message": "ENTER KEY"}

    with DB_LOCK:
        db = load_db()
        for item in db.get("keys", []):
            if str(item.get("key", "")).strip().upper() == key:
                if item.get("revoked"):
                    return {"ok": False, "message": "KEY REVOKED"}
                if item.get("hwid") and item.get("hwid") != hwid:
                    return {"ok": False, "message": "HWID MISMATCH"}

                if not item.get("expires_at"):
                    days = int(item.get("days", 1))
                    now = datetime.now()
                    item["activated_at"] = now.isoformat()
                    item["expires_at"] = (now + timedelta(days=days)).isoformat()
                if not item.get("hwid"):
                    item["hwid"] = hwid

                save_db(db)
                ok, msg = verify_entry(item, hwid)
                return {"ok": ok, "message": msg}

    return {"ok": False, "message": "INVALID KEY"}


@app.post("/api/check")
def check_key(req: KeyRequest):
    key = req.key.strip().upper()
    hwid = req.hwid.strip().upper()
    if not key or not hwid:
        return {"ok": False, "message": "KEY REQUIRED"}

    with DB_LOCK:
        db = load_db()
        for item in db.get("keys", []):
            if str(item.get("key", "")).strip().upper() == key:
                ok, msg = verify_entry(item, hwid)
                return {"ok": ok, "message": msg}

    return {"ok": False, "message": "KEY REQUIRED"}