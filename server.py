import base64
from datetime import datetime, timedelta
import json
import os
import secrets
import string
from threading import Lock

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
import requests

app = FastAPI()
DB_PATH = "keys_db.json"
DB_LOCK = Lock()


class KeyRequest(BaseModel):
    key: str
    hwid: str


class CreateKeyRequest(BaseModel):
    days: int = 30


def _generate_key() -> str:
    alphabet = string.ascii_uppercase + string.digits
    part1 = "".join(secrets.choice(alphabet) for _ in range(2))
    part2 = "".join(secrets.choice(alphabet) for _ in range(4))
    part3 = "".join(secrets.choice(alphabet) for _ in range(4))
    return f"ROB-{part1}-{part2}-{part3}"


def _github_configured() -> bool:
    return bool(os.getenv("GITHUB_TOKEN", "").strip())


def _github_headers() -> dict:
    token = os.getenv("GITHUB_TOKEN", "").strip()
    if not token:
        raise HTTPException(status_code=500, detail="GITHUB_TOKEN is not configured")
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
    }


def _load_keys_from_github() -> tuple[dict, str | None]:
    repo = os.getenv("GITHUB_REPO", "vovlytoo-ctrl/launcher-license-api").strip()
    branch = os.getenv("GITHUB_BRANCH", "main").strip()
    url = f"https://api.github.com/repos/{repo}/contents/{DB_PATH}"
    resp = requests.get(
        url,
        headers=_github_headers(),
        params={"ref": branch},
        timeout=15,
    )
    if resp.status_code != 200:
        raise HTTPException(status_code=500, detail=f"GitHub GET error: {resp.text}")
    data = resp.json()
    content_bytes = base64.b64decode(data["content"])
    parsed = json.loads(content_bytes.decode("utf-8"))
    if not isinstance(parsed, dict) or not isinstance(parsed.get("keys"), list):
        parsed = {"keys": []}
    return parsed, data.get("sha")


def _save_keys_to_github(db_obj: dict, sha: str | None, message: str) -> None:
    repo = os.getenv("GITHUB_REPO", "vovlytoo-ctrl/launcher-license-api").strip()
    branch = os.getenv("GITHUB_BRANCH", "main").strip()
    url = f"https://api.github.com/repos/{repo}/contents/{DB_PATH}"
    encoded = base64.b64encode(
        json.dumps(db_obj, indent=2, ensure_ascii=False).encode("utf-8")
    ).decode("utf-8")
    payload = {
        "message": message,
        "content": encoded,
        "branch": branch,
    }
    if sha:
        payload["sha"] = sha
    resp = requests.put(url, headers=_github_headers(), json=payload, timeout=15)
    if resp.status_code not in (200, 201):
        raise HTTPException(status_code=500, detail=f"GitHub PUT error: {resp.text}")


def load_local_db():
    if not os.path.isfile(DB_PATH):
        return {"keys": []}
    with open(DB_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def save_local_db(data):
    with open(DB_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def load_db_state() -> tuple[dict, str | None]:
    if _github_configured():
        return _load_keys_from_github()
    return load_local_db(), None


def save_db_state(db_obj: dict, sha: str | None, message: str) -> None:
    save_local_db(db_obj)
    if _github_configured():
        _save_keys_to_github(db_obj, sha, message)


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
        db, sha = load_db_state()
        for item in db.get("keys", []):
            if str(item.get("key", "")).strip().upper() == key:
                if item.get("revoked"):
                    return {"ok": False, "message": "KEY REVOKED"}
                if item.get("hwid") and item.get("hwid") != hwid:
                    return {"ok": False, "message": "HWID MISMATCH"}

                changed = False
                if not item.get("expires_at"):
                    days = int(item.get("days", 1))
                    now = datetime.now()
                    item["activated_at"] = now.isoformat()
                    item["expires_at"] = (now + timedelta(days=days)).isoformat()
                    changed = True
                if not item.get("hwid"):
                    item["hwid"] = hwid
                    changed = True

                if changed:
                    save_db_state(db, sha, f"Activate key {key}")
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
        db, _ = load_db_state()
        for item in db.get("keys", []):
            if str(item.get("key", "")).strip().upper() == key:
                ok, msg = verify_entry(item, hwid)
                return {"ok": ok, "message": msg}

    return {"ok": False, "message": "KEY REQUIRED"}


@app.post("/admin/create-key")
def admin_create_key(
    body: CreateKeyRequest,
    x_admin_token: str | None = Header(default=None),
):
    expected_token = os.getenv("ADMIN_TOKEN", "").strip()
    if not expected_token or x_admin_token != expected_token:
        raise HTTPException(status_code=401, detail="Invalid admin token")

    days = max(1, min(body.days, 3650))
    with DB_LOCK:
        db_obj, sha = _load_keys_from_github()
        existing_keys = {item.get("key") for item in db_obj["keys"]}

        new_key = _generate_key()
        while new_key in existing_keys:
            new_key = _generate_key()

        record = {
            "key": new_key,
            "days": days,
            "hwid": None,
            "expires_at": None,
            "revoked": False,
        }
        db_obj["keys"].append(record)
        save_db_state(db_obj, sha, f"Add license key {new_key}")

    return {"ok": True, "key": new_key, "days": days}
