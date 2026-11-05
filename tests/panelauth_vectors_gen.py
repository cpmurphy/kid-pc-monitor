"""Generate the golden web-panel auth vectors shared by Python and Go.

A snapshot of the parent panel's password handling, written to
``testdata/panelauth/vectors.json``:

* werkzeug's ``check_password_hash`` on scrypt and pbkdf2 hashes (the format
  ``web_panel_auth.json`` stores), and the exact hash strings
  ``generate_password_hash`` builds for fixed salts;
* the auth-file helpers in ``web_panel`` (which records count as a configured
  password, the session secret key, and the JSON ``save_password`` writes);
* ``web_panel.is_local_path``, the login "next" redirect check.

``go/panel/auth`` must reproduce every case; ``tests/test_panelauth_vectors.py``
fails when the file is stale.

    python tests/panelauth_vectors_gen.py          # rewrite the vectors file
    python tests/panelauth_vectors_gen.py --check  # exit 1 if the file is stale

Hash cases werkzeug rejects by raising (an unknown method, malformed scrypt
parameters) are recorded as ``"error"``; the panel treats them as a wrong
password.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from werkzeug.security import _hash_internal, check_password_hash

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from kid_pc_monitor import web_panel as wp  # noqa: E402

VECTORS_PATH = ROOT / "testdata" / "panelauth" / "vectors.json"

PASSWORDS = ["supersecret1", "", "pässwörd ✓", "with $ and : inside", " padded "]

# (method, salt) pairs; generate_password_hash uses a random 16-char salt.
GENERATE_CASES: list[tuple[str, str]] = [
    ("scrypt", "abcdefghijklmnop"),
    ("scrypt:32768:8:1", "Z9y8X7w6V5u4T3s2"),
    ("scrypt:16384:8:1", "saltsaltsaltsalt"),
    ("scrypt:1024:1:1", "s"),
    ("scrypt:2048:2:2", "0123456789ABCDEF"),
    ("pbkdf2:sha256:1000", "abcdefghijklmnop"),
    ("pbkdf2:sha256:600000", "Pq2Rs3Tu4Vw5Xy6Z"),
    ("pbkdf2:sha1:2000", "ABCDEFGHIJKLMNOP"),
    ("pbkdf2:sha512:1000", "abcdefghijklmnop"),
    ("pbkdf2:sha224:1000", "abcdefghijklmnop"),
    ("pbkdf2:sha384:1000", "abcdefghijklmnop"),
    ("pbkdf2:sha3_256:1000", "abcdefghijklmnop"),
    ("pbkdf2:md5:1000", "abcdefghijklmnop"),
]


def full_hash(method: str, salt: str, password: str) -> str:
    hashval, method_out = _hash_internal(method, salt, password)
    return f"{method_out}${salt}${hashval}"


def generate_cases() -> list[dict[str, Any]]:
    out = []
    for method, salt in GENERATE_CASES:
        # Real-strength parameters are slow; one password is enough for them.
        slow = method in ("scrypt", "scrypt:32768:8:1", "pbkdf2:sha256:600000")
        for password in PASSWORDS[:1] if slow else PASSWORDS:
            out.append(
                {
                    "method": method,
                    "salt": salt,
                    "password": password,
                    "hash": full_hash(method, salt, password),
                }
            )
    return out


def check_cases() -> list[dict[str, Any]]:
    good = full_hash("scrypt:1024:1:1", "abcdefghijklmnop", "supersecret1")
    pb = full_hash("pbkdf2:sha256:1000", "abcdefghijklmnop", "supersecret1")
    method, salt, hexval = good.split("$")
    pb_method, pb_salt, pb_hex = pb.split("$")
    cases: list[tuple[str, str]] = [
        (good, "supersecret1"),
        (good, "supersecret2"),
        (good, ""),
        (good, "Supersecret1"),
        (pb, "supersecret1"),
        (pb, "supersecret1 "),
        (full_hash("scrypt", "abcdefghijklmnop", "pässwörd ✓"), "pässwörd ✓"),
        (full_hash("scrypt", "abcdefghijklmnop", "pässwörd ✓"), "passwörd ✓"),
        (full_hash("pbkdf2:sha1:1000", "x$y", "pw"), "pw"),
        (f"{method}${salt}${hexval.upper()}", "supersecret1"),
        (f"{method}${salt}${hexval[:-2]}", "supersecret1"),
        (f"{method}${salt}${hexval}00", "supersecret1"),
        (f"{method}${salt}x${hexval}", "supersecret1"),
        (f"{pb_method}${pb_salt}${pb_hex}$extra", "supersecret1"),
        (f"{method}${salt}", "supersecret1"),
        (f"{method}{salt}{hexval}", "supersecret1"),
        ("", "supersecret1"),
        ("$$", ""),
        ("scrypt$abcdefghijklmnop$" + hexval, "supersecret1"),
        (f"scrypt:1024:1${salt}${hexval}", "supersecret1"),
        (f"scrypt:1024:1:x${salt}${hexval}", "supersecret1"),
        (f"scrypt:1000:1:1${salt}${hexval}", "supersecret1"),
        # Below OpenSSL's memory floor for werkzeug's maxmem=132*n*r*p.
        (full_hash("scrypt:128:1:1", "abcdefghijklmnop", "pw"), "pw"),
        # A correct digest werkzeug still refuses (hashlib's own default maxmem
        # allows it), so ignoring the floor would wrongly accept it.
        (
            "scrypt:64:1:1$abcdefghijklmnop$"
            + hashlib.scrypt(b"pw", salt=b"abcdefghijklmnop", n=64, r=1, p=1).hex(),
            "pw",
        ),
        (f"scrypt: 1024:1:1${salt}${hexval}", "supersecret1"),
        (f"pbkdf2:sha256:1000:9${pb_salt}${pb_hex}", "supersecret1"),
        (f"pbkdf2:sha256:abc${pb_salt}${pb_hex}", "supersecret1"),
        (f"md5${salt}${hexval}", "supersecret1"),
        (f"plain${salt}$supersecret1", "supersecret1"),
        (f"SCRYPT:1024:1:1${salt}${hexval}", "supersecret1"),
    ]
    out = []
    for pwhash, password in cases:
        case: dict[str, Any] = {"hash": pwhash, "password": password}
        try:
            case["result"] = check_password_hash(pwhash, password)
        except (ValueError, TypeError):
            case["result"] = "error"
        out.append(case)
    return out


AUTH_FILE_TEXTS = [
    '{"secret_key": "' + "c" * 32 + '", "password_hash": "scrypt:32768:8:1$a$b"}',
    '{"password_hash": "scrypt:32768:8:1$a$b"}',
    '{"secret_key": "short", "password_hash": "x"}',
    '{"secret_key": "' + "k" * 16 + '"}',
    '{"secret_key": "' + "k" * 15 + '", "password_hash": ""}',
    '{"secret_key": "ééééééééééééééé✓", "password_hash": "h"}',
    '{"secret_key": 1234567890123456789, "password_hash": 5}',
    '{"hash": "scrypt:abc", "salt": "' + "a" * 16 + '"}',
    '{"password_hash": null, "secret_key": null}',
    "{}",
    "[]",
    "null",
    '""',
    "not json",
    "",
    '{"password_hash": "h", "password_hash": ""}',
    '{"password_hash": "h",}',
    '﻿{"password_hash": "h"}',
]


def auth_record_cases() -> list[dict[str, Any]]:
    out = []
    for text in AUTH_FILE_TEXTS:
        try:
            record = json.loads(text)
        except json.JSONDecodeError:
            record = None
        case: dict[str, Any] = {"text": text}
        try:
            case["password_hash"] = wp._stored_password_hash(record)
            case["secret_key"] = wp._panel_secret_key(record)
        except AttributeError:
            # A JSON value that is not an object: the Python panel crashes;
            # Go treats it as no record.
            case["error"] = True
        out.append(case)
    return out


SAVE_CASES = [
    ("a" * 64, "scrypt:32768:8:1$abcdefghijklmnop$" + "0f" * 64),
    ("ffffffffffffffff", "pbkdf2:sha256:1000$s$00"),
    ('quo"te\\ ✓ key 123', "h"),
]


def save_record_cases() -> list[dict[str, Any]]:
    return [
        {
            "secret_key": key,
            "password_hash": pwhash,
            "text": json.dumps({"secret_key": key, "password_hash": pwhash}, indent=2),
        }
        for key, pwhash in SAVE_CASES
    ]


LOCAL_PATHS = [
    "/",
    "/control/192.168.1.1",
    "/usage/kid name",
    "/usage/kïd",
    "/control/x?next=//evil",
    "/a/../b",
    "",
    "control/x",
    "//evil.example/",
    "///evil.example/",
    "/\\evil.example/",
    "\\\\evil.example/",
    "/control\\x",
    "/\t/evil.example/",
    "/a\nb",
    "/a\x7fb",
    "/a\x00",
    " /x",
    "https://evil.example/",
    "http://localhost/control/x",
    "javascript:alert(1)",
    "/%2F%2Fevil.example",
    "/　x",
]


def local_path_cases() -> list[dict[str, Any]]:
    return [{"in": p, "out": wp.is_local_path(p)} for p in LOCAL_PATHS]


def build_vectors() -> dict[str, Any]:
    return {
        "_about": (
            "Golden web-panel auth vectors generated from werkzeug.security and "
            "kid_pc_monitor.web_panel by tests/panelauth_vectors_gen.py. Do not edit by hand."
        ),
        "constants": {
            "auth_file": wp.AUTH_FILE,
            "min_secret_key_length": 16,
        },
        "generate_password_hash": generate_cases(),
        "check_password_hash": check_cases(),
        "auth_record": auth_record_cases(),
        "save_record": save_record_cases(),
        "is_local_path": local_path_cases(),
    }


def render(vectors: dict[str, Any]) -> str:
    return json.dumps(vectors, indent=1, ensure_ascii=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if the file is out of date")
    args = parser.parse_args()
    text = render(build_vectors())
    if args.check:
        current = VECTORS_PATH.read_text(encoding="utf-8") if VECTORS_PATH.exists() else ""
        if current != text:
            print(
                f"{VECTORS_PATH} is out of date; run tests/panelauth_vectors_gen.py",
                file=sys.stderr,
            )
            return 1
        return 0
    VECTORS_PATH.parent.mkdir(parents=True, exist_ok=True)
    VECTORS_PATH.write_text(text, encoding="utf-8")
    print(f"wrote {VECTORS_PATH.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
