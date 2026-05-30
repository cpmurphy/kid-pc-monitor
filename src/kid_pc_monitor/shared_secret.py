"""Interactive prompt for the panel <-> agent shared secret (protocol v2).

The web panel and the monitoring agent authenticate their messages to each
other with a single shared secret.  Because the parent types the same secret
on both halves of the install, it should be a memorable passphrase rather than
a random string.  This module collects that passphrase and persists it with
:mod:`kid_pc_monitor.secrets_store`.
"""

from __future__ import annotations

import getpass

from kid_pc_monitor import secrets_store

SHARED_SECRET_NAME = "panel-agent-shared-secret"

MIN_SECRET_LENGTH = 8


def _print_guidance() -> None:
    print("\n🔑 Shared secret (web panel <-> monitoring agent)")
    print("\n   The web panel and the monitoring agent must share one secret so each")
    print("   can confirm the other's messages are genuine. Enter the SAME secret")
    print("   here and when you install the other half.")
    print("\n   Pick something that is:")
    print("     • Easy for YOU to remember and type")
    print("     • Hard for your child (or anyone else) to guess")
    print("     • Like a password — but NOT one you use anywhere else")
    print("\n   A short phrase of a few unrelated words works well.")


def prompt_for_shared_secret(*, getpass_fn=getpass.getpass) -> str | None:
    """Prompt for the shared secret (entered twice) and return it.

    Returns the validated secret, or ``None`` if the parent cancelled.
    """
    while True:
        try:
            secret = getpass_fn("\n   Enter shared secret: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n   Cancelled; shared secret not changed.")
            return None

        if len(secret) < MIN_SECRET_LENGTH:
            print(f"   ❌ Too short — use at least {MIN_SECRET_LENGTH} characters.")
            continue

        try:
            confirm = getpass_fn("   Re-enter to confirm: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n   Cancelled; shared secret not changed.")
            return None

        if secret != confirm:
            print("   ❌ Entries did not match. Please try again.")
            continue

        return secret


def prompt_and_store_shared_secret(
    *,
    getpass_fn=getpass.getpass,
    input_fn=input,
) -> str | None:
    """Show guidance, prompt for the shared secret, and persist it.

    If a secret is already stored, the parent may keep it. Returns the stored
    secret, or ``None`` if the parent cancelled without saving.
    """
    _print_guidance()

    existing = secrets_store.load_secret(SHARED_SECRET_NAME)
    if existing is not None:
        try:
            keep = input_fn("\n   A shared secret is already stored. Keep it? (Y/n): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            keep = ""
        if keep in ("", "y", "yes"):
            print("   Keeping the existing shared secret.")
            return existing

    secret = prompt_for_shared_secret(getpass_fn=getpass_fn)
    if secret is None:
        return None

    secrets_store.save_secret(SHARED_SECRET_NAME, secret)
    print("   ✅ Shared secret saved (encrypted at rest).")
    return secret
