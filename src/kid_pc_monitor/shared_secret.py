"""Interactive prompt for the panel <-> agent shared secret (protocol v2).

The web panel and the monitoring agent authenticate their messages to each
other with a single shared secret entered on both sides of the install.
This module collects that secret and persists it with
:mod:`kid_pc_monitor.secrets_store`.
"""
from __future__ import annotations

import getpass

from kid_pc_monitor import secrets_store

SHARED_SECRET_NAME = "panel-agent-shared-secret"

MIN_SECRET_LENGTH = 8


class SharedSecretMissing(RuntimeError):
    """Raised when the panel/agent shared secret has not been configured."""


def load_shared_secret() -> str | None:
    """Return the stored shared secret, or ``None`` if it has not been set."""
    return secrets_store.load_secret(SHARED_SECRET_NAME)


def require_shared_secret() -> str:
    """Return the stored shared secret or raise :class:`SharedSecretMissing`.

    Both halves of the system authenticate every protocol v2 frame with this
    secret, so a missing secret is a hard configuration error rather than a
    reason to silently fall back to unauthenticated traffic.
    """
    secret = load_shared_secret()
    if not secret:
        raise SharedSecretMissing(
            "No shared secret is configured. Re-run the installer to set the "
            "panel/agent shared secret on this machine."
        )
    return secret


def _print_guidance() -> None:
    print("\n🔑 Shared secret (web panel <-> monitoring agent)")
    print("\n   The web panel and the monitoring agent must share one secret so each")
    print("   can confirm the other's messages are genuine. Enter the SAME secret")
    print("   here and when you install the other half.")
    print("\n   Best option:")
    print("     • Generate a random string in a password manager (Bitwarden,")
    print("       1Password, Apple Keychain, etc.) and paste it in on each PC.")
    print("\n   If you can't use a password manager, pick something that is:")
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


def _persist_shared_secret(secret: str):
    """Store the secret in the preferred location and drop stale copies.

    Re-saving on every install (even when reusing an existing secret) is what
    migrates a secret that an earlier version left in the admin's per-user
    AppData into the machine-wide directory, so the agent running in the
    child's session can read it (mode 2 / cross-user installs).
    """
    path = secrets_store.save_secret(SHARED_SECRET_NAME, secret)
    return path


def prompt_and_store_shared_secret(
    *,
    getpass_fn=getpass.getpass,
    input_fn=input,
) -> str | None:
    """Show guidance, prompt for the shared secret, and persist it.

    If a secret is already stored, the parent is offered a short prompt to reuse
    it without re-reading the full guidance. Either way the secret is (re-)saved
    to the machine-wide location so cross-user installs work. Returns the stored
    secret, or ``None`` if the parent cancelled without saving.
    """
    existing = secrets_store.load_secret(SHARED_SECRET_NAME)
    if existing is not None:
        try:
            keep = input_fn(
                "\n🔑 A shared secret is already stored. Reuse it? (Y/n): "
            ).strip().lower()
        except (EOFError, KeyboardInterrupt):
            keep = ""
        if keep in ("", "y", "yes"):
            path = _persist_shared_secret(existing)
            print(f"   Keeping the existing shared secret (stored at {path}).")
            return existing

    _print_guidance()

    secret = prompt_for_shared_secret(getpass_fn=getpass_fn)
    if secret is None:
        return None

    path = _persist_shared_secret(secret)
    print(f"   ✅ Shared secret saved (encrypted at rest) at {path}.")
    return secret
