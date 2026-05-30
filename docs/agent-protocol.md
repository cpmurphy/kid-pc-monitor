The request/response format is a subset of (KDL)[https://kdl.dev/spec], excluding most
notably
- comments
- type annotations
- floating point numbers
- multi-line strings

(A quoted string can include "\n" to indicate a line break, so multi-line
values are possible.  We just don't attempt to support the special
multi-line syntax.)

Example request body:
```
v 1
id b9e7c0
action set
var daily_limit
val 120
```

The `v` is for protocol version.  We start at 1.

Example successful response body:
```
v 1
id b9e7c0
status ok
result 120
```

## Errors

```
v 1
id b9e7c0
status failure
error {
  code invalid_value
   message "minutes must be between 1 and 1440"
}
```

Available codes are:

- `invalid_request` for any request that cannot be parsed
- `unsupported_version`
- `unknown_action`
- `unknown_variable`
- `invalid_value`
- `forbidden`
- `internal_error` a catch-all for anything else
- `authentication_required` (v2) — a write action arrived without an `auth` block or without `name`
- `authentication_failed` (v2) — signature does not verify or name mismatch
- `stale_timestamp` (v2) — frame timestamp outside ±60 s window


## Actions

One of

- `get` with either a single variable to get or "settings" for all variables
- `set` with by a single variable and a new value
- `clear` with by a single variable
- `lock`
- `unlock`
- `extend` with `val` set to a number of minutes to add to today's allowance.
  This accumulates; it never resets the usage already counted today.
- `message` with `val` set to the text to show on the PC
- `shutdown` with an optional `val` giving the warning period in seconds
  (defaults to 60)
- `list_capabilities`

Note there is deliberately no "reset" action: `accumulated_seconds` and
`cumulative_extension` accumulate until the daily `wake_time` rollover and are
not zeroed by setting a new limit.

## Values

One of

- `name` -- read-only
- `status`
- `current_user`
- `daily_limit`
- `bed_time`
- `manual_lock`
- `wake_time`
- `cumulative_extension`
- `accumulated_seconds`
- `time_remaining`


## List Capabilities

The `list_capabilities` action results in a response like this:

```
v 1
id b9e7c0
status ok
actions {
 get "get a single variable or \"settings\" to get all variables"
 set "set a single variable to a new value"
 clear "clear a single variable"
 lock "immediately lock (considered a manual lock)"
 unlock "immediately release a manual lock"
 extend "add minutes of extra allowance for today (val=minutes)"
 message "show a popup message on the PC (val=text)"
 shutdown "shut down the PC after a warning (val=seconds, default 60)"
}
values {
 name "read-only, name of computer"
 status "read-only, the status"
 current_user "read-only, the username of the currently logged-in user"
 daily_limit "current daily limit"
 bed_time "bed time, at which the computer will be locked"
 manual_lock "boolean, whether a manual lock is in effect"
 wake_time "time, at which the computer can be used the following morning"
 cumulative_extension "read-only, a running total of extensions given today"
 accumulated_seconds "read-only, a running total of time used today"
 time_remaining "read-only, a total time remaining today"
}
```

## On the Wire

The actual wire format starts with a length prefix for both requests and
responses:

In this case the prefix is 35 because the body is 35 bytes in length
```
35
v 1
id b9e7c0
status ok
result 120
```

The protocol works as a conversation over a TCP connection.  From the perspective
of the client, we:

1. Establish a TCP connection
2. Send a length-prefixed request
3. Read a length-prefixed response
4. Optionally go back to (2) to send another request
5. Close connection

## Security

Security is implemented starting in protocol version 2.  Every request and
every response carries an `auth` block with an HMAC-SHA256 signature.  Both
sides verify the other's signature on every frame.

### Threat model

Kids on the same LAN can capture traffic, replay old commands, tamper with
messages in flight, and redirect commands from one PC to another.  v2 makes
the panel and agent mutually authenticate every exchange so that:

- An agent only acts on commands genuinely issued by the parent panel.
- The panel only trusts status data from the real agent.
- A command captured on one PC cannot be replayed to a different PC.

Blind replay on the *same* PC is defeated by a timestamp window.
v2 does **not** encrypt the message payload — secrecy is out of scope.
All traffic stays on the local trusted LAN.

### Shared secret

The parent chooses one secret — either a memorable passphrase or a long
random token from a password manager — and supplies it on every PC that runs
the panel or the agent.  Each side stores it encrypted-at-rest via the
`secrets_store` module.  The stored secret is the raw passphrase, whose
UTF-8 bytes are used directly as the HMAC signing key for every frame.

### Authenticated wire format

Every v2 frame includes an `auth` block as its **last** node.  The block is
present on both requests and responses.

**Request:**

```
v 2
name bedroom-pc
timestamp 1710000000
nonce "a1b2c3d4e5f6..."
action unlock
auth {
  algorithm hmac-sha256
  key_id "kid-pc-monitor-shared-secret"
  signature "base64url-encoded-hmac..."
}
```

**Response:**

```
v 2
timestamp 1710000001
nonce "f6e5d4c3b2a1..."
status ok
result "unlocked"
auth {
  algorithm hmac-sha256
  key_id "kid-pc-monitor-shared-secret"
  signature "base64url-encoded-hmac..."
}
```

| Field | Type | Required? | Notes |
|---|---|---|---|
| `version` | int | yes | Always `2` for v2 frames. |
| `id` | string | no | Request id echoed back in the response. Omitted on responses if the request had none. |
| `name` | string | **write actions only** | The target agent's hostname. Required for `set`, `clear`, `lock`, `unlock`, `extend`, `shutdown`, `message`. Optional for `get` and `list_capabilities`. |
| `timestamp` | int | yes | Unix seconds as an integer (not a float). |
| `nonce` | string | yes | At least 16 bytes of hex-encoded randomness. Provides uniqueness for the HMAC even when multiple requests share the same timestamp. |
| `auth.algorithm` | bare | yes | Always `hmac-sha256`. |
| `auth.key_id` | string | yes | Identifies the shared secret used to generate the signature |
| `auth.signature` | string | yes | Base64url-encoded HMAC-SHA256 over the canonical signing string (see below). |

When `name` is absent from a read-only request (the common case),
the agent still signs, validates, and includes its own `name` in its
response — so the panel learns the hostname without needing to know
it in advance.

Every response — including discovery responses and signed error
responses — carries the agent's own `name` and is signed with the shared
key. The panel can therefore authenticate the very first reply from an
agent it has never contacted, and afterwards confirm that the `name` in the
response matches the agent it expected.

### Signature computation

Strip the `auth` block from the parsed frame.  Serialize every remaining
top-level node — including any block nodes like `settings` or `error`, and
any future block nodes added in later protocol versions — to their
deterministic KDL string representation.  The HMAC is computed over the
UTF-8 bytes of that serialized string.

**Request canonical string** (the request above, minus `auth`):

```
v 2
name bedroom-pc
timestamp 1710000000
nonce "a1b2c3d4e5f6..."
action unlock
```

**Response canonical string** with a block node (`settings`):

```
v 2
timestamp 1710000001
nonce "f6e5d4c3b2a1..."
status ok
settings {
  name "bedroom-pc"
  status UNLOCKED
  daily_limit 120
}
```

The HMAC key is the UTF-8 bytes of the shared secret.

Then `signature = base64url(HMAC-SHA256(key, canonical_string_bytes))`.

The recipient strips `auth`, re-serializes the remaining nodes, and
compares the HMAC.  Mismatch → `authentication_failed`.

> The length-prefix framing layer is NOT part of the canonical string.
> Node ordering within the `auth` block does not matter because the entire
> block is stripped before serialization.  All other nodes are serialized
> with the standard KDL-Subset serialization (two-space block indent, no
> trailing newline).

### Timestamp window

Constant `TIMESTAMP_WINDOW_SECONDS = 60`.

The recipient checks `abs(current_unix_time - frame_timestamp)` against the
window.  A frame outside the window is rejected with `stale_timestamp`.
This tolerates reasonable NTP drift (minutes, not hours) while preventing an
attacker from saving a valid frame and replaying it the next day.

### Cross-PC replay

Cross-PC replay is prevented by the signed `name` field, not by the key.
The `name` is part of the canonical signing string, so it cannot be altered
without breaking the signature.

The agent receiving a frame with a `name` field checks that the value
matches its own hostname.  A mismatch is rejected immediately
(`authentication_failed`).  The panel likewise verifies that the name in a
response matches the agent it expected to talk to.

So a kid who captures an `unlock` command on `bedroom-pc` cannot replay it
against `living-room-pc` — the captured frame still says `name bedroom-pc`,
which it cannot change without invalidating the signature, and
`living-room-pc` rejects the mismatch.

### Discovery handshake

When the panel first contacts an agent on a given IP, it does not yet know
the agent's hostname.  It sends a read-only request (`get name` or
`get settings`) **without** a `name` field.  The agent answers with a
signed response that includes its `name`.  From that point on the panel
includes that `name` in all future requests.

The agent never requires `name` for read-only actions (`get`,
`list_capabilities`).  Write or destructive actions (`set`, `clear`, `lock`,
`unlock`, `extend`, `shutdown`, `message`) **must** carry `name`, and it
must match the agent's hostname.

Example:

```
Panel → Agent:   v 2 ... timestamp ... nonce ... action get var name
                 auth { algorithm hmac-sha256 key_id "..." signature "..." }
                 (no name field; discovery request)

Agent → Panel:   v 2 ... name "bedroom-pc" ... status ok result "bedroom-pc"
                 auth { algorithm hmac-sha256 key_id "..." signature "..." }

Panel → Agent:   v 2 ... name "bedroom-pc" ... action unlock
                 auth { algorithm hmac-sha256 key_id "..."
                        signature "..." }
                 (name is signed, so the agent can enforce it)
```

### Error codes (v2 additions)

| Code | Meaning |
|---|---|
| `authentication_required` | A write action arrived without an `auth` block or without `name`. |
| `authentication_failed` | The signature does not verify, or `name` does not match the agent. |
| `stale_timestamp` | The frame's timestamp is outside the ±60 s window. |
