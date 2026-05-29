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

The `v` is for protocol version.  We start at 1.  (The existing ad-hoc
protocol is version zero.

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

To be implemented in a follow-on version (not version 1).

```
v 2
id "uuid-or-random-hex"
timestamp: 1710000000
nonce "random-hex"
action set
var daily_limit
val 120
auth {
    key_id "parent-panel"
    algorithm "hmac-sha256"
    signature "..."
  }
}
```

The signature covers the canonical request/response fields: version, id, timestamp,
nonce, action, var, val.
