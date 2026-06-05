"use strict";

// Behavior for the Kids PC Control Panel. Loaded once from base.html on every
// page and self-guards by feature detection, so it is harmless on pages without
// interactive controls (login, set_password). Page-specific values that used to
// be interpolated into inline scripts (the target IP, control URLs) now arrive
// via data-* attributes.

(function () {
    function csrfHeaders() {
        const meta = document.querySelector('meta[name="csrf-token"]');
        return {
            "Content-Type": "application/json",
            "X-CSRF-Token": meta ? meta.content : "",
        };
    }

    function showStatus(message, isSuccess) {
        const statusEl = document.getElementById("status-message");
        if (!statusEl) {
            return;
        }
        statusEl.textContent = message;
        statusEl.className = "status-message " + (isSuccess ? "success" : "error");
        statusEl.style.display = "block";
        setTimeout(function () {
            statusEl.style.display = "none";
        }, 3000);
    }

    function getIp() {
        const el = document.querySelector("[data-ip]");
        return el ? el.getAttribute("data-ip") : "";
    }

    // Central POST helper for /action. `body` is merged with the page IP. opts:
    //   button      - element to disable while the request is in flight
    //   reloadDelay - if set and the action succeeds, reload after this many ms
    //   onSuccess   - callback run on a successful response
    function postAction(body, opts) {
        opts = opts || {};
        const button = opts.button || null;
        if (button) {
            button.disabled = true;
            button.setAttribute("aria-busy", "true");
        }
        const payload = Object.assign({ ip: getIp() }, body);
        return fetch("/action", {
            method: "POST",
            headers: csrfHeaders(),
            body: JSON.stringify(payload),
        })
            .then(function (response) {
                if (!response.ok) {
                    showStatus("Request failed (" + response.status + ")", false);
                    return null;
                }
                return response.json();
            })
            .then(function (data) {
                if (!data) {
                    return;
                }
                showStatus(data.response, data.success);
                if (data.success) {
                    if (typeof opts.onSuccess === "function") {
                        opts.onSuccess();
                    }
                    if (opts.reloadDelay) {
                        setTimeout(function () {
                            location.reload();
                        }, opts.reloadDelay);
                    }
                }
            })
            .catch(function () {
                showStatus("Network error — please try again", false);
            })
            .finally(function () {
                if (button) {
                    button.disabled = false;
                    button.removeAttribute("aria-busy");
                }
            });
    }

    // Parse a minutes field into a positive integer, or null if invalid/empty.
    function parsePositiveInt(raw) {
        if (!raw) {
            return null;
        }
        const value = parseInt(raw, 10);
        if (!Number.isInteger(value) || value <= 0) {
            return null;
        }
        return value;
    }

    function grantExtension(button) {
        const minutes = parsePositiveInt(
            document.getElementById("extension-minutes").value
        );
        if (minutes === null) {
            showStatus("Enter a positive number of minutes", false);
            return;
        }
        postAction(
            { action: "extend_time", minutes: minutes },
            { button: button, reloadDelay: 1000 }
        );
    }

    // data-action handlers. Each receives the matched element.
    const handlers = {
        lock: function (el) {
            postAction({ action: "lock" }, { button: el, reloadDelay: 2000 });
        },
        shutdown: function (el) {
            if (!confirm("Are you sure you want to shutdown this computer?")) {
                return;
            }
            postAction({ action: "shutdown" }, { button: el, reloadDelay: 2000 });
        },
        "send-message": function (el) {
            const input = document.getElementById("message-text");
            const message = input.value;
            if (!message) {
                showStatus("Please enter a message", false);
                return;
            }
            postAction(
                { action: "message", message: message },
                {
                    button: el,
                    onSuccess: function () {
                        input.value = "";
                    },
                }
            );
        },
        "quick-extend": function (el) {
            const minutes = el.getAttribute("data-minutes");
            document.getElementById("extension-minutes").value = minutes;
            grantExtension(el);
        },
        "grant-extension": function (el) {
            grantExtension(el);
        },
        "clear-manual-lock": function (el) {
            if (!confirm("Clear the manual lock?")) {
                return;
            }
            postAction(
                { action: "clear_manual_lock" },
                { button: el, reloadDelay: 1000 }
            );
        },
        "save-daily-limit": function (el) {
            const minutes = parsePositiveInt(
                document.getElementById("daily-limit-minutes").value
            );
            if (minutes === null) {
                showStatus("Enter a positive number of minutes or use Remove", false);
                return;
            }
            postAction(
                { action: "set_daily_limit", minutes: minutes },
                { button: el, reloadDelay: 1000 }
            );
        },
        "clear-daily-limit": function (el) {
            if (!confirm("Remove the daily allowance default?")) {
                return;
            }
            postAction(
                { action: "clear_usage_limit" },
                { button: el, reloadDelay: 1000 }
            );
        },
        "save-bed-time": function (el) {
            const time = document.getElementById("bed-time").value;
            if (!time) {
                showStatus("Please select a bedtime", false);
                return;
            }
            postAction(
                { action: "set_bed_time", time: time },
                { button: el, reloadDelay: 1000 }
            );
        },
        "clear-bed-time": function (el) {
            if (!confirm("Remove the bedtime default?")) {
                return;
            }
            postAction(
                { action: "clear_bed_time" },
                { button: el, reloadDelay: 1000 }
            );
        },
        "save-wake-time": function (el) {
            const time = document.getElementById("wake-time").value;
            if (!time) {
                showStatus("Please select a wake-up time", false);
                return;
            }
            postAction(
                { action: "set_wake_time", time: time },
                { button: el, reloadDelay: 1000 }
            );
        },
        navigate: function (el) {
            const href = el.getAttribute("data-href");
            if (href) {
                location.href = href;
            }
        },
    };

    document.addEventListener("click", function (event) {
        const target = event.target.closest("[data-action]");
        if (!target) {
            return;
        }
        const handler = handlers[target.getAttribute("data-action")];
        if (handler) {
            handler(target);
        }
    });

    // Home page auto-refresh.
    if (document.body.classList.contains("page-home")) {
        setTimeout(function () {
            location.reload();
        }, 30000);
    }

    // Agent-log viewer (logs.html). Guarded on the log element being present.
    (function setupAgentLog() {
        const el = document.getElementById("agent-log");
        if (!el) {
            return;
        }
        const STICK_KEY = "kid-pc-monitor-agent-log-stick-bottom";
        const NEAR_BOTTOM_PX = 40;

        function isNearBottom(node) {
            return node.scrollHeight - node.scrollTop - node.clientHeight <= NEAR_BOTTOM_PX;
        }
        function scrollToTop(node) {
            node.scrollTop = 0;
        }
        function scrollToBottom(node) {
            node.scrollTop = node.scrollHeight;
        }

        const stick = sessionStorage.getItem(STICK_KEY);
        sessionStorage.removeItem(STICK_KEY);
        if (stick === null || stick === "1") {
            scrollToBottom(el);
        }

        const top = document.getElementById("log-top");
        if (top) {
            top.addEventListener("click", function () {
                scrollToTop(el);
                el.focus();
            });
        }
        const bottom = document.getElementById("log-bottom");
        if (bottom) {
            bottom.addEventListener("click", function () {
                scrollToBottom(el);
                el.focus();
            });
        }
        const refresh = document.getElementById("log-refresh");
        if (refresh) {
            refresh.addEventListener("click", function () {
                sessionStorage.setItem(STICK_KEY, isNearBottom(el) ? "1" : "0");
                location.reload();
            });
        }

        el.addEventListener("keydown", function (e) {
            if (e.key === "Home") {
                e.preventDefault();
                scrollToTop(el);
            } else if (e.key === "End") {
                e.preventDefault();
                scrollToBottom(el);
            }
        });
    })();
})();
