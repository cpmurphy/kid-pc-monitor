"use strict";

// Shared helpers for control and daily-settings pages.

const handlers = {};
let listenerAttached = false;

export function csrfHeaders() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return {
        "Content-Type": "application/json",
        "X-CSRF-Token": meta ? meta.content : "",
    };
}

export function showStatus(message, isSuccess) {
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

export function getIp() {
    const el = document.querySelector("[data-ip]");
    return el ? el.getAttribute("data-ip") : "";
}

export function refreshPageStats(opts) {
    opts = opts || {};
    const container = document.getElementById("today-stats");
    if (!container) {
        return Promise.resolve();
    }
    let statsUrl = window.location.pathname.replace(/\/?$/, "") + "/stats";
    if (opts.source === "poll") {
        statsUrl += "?source=poll";
    }
    return fetch(statsUrl, { headers: { Accept: "text/html" } })
        .then(function (response) {
            if (!response.ok) {
                return null;
            }
            return response.text();
        })
        .then(function (html) {
            if (html !== null) {
                container.innerHTML = html;
            }
        })
        .catch(function () {
            // Leave the current stats visible if refresh fails.
        });
}

export function startControlPagePoll() {
    const container = document.getElementById("today-stats");
    if (!container) {
        return;
    }
    let lastUpdatedAt = container.getAttribute("data-poll-updated-at");
    const metaUrl = window.location.pathname.replace(/\/?$/, "") + "/poll-meta";

    function pollCheckIntervalMs(data) {
        if (
            data &&
            typeof data.poll_interval_sec === "number" &&
            data.poll_interval_sec > 0
        ) {
            return Math.max(5000, Math.round((data.poll_interval_sec * 1000) / 4));
        }
        return 15000;
    }

    function checkPollUpdate() {
        fetch(metaUrl, { headers: { Accept: "application/json" } })
            .then(function (response) {
                if (!response.ok) {
                    return null;
                }
                return response.json();
            })
            .then(function (data) {
                if (!data || !data.updated_at || data.updated_at === lastUpdatedAt) {
                    return;
                }
                lastUpdatedAt = data.updated_at;
                container.setAttribute("data-poll-updated-at", lastUpdatedAt);
                return refreshPageStats({ source: "poll" });
            })
            .catch(function () {
                // Ignore transient poll-meta failures.
            });
    }

    fetch(metaUrl, { headers: { Accept: "application/json" } })
        .then(function (response) {
            if (!response.ok) {
                return null;
            }
            return response.json();
        })
        .then(function (data) {
            const intervalMs = pollCheckIntervalMs(data);
            checkPollUpdate();
            setInterval(checkPollUpdate, intervalMs);
        })
        .catch(function () {
            setInterval(checkPollUpdate, 15000);
        });
}


function waitForCommand(commandId, opts) {
    opts = opts || {};
    let attempts = 0;
    const maxAttempts = 30;

    function check() {
        attempts += 1;
        return fetch("/command/" + commandId, { headers: { Accept: "application/json" } })
            .then(function (response) {
                if (!response.ok) {
                    showStatus("Command status failed (" + response.status + ")", false);
                    return null;
                }
                return response.json();
            })
            .then(function (data) {
                if (!data) {
                    return;
                }
                if (data.pending && attempts < maxAttempts) {
                    setTimeout(check, 1000);
                    return;
                }
                showStatus(data.response, data.success);
                if (data.success) {
                    if (typeof opts.onSuccess === "function") {
                        opts.onSuccess();
                    }
                    if (opts.refreshStats) {
                        refreshPageStats({ source: "poll" });
                    } else if (opts.reloadDelay) {
                        setTimeout(function () {
                            location.reload();
                        }, opts.reloadDelay);
                    }
                }
            })
            .catch(function () {
                showStatus("Command status unavailable", false);
            });
    }

    return check();
}

// Central POST helper for /action. `body` is merged with the page IP. opts:
//   button       - element to disable while the request is in flight
//   refreshStats - if true and #today-stats exists, reload that section after success
//   reloadDelay  - if set and the action succeeds, reload after this many ms
//   onSuccess    - callback run on a successful response
export function postAction(body, opts) {
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
            if (data.success && data.command_id) {
                return waitForCommand(data.command_id, opts);
            }
            if (data.success) {
                if (typeof opts.onSuccess === "function") {
                    opts.onSuccess();
                }
                if (opts.refreshStats) {
                    refreshPageStats();
                } else if (opts.reloadDelay) {
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
export function parsePositiveInt(raw) {
    if (!raw) {
        return null;
    }
    const value = parseInt(raw, 10);
    if (!Number.isInteger(value) || value <= 0) {
        return null;
    }
    return value;
}

export function registerHandlers(map) {
    Object.assign(handlers, map);
    if (listenerAttached) {
        return;
    }
    listenerAttached = true;
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
}
