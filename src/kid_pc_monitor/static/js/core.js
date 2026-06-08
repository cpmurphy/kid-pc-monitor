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

export function refreshPageStats() {
    const container = document.getElementById("today-stats");
    if (!container) {
        return Promise.resolve();
    }
    const statsUrl = window.location.pathname.replace(/\/?$/, "") + "/stats";
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
