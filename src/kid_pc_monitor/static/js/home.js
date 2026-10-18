"use strict";

// Home page: PC card navigation and live status refresh.
//
// DuckDuckGo's mobile browser replays a cached document for a normal reload, so a
// dashboard loaded while a PC was offline can still say "not connected" a day
// later. Safari revalidates that navigation. Fetch this page with cache
// "no-store" and a unique query so the status cards update from the network.

document.addEventListener("click", function (event) {
    const target = event.target.closest('[data-action="navigate"]');
    if (!target) {
        return;
    }
    const href = target.getAttribute("data-href");
    if (href) {
        location.href = href;
    }
});

const HOME_REFRESH_MS = 30000;
let refreshInFlight = null;

function refreshHome() {
    if (refreshInFlight) {
        return refreshInFlight;
    }
    const url = new URL(window.location.href);
    url.searchParams.set("_", String(Date.now()));
    refreshInFlight = fetch(url.toString(), {
        cache: "no-store",
        credentials: "same-origin",
        headers: { Accept: "text/html" },
    })
        .then(function (response) {
            if (!response.ok) {
                return null;
            }
            if (response.redirected) {
                const landed = new URL(response.url);
                if (landed.pathname !== window.location.pathname) {
                    window.location.replace(response.url);
                    return null;
                }
            }
            return response.text();
        })
        .then(function (html) {
            if (!html) {
                return;
            }
            const doc = new DOMParser().parseFromString(html, "text/html");
            if (!doc.body.classList.contains("page-home")) {
                return;
            }
            const next = doc.getElementById("home-dashboard");
            const current = document.getElementById("home-dashboard");
            if (!next || !current) {
                return;
            }
            current.innerHTML = next.innerHTML;
        })
        .catch(function () {
            // Keep the cards already on screen if this refresh fails.
        })
        .finally(function () {
            refreshInFlight = null;
        });
    return refreshInFlight;
}

if (document.body.classList.contains("page-home")) {
    refreshHome();
    setInterval(refreshHome, HOME_REFRESH_MS);

    // Back-forward cache restores the previous paint without re-running this
    // script. Pull a fresh dashboard as soon as that snapshot is shown.
    window.addEventListener("pageshow", function (event) {
        if (event.persisted) {
            refreshHome();
        }
    });

    // A backgrounded mobile tab keeps the last painted status until script
    // runs again. Refresh as soon as the page is visible.
    document.addEventListener("visibilitychange", function () {
        if (document.visibilityState === "visible") {
            refreshHome();
        }
    });
}
