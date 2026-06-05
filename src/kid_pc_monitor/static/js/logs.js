"use strict";

// Agent-log viewer (logs.html). Guarded on the log element being present.

const el = document.getElementById("agent-log");
if (el) {
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
}
