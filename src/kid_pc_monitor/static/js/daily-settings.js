"use strict";

import { parsePositiveInt, postAction, registerHandlers, showStatus } from "./core.js";

registerHandlers({
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
});
