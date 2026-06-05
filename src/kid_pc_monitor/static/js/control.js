"use strict";

import { parsePositiveInt, postAction, registerHandlers, showStatus } from "./core.js";

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

registerHandlers({
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
});
