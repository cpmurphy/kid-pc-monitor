"use strict";

// Home page: PC card navigation and periodic refresh.

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

if (document.body.classList.contains("page-home")) {
    setTimeout(function () {
        location.reload();
    }, 30000);
}
