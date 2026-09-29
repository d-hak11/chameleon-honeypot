/* Greenwood College -- persona interactivity (vanilla JS, no dependencies).
 * Makes the static persona behave like a real Moodle site: left drawer, live
 * course search, language menu, cookie notice, and a login form that responds
 * the way Moodle does for a bad credential. Content-free by design.
 */
(function () {
    "use strict";

    function $(sel, root) { return (root || document).querySelector(sel); }
    function $all(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }

    /* ---------- Left drawer ---------- */
    var drawer = $("#gc-drawer");
    var overlay = $("#gc-drawer-overlay");
    function setDrawer(open) {
        if (!drawer) return;
        drawer.classList.toggle("show", open);
        if (overlay) overlay.classList.toggle("show", open);
        drawer.setAttribute("aria-hidden", String(!open));
    }
    $all("[data-gc-drawer-open]").forEach(function (b) {
        b.addEventListener("click", function () { setDrawer(true); });
    });
    $all("[data-gc-drawer-close]").forEach(function (b) {
        b.addEventListener("click", function () { setDrawer(false); });
    });
    if (overlay) overlay.addEventListener("click", function () { setDrawer(false); });
    document.addEventListener("keydown", function (e) {
        if (e.key === "Escape") setDrawer(false);
    });

    /* ---------- Live course search ---------- */
    var searchInput = $("#gc-course-search");
    if (searchInput) {
        var cards = $all(".card-grid > .card");
        var emptyNote = $("#gc-no-courses");
        searchInput.addEventListener("input", function () {
            var q = searchInput.value.trim().toLowerCase();
            var visible = 0;
            cards.forEach(function (card) {
                var text = card.textContent.toLowerCase();
                var show = q === "" || text.indexOf(q) !== -1;
                card.style.display = show ? "" : "none";
                if (show) visible++;
            });
            if (emptyNote) emptyNote.style.display = visible === 0 ? "" : "none";
        });
    }

    /* ---------- Language dropdown ---------- */
    var langToggle = $("#gc-lang-toggle");
    var langMenu = $("#gc-lang-menu");
    if (langToggle && langMenu) {
        langToggle.addEventListener("click", function (e) {
            e.preventDefault();
            e.stopPropagation();
            langMenu.classList.toggle("show");
        });
        document.addEventListener("click", function () { langMenu.classList.remove("show"); });
    }

    /* ---------- Cookie notice ---------- */
    var cookieKey = "gc_cookie_notice";
    var cookieBar = $("#gc-cookie-notice");
    if (cookieBar) {
        try {
            if (!window.localStorage.getItem(cookieKey)) cookieBar.classList.add("show");
        } catch (e) { cookieBar.classList.add("show"); }
        var accept = $("#gc-cookie-accept");
        if (accept) accept.addEventListener("click", function () {
            cookieBar.classList.remove("show");
            try { window.localStorage.setItem(cookieKey, "1"); } catch (e) { /* ignore */ }
        });
    }

    /* ---------- Enrol buttons -> login (not logged in) ---------- */
    $all("[data-gc-enrol]").forEach(function (btn) {
        btn.addEventListener("click", function (e) {
            e.preventDefault();
            window.location.href = "login/index.php";
        });
    });

    /* ---------- Login form ---------- */
    var loginForm = $("#login");
    if (loginForm) {
        var user = $("#username");
        var pass = $("#password");
        var alertBox = $("#gc-login-alert");
        var submitBtn = $("#loginbtn");
        var submitLabel = submitBtn ? submitBtn.querySelector(".btn-label") : null;

        function setSubmit(text, disabled) {
            if (!submitBtn) return;
            submitBtn.disabled = disabled;
            if (submitLabel) submitLabel.textContent = text;
            else submitBtn.textContent = text;
        }

        // Show / hide password
        var pwToggle = $("#gc-pw-toggle");
        if (pwToggle && pass) {
            pwToggle.addEventListener("click", function () {
                var showing = pass.type === "text";
                pass.type = showing ? "password" : "text";
                pwToggle.setAttribute("aria-label", showing ? "Show password" : "Hide password");
                pwToggle.classList.toggle("is-on", !showing);
            });
        }

        loginForm.addEventListener("submit", function (e) {
            e.preventDefault();
            var u = user ? user.value.trim() : "";
            var p = pass ? pass.value : "";

            if (u === "" || p === "") {
                showLoginError("Please fill in your username and password.");
                return;
            }
            // Behave like Moodle on a bad credential: brief pause, then the
            // standard "Invalid login" message. No real authentication happens.
            setSubmit("Logging in...", true);
            window.setTimeout(function () {
                showLoginError("Invalid login, please try again");
                setSubmit("Log in", false);
                if (pass) { pass.value = ""; pass.focus(); }
            }, 650);
        });

        function showLoginError(msg) {
            if (!alertBox) return;
            alertBox.textContent = msg;
            alertBox.classList.add("show");
            loginForm.classList.remove("shake");
            // force reflow so the animation can replay
            void loginForm.offsetWidth;
            loginForm.classList.add("shake");
        }
    }

    /* ---------- Footer year ---------- */
    var yearEl = $("#gc-year");
    if (yearEl) yearEl.textContent = String(new Date().getFullYear());
})();
