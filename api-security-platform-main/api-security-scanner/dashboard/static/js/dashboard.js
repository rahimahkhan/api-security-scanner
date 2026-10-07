// Xploiter UI — theme, navigation, and shared widgets.
(function () {
    "use strict";

    function onReady(fn) {
        if (document.readyState !== "loading") fn();
        else document.addEventListener("DOMContentLoaded", fn);
    }

    // Timestamps are stored in UTC; render them in the viewer's local timezone.
    onReady(function () {
        document.querySelectorAll(".local-dt[data-utc]").forEach(function (el) {
            var d = new Date(el.getAttribute("data-utc"));
            if (isNaN(d.getTime())) return;
            el.textContent = d.toLocaleString(undefined, {
                year: "numeric", month: "short", day: "numeric",
                hour: "2-digit", minute: "2-digit"
            });
            el.title = "Server time (UTC): " + el.getAttribute("data-utc");
        });
    });

    /* ---------- Theme ---------- */
    function applyThemeChoice(choice) {
        var theme = choice;
        if (choice === "system") {
            theme = (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches) ? "dark" : "light";
        }
        document.documentElement.setAttribute("data-theme", theme || "light");
        try { localStorage.setItem("xploiter-theme", choice); } catch (e) {}
        syncAppearanceRadios(choice);
    }
    function currentChoice() {
        try { return localStorage.getItem("xploiter-theme") || "light"; }
        catch (e) { return "light"; }
    }
    function syncAppearanceRadios(choice) {
        document.querySelectorAll('input[name="appearance"]').forEach(function (r) {
            r.checked = (r.value === choice);
        });
    }
    function syncThemeIcon() {
        var icon = document.getElementById("theme-icon");
        if (icon) icon.innerHTML = document.documentElement.getAttribute("data-theme") === "dark" ? "&#127769;" : "&#9728;&#65039;";
        document.querySelectorAll('[data-theme-choice]').forEach(function (b) {
            b.setAttribute("aria-checked", b.getAttribute("data-theme-choice") === currentChoice() ? "true" : "false");
        });
    }
    var _applyThemeChoice = applyThemeChoice;
    applyThemeChoice = function (choice) { _applyThemeChoice(choice); syncThemeIcon(); };

    /* ---------- Alerts badge (localStorage read-state) ---------- */
    var READ_KEY = "xploiter-alerts-read";
    function readIds() {
        try { return JSON.parse(localStorage.getItem(READ_KEY) || "[]"); }
        catch (e) { return []; }
    }
    function refreshAlertBadge() {
        var badge = document.getElementById("alert-badge");
        if (!badge) return;
        var total = 0;
        document.querySelectorAll("[data-alert-id]").forEach(function () { total += 1; });
        // On non-alert pages the server renders the total count inside the badge.
        if (total === 0) total = parseInt(badge.textContent || "0", 10) || 0;
        var read = readIds();
        var unread = 0;
        if (document.querySelectorAll("[data-alert-id]").length) {
            document.querySelectorAll("[data-alert-id]").forEach(function (el) {
                if (read.indexOf(el.getAttribute("data-alert-id")) === -1) unread += 1;
            });
        } else {
            // Badge already holds the server-computed total; we cannot know
            // per-item read state here, so leave the server count as-is.
            return;
        }
        badge.textContent = unread;
        badge.hidden = unread === 0;
    }

    onReady(function () {
        /* Theme dropdown (top bar): explicit Light / Dark choice */
        var themeBtn = document.getElementById("theme-btn");
        var themeDropdown = document.getElementById("theme-dropdown");
        /* Account dropdown (top bar) */
        var accountBtn = document.getElementById("account-btn");
        var accountDropdown = document.getElementById("account-dropdown");
        function closeIconDropdowns(except) {
            [themeDropdown, accountDropdown].forEach(function (dd) {
                if (dd && dd !== except) dd.classList.remove("open");
            });
        }
        if (themeBtn && themeDropdown) {
            themeBtn.addEventListener("click", function (e) {
                e.stopPropagation();
                var willOpen = !themeDropdown.classList.contains("open");
                closeIconDropdowns();
                if (willOpen) themeDropdown.classList.add("open");
            });
            themeDropdown.querySelectorAll("[data-theme-choice]").forEach(function (b) {
                b.addEventListener("click", function () {
                    applyThemeChoice(b.getAttribute("data-theme-choice"));
                    themeDropdown.classList.remove("open");
                });
            });
        }
        if (accountBtn && accountDropdown) {
            accountBtn.addEventListener("click", function (e) {
                e.stopPropagation();
                var willOpen = !accountDropdown.classList.contains("open");
                closeIconDropdowns();
                if (willOpen) accountDropdown.classList.add("open");
            });
        }
        document.addEventListener("click", function () { closeIconDropdowns(); });
        syncThemeIcon();
        /* Appearance radios (settings) */
        document.querySelectorAll('input[name="appearance"]').forEach(function (r) {
            r.addEventListener("change", function () { applyThemeChoice(r.value); });
        });
        syncAppearanceRadios(currentChoice());


        /* Mobile nav drawer */
        var hamburger = document.getElementById("nav-hamburger");
        var sidebar = document.getElementById("sidebar");
        var scrim = document.getElementById("nav-scrim");
        function closeDrawer() {
            if (sidebar) sidebar.classList.remove("open");
            if (scrim) scrim.classList.remove("open");
        }
        if (hamburger && sidebar) {
            hamburger.addEventListener("click", function () {
                sidebar.classList.toggle("open");
                if (scrim) scrim.classList.toggle("open", sidebar.classList.contains("open"));
            });
        }
        if (scrim) scrim.addEventListener("click", closeDrawer);

        /* More sheet (phone bottom tabs) */
        var moreTab = document.getElementById("more-tab");
        var sheet = document.getElementById("more-sheet");
        var sheetScrim = document.getElementById("sheet-scrim");
        function closeSheet() {
            if (sheet) sheet.classList.remove("open");
            if (sheetScrim) sheetScrim.classList.remove("open");
        }
        if (moreTab && sheet) moreTab.addEventListener("click", function () {
            sheet.classList.add("open");
            if (sheetScrim) sheetScrim.classList.add("open");
        });
        if (sheetScrim) sheetScrim.addEventListener("click", closeSheet);

        /* Export dropdowns */
        document.querySelectorAll("[data-export-toggle]").forEach(function (btn) {
            btn.addEventListener("click", function (e) {
                e.stopPropagation();
                var menu = btn.parentElement.querySelector(".export-menu");
                if (menu) menu.classList.toggle("open");
            });
        });
        document.addEventListener("click", function () {
            document.querySelectorAll(".export-menu.open").forEach(function (m) { m.classList.remove("open"); });
        });

        /* Generic filter tabs (results page) */
        document.querySelectorAll(".filter-tabs").forEach(function (tabs) {
            var buttons = tabs.querySelectorAll(".filter-tab");
            buttons.forEach(function (tab) {
                tab.addEventListener("click", function () {
                    buttons.forEach(function (t) { t.classList.remove("active"); });
                    tab.classList.add("active");
                    var f = tab.getAttribute("data-filter");
                    var scope = tabs.getAttribute("data-scope") || document;
                    var scopeEl = (typeof scope === "string" ? document : scope);
                    var visible = 0;
                    scopeEl.querySelectorAll("[data-status]").forEach(function (el) {
                        var show = (f === "all" || el.getAttribute("data-status") === f);
                        el.style.display = show ? "" : "none";
                        if (show && el.classList.contains("risk-card")) visible++;
                    });
                    // Keep the "N SHOWN" header honest on the top-risks section.
                    var header = tabs.parentElement.querySelector(".top-risks-count");
                    if (header) header.textContent = visible + " SHOWN";
                });
            });
        });

        /* Alerts: tabs + mark all as read */
        var alertTabs = document.querySelectorAll(".alert-tabs .filter-tab");
        alertTabs.forEach(function (tab) {
            tab.addEventListener("click", function () {
                alertTabs.forEach(function (t) { t.classList.remove("active"); });
                tab.classList.add("active");
                var onlyUnread = tab.getAttribute("data-filter") === "unread";
                var read = readIds();
                document.querySelectorAll("[data-alert-id]").forEach(function (el) {
                    var isRead = read.indexOf(el.getAttribute("data-alert-id")) !== -1;
                    el.querySelector(".alert-dot").classList.toggle("read", isRead);
                    el.style.display = (onlyUnread && isRead) ? "none" : "";
                });
            });
        });
        // Paint read state on load.
        (function () {
            var read = readIds();
            document.querySelectorAll("[data-alert-id]").forEach(function (el) {
                if (read.indexOf(el.getAttribute("data-alert-id")) !== -1) {
                    el.querySelector(".alert-dot").classList.add("read");
                }
            });
        })();
        var markAll = document.getElementById("mark-all-read");
        if (markAll) {
            markAll.addEventListener("click", function () {
                var ids = [];
                document.querySelectorAll("[data-alert-id]").forEach(function (el) {
                    ids.push(el.getAttribute("data-alert-id"));
                });
                try { localStorage.setItem(READ_KEY, JSON.stringify(ids)); } catch (e) {}
                document.querySelectorAll("[data-alert-id] .alert-dot").forEach(function (d) { d.classList.add("read"); });
                refreshAlertBadge();
            });
        }
        refreshAlertBadge();

        /* History: select-all checkbox */
        var selectAll = document.getElementById("select-all-scans");
        if (selectAll) {
            selectAll.addEventListener("change", function () {
                document.querySelectorAll(".scan-checkbox").forEach(function (cb) { cb.checked = selectAll.checked; });
            });
        }

        /* New scan: auth type conditional fields */
        var authType = document.getElementById("auth_type");
        var authFields = document.getElementById("auth-fields");
        var authValue = document.getElementById("auth_value");
        if (authType && authFields) {
            var AUTH_LABELS = {
                bearer: "Bearer token",
                api_key: "API key",
                cookie: "Cookie (e.g. sessionid=abc123)"
            };
            authType.addEventListener("change", function () {
                var v = authType.value;
                if (v && v !== "none") {
                    authFields.classList.add("show");
                    var label = authFields.querySelector("label");
                    if (label && AUTH_LABELS[v]) label.textContent = AUTH_LABELS[v];
                    if (authValue) authValue.required = true;
                } else {
                    authFields.classList.remove("show");
                    if (authValue) { authValue.required = false; authValue.value = ""; }
                }
            });
        }

        /* New scan: dropzone file name */
        var specInput = document.getElementById("spec_file");
        var specLabel = document.getElementById("spec-file-label");
        if (specInput && specLabel) {
            specInput.addEventListener("change", function () {
                if (specInput.files && specInput.files.length) {
                    specLabel.innerHTML = 'Selected: <span class="file-name"></span>';
                    specLabel.querySelector(".file-name").textContent = specInput.files[0].name;
                }
            });
        }

        /* Vuln guide: code tabs */
        document.querySelectorAll(".code-tabs").forEach(function (tabs) {
            var btns = tabs.querySelectorAll(".code-tab");
            btns.forEach(function (btn) {
                btn.addEventListener("click", function () {
                    btns.forEach(function (b) { b.classList.remove("active"); });
                    btn.classList.add("active");
                    var lang = btn.getAttribute("data-lang");
                    tabs.parentElement.querySelectorAll(".code-block").forEach(function (block) {
                        block.style.display = block.getAttribute("data-lang") === lang ? "" : "none";
                    });
                });
            });
        });

        /* Results page charts (kept from the previous dashboard) */
        if (window.severityData && document.getElementById("severityChart")) {
            new Chart(document.getElementById("severityChart").getContext("2d"), {
                type: "doughnut",
                data: {
                    labels: Object.keys(window.severityData),
                    datasets: [{
                        data: Object.values(window.severityData),
                        backgroundColor: ["#64748b", "#475569", "#c2410c", "#b91c1c"],
                        borderWidth: 2,
                        borderColor: getComputedStyle(document.documentElement).getPropertyValue("--card") || "#ffffff"
                    }]
                },
                options: {
                    responsive: true,
                    plugins: { legend: { position: "bottom", labels: { boxWidth: 12, font: { size: 11 } } } }
                }
            });
        }
        if (window.attackData && document.getElementById("attackTypeChart")) {
            new Chart(document.getElementById("attackTypeChart").getContext("2d"), {
                type: "bar",
                data: {
                    labels: Object.keys(window.attackData),
                    datasets: [{
                        data: Object.values(window.attackData),
                        backgroundColor: "#2563eb",
                        borderRadius: 6
                    }]
                },
                options: {
                    responsive: true,
                    plugins: { legend: { display: false } },
                    scales: { y: { beginAtZero: true, ticks: { stepSize: 1 } } }
                }
            });
        }
        if (window.riskOverTime && document.getElementById("riskOverTimeChart")) {
            new Chart(document.getElementById("riskOverTimeChart").getContext("2d"), {
                type: "line",
                data: {
                    labels: window.riskOverTime.labels,
                    datasets: [{
                        label: "Risk score",
                        data: window.riskOverTime.scores,
                        borderColor: "#2563eb",
                        backgroundColor: "rgba(37,99,235,0.12)",
                        fill: true,
                        tension: 0.3,
                        pointRadius: 3
                    }]
                },
                options: {
                    responsive: true,
                    plugins: { legend: { display: false } },
                    scales: { y: { beginAtZero: true, max: 100 } }
                }
            });
        }
    });
})();
