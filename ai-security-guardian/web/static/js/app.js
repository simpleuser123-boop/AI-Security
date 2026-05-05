/*
 * app.js — 全局壳：侧边栏、导航、状态灯、响应式（Phase 7）
 *
 * 依赖 utils.js（提供 AGApi / AGUI）。
 * 所有业务页都会间接加载本文件（由 base.html 引入）。
 */
(function () {
  "use strict";

  document.addEventListener("DOMContentLoaded", init);

  function init() {
    highlightActiveNav();
    bindSidebarToggle();
    bindLogout();
    renderUsername();
    startStatusPoll();
  }

  function highlightActiveNav() {
    const current = document.body.dataset.page;
    document.querySelectorAll(".sidebar__item").forEach((node) => {
      if (node.dataset.page === current) {
        node.classList.add("is-active");
      } else {
        node.classList.remove("is-active");
      }
    });
  }

  function bindSidebarToggle() {
    const sidebar = document.querySelector(".sidebar");
    if (!sidebar) return;

    const toggle = document.getElementById("menu-toggle");
    if (toggle) {
      toggle.addEventListener("click", () => {
        // 移动端：整体滑入/滑出
        if (window.matchMedia("(max-width: 767px)").matches) {
          sidebar.classList.toggle("is-open");
        } else {
          // 桌面端：收起/展开
          sidebar.classList.toggle("sidebar--collapsed");
        }
      });
    }

    // 点击侧栏外部时在移动端收起
    document.addEventListener("click", (e) => {
      if (!window.matchMedia("(max-width: 767px)").matches) return;
      if (!sidebar.classList.contains("is-open")) return;
      if (sidebar.contains(e.target) || (toggle && toggle.contains(e.target)))
        return;
      sidebar.classList.remove("is-open");
    });
  }

  function bindLogout() {
    const btn = document.getElementById("btn-logout");
    if (btn && window.AGApi) {
      btn.addEventListener("click", (e) => {
        e.preventDefault();
        window.AGApi.logout();
      });
    }
  }

  function renderUsername() {
    const node = document.getElementById("topbar-username");
    if (!node || !window.AGApi) return;
    const name = window.AGApi.getUsername();
    if (name) node.textContent = name;
  }

  /**
   * 每 15 秒查一次健康状态，更新侧栏底部的状态灯。
   * 使用公开 `/api/health` 接口（无需 JWT），失败则置为异常。
   */
  function startStatusPoll() {
    const light = document.querySelector(".sidebar__status .status-light");
    const label = document.getElementById("sidebar-status-label");
    if (!light) return;

    async function check() {
      try {
        const resp = await fetch("/api/health", {
          headers: { Accept: "application/json" },
        });
        if (resp.ok) {
          light.classList.remove("status-light--warn", "status-light--danger");
          if (label) label.textContent = "系统正常";
        } else {
          light.classList.add("status-light--warn");
          light.classList.remove("status-light--danger");
          if (label) label.textContent = "状态异常";
        }
      } catch (_) {
        light.classList.add("status-light--danger");
        light.classList.remove("status-light--warn");
        if (label) label.textContent = "通信失败";
      }
    }

    check();
    setInterval(check, 15000);
  }
})();
