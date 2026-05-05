/*
 * utils.js — 前端通用工具（Phase 7）
 *
 * 职责：
 *   1. 统一的 `fetchApi`：附带 JWT、处理 401/403/429
 *   2. Token 读写（localStorage）与跳转登录页
 *   3. 简单 toast / 时间格式化 / 安全 HTML 转义
 *
 * 所有业务页面只应通过本文件暴露的 `window.AGApi` / `window.AGUI` 访问。
 */
(function () {
  "use strict";

  const TOKEN_KEY = "ag_access_token";
  const REFRESH_KEY = "ag_refresh_token";
  const USER_KEY = "ag_username";

  /* ------------------------- Token 管理 ------------------------- */
  function getToken() {
    return localStorage.getItem(TOKEN_KEY) || "";
  }

  function getRefreshToken() {
    return localStorage.getItem(REFRESH_KEY) || "";
  }

  function setTokens({ access_token, refresh_token, username }) {
    if (access_token) localStorage.setItem(TOKEN_KEY, access_token);
    if (refresh_token) localStorage.setItem(REFRESH_KEY, refresh_token);
    if (username) localStorage.setItem(USER_KEY, username);
  }

  function clearTokens() {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(REFRESH_KEY);
    localStorage.removeItem(USER_KEY);
  }

  function getUsername() {
    return localStorage.getItem(USER_KEY) || "";
  }

  function gotoLogin(message) {
    clearTokens();
    if (message) {
      sessionStorage.setItem("ag_login_message", message);
    }
    // 避免循环跳转
    if (!location.pathname.endsWith("/login")) {
      location.href = "/login";
    }
  }

  /* ------------------------- fetchApi --------------------------- */
  /**
   * 统一的 REST 调用封装。
   * @param {string} path 以 `/api/` 开头的路径
   * @param {{
   *   method?: string,
   *   body?: any,
   *   headers?: Record<string,string>,
   *   query?: Record<string,any>,
   *   skipAuth?: boolean,
   *   returnResponse?: boolean,
   * }} options
   * @returns {Promise<any>} 默认返回解析后的 JSON；returnResponse=true 时返回
   *   `{data, status, headers}`（headers 为 Headers 对象）。非 2xx 会 reject Error。
   */
  async function fetchApi(path, options = {}) {
    const {
      method = "GET",
      body,
      headers = {},
      query,
      skipAuth = false,
      returnResponse = false,
    } = options;

    // 查询字符串组装
    let url = path;
    if (query && typeof query === "object") {
      const qs = new URLSearchParams();
      Object.entries(query).forEach(([k, v]) => {
        if (v === undefined || v === null || v === "") return;
        qs.append(k, String(v));
      });
      const suffix = qs.toString();
      if (suffix) url += (url.includes("?") ? "&" : "?") + suffix;
    }

    const finalHeaders = { Accept: "application/json", ...headers };
    if (body && !(body instanceof FormData)) {
      finalHeaders["Content-Type"] = "application/json";
    }
    if (!skipAuth) {
      const token = getToken();
      if (token) finalHeaders["Authorization"] = "Bearer " + token;
    }

    let resp;
    try {
      resp = await fetch(url, {
        method,
        headers: finalHeaders,
        body: body
          ? body instanceof FormData
            ? body
            : JSON.stringify(body)
          : undefined,
        credentials: "same-origin",
      });
    } catch (networkErr) {
      throw new Error("网络异常：" + networkErr.message);
    }

    // 401：尝试刷新令牌一次，失败则跳登录
    if (resp.status === 401 && !skipAuth && !options._retry) {
      const refreshed = await tryRefresh();
      if (refreshed) {
        return fetchApi(path, { ...options, _retry: true });
      }
      gotoLogin("登录状态已失效，请重新登录");
      throw new Error("未授权");
    }

    if (resp.status === 403) {
      toast("没有权限访问此资源", "error");
      throw new Error("Forbidden");
    }

    if (resp.status === 429) {
      toast("操作过于频繁，请稍后再试", "warning");
      throw new Error("Rate limited");
    }

    const contentType = resp.headers.get("content-type") || "";
    const isJson = contentType.includes("application/json");
    const payload = isJson ? await resp.json().catch(() => ({})) : await resp.text();

    if (!resp.ok) {
      const msg =
        (isJson && payload && payload.error) ||
        (typeof payload === "string" ? payload : "") ||
        "请求失败";
      const err = new Error(msg);
      err.status = resp.status;
      err.payload = payload;
      throw err;
    }

    if (returnResponse) {
      return { data: payload, status: resp.status, headers: resp.headers };
    }
    return payload;
  }

  async function tryRefresh() {
    const refresh = getRefreshToken();
    if (!refresh) return false;
    try {
      const resp = await fetch("/api/auth/refresh", {
        method: "POST",
        headers: {
          Accept: "application/json",
          Authorization: "Bearer " + refresh,
        },
      });
      if (!resp.ok) return false;
      const data = await resp.json();
      if (data.access_token) {
        localStorage.setItem(TOKEN_KEY, data.access_token);
        return true;
      }
      return false;
    } catch (_) {
      return false;
    }
  }

  /* ------------------------- UI 工具 --------------------------- */

  function ensureToastContainer() {
    let el = document.getElementById("ag-toast-container");
    if (!el) {
      el = document.createElement("div");
      el.id = "ag-toast-container";
      el.className = "toast-container";
      document.body.appendChild(el);
    }
    return el;
  }

  /**
   * @param {string} message
   * @param {"info"|"error"|"warning"} type
   * @param {number} duration
   */
  function toast(message, type = "info", duration = 3200) {
    const container = ensureToastContainer();
    const el = document.createElement("div");
    el.className = "toast" + (type === "error"
      ? " toast--error"
      : type === "warning"
      ? " toast--warning"
      : "");
    el.textContent = message;
    container.appendChild(el);
    setTimeout(() => {
      el.style.opacity = "0";
      el.style.transition = "opacity 0.2s ease";
      setTimeout(() => el.remove(), 220);
    }, duration);
  }

  function escapeHtml(value) {
    if (value === null || value === undefined) return "";
    return String(value)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;");
  }

  function formatTime(iso) {
    if (!iso) return "";
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso;
    const pad = (n) => String(n).padStart(2, "0");
    return (
      d.getFullYear() +
      "-" +
      pad(d.getMonth() + 1) +
      "-" +
      pad(d.getDate()) +
      " " +
      pad(d.getHours()) +
      ":" +
      pad(d.getMinutes()) +
      ":" +
      pad(d.getSeconds())
    );
  }

  function levelBadge(level) {
    const safe = ["low", "medium", "high", "critical"].includes(level)
      ? level
      : "low";
    return (
      '<span class="badge badge--' +
      safe +
      '">' +
      safe.toUpperCase() +
      "</span>"
    );
  }

  /* ------------------------- 登录守卫 --------------------------- */

  /**
   * 在受保护页面加载时调用。若无 token，立即跳登录。
   * 返回 true 表示已认证，可以继续初始化业务。
   */
  function requireAuth() {
    if (!getToken()) {
      gotoLogin();
      return false;
    }
    return true;
  }

  async function logout() {
    clearTokens();
    location.href = "/login";
  }

  /* ------------------------- 导出 ------------------------------- */
  window.AGApi = {
    fetchApi,
    getToken,
    getRefreshToken,
    setTokens,
    clearTokens,
    getUsername,
    requireAuth,
    logout,
    gotoLogin,
  };

  window.AGUI = {
    toast,
    escapeHtml,
    formatTime,
    levelBadge,
  };
})();
