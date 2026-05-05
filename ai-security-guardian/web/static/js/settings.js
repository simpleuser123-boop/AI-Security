/*
 * settings.js — 系统设置控制器（Phase 7，Prompt §5）
 *
 * 职责：
 *   1. 拉取 /api/settings → 把 editable 值灌入输入控件
 *   2. 绑定 change 事件 → 维护「已修改」脏位
 *   3. 保存：PUT /api/settings；400 时把 errors 挂到对应字段
 *   4. 通知测试：POST /api/settings/test_webhook|test_email
 *
 * schema 由后端下发（SETTINGS_SCHEMA），hint / min / max / step 都由它驱动。
 */
(function () {
  "use strict";

  if (!window.AGApi) return;
  const { fetchApi } = window.AGApi;
  const { escapeHtml, toast } = window.AGUI;

  const state = {
    schema: {},
    saved: {},   // 已保存（来自后端）
    current: {}, // 表单当前值
    dirty: false,
  };

  /* =============================================================
   * DOM 查询帮助
   * ============================================================= */
  function qBind(key) {
    return document.querySelector(`[data-bind="${key}"]`);
  }
  function qDisplay(key) {
    return document.querySelector(`[data-bind-display="${key}"]`);
  }
  function qHint(field) {
    const el = document.querySelector(
      `[data-field="${field}"] .settings-field__hint`
    );
    return el;
  }
  function qLabel(field) {
    const el = document.querySelector(
      `[data-field="${field}"] .settings-field__label`
    );
    return el;
  }
  function qError(field) {
    return document.querySelector(`[data-error="${field}"]`);
  }
  function qRuntime(key) {
    return document.querySelector(`[data-runtime="${key}"]`);
  }

  const statusText = document.getElementById("settings-status-text");
  const statusEl = document.getElementById("settings-status");
  const btnSave = document.getElementById("btn-save");
  const btnReset = document.getElementById("btn-reset");

  /* =============================================================
   * 首次渲染
   * ============================================================= */
  async function loadSnapshot() {
    setStatus("loading", "加载中…");
    try {
      const snap = await fetchApi("/api/settings");
      state.schema = snap.schema || {};
      state.saved = Object.assign({}, snap.editable || {});
      state.current = Object.assign({}, state.saved);
      applySchema(state.schema);
      applyEditableToForm(state.current);
      applyRuntime(snap.runtime || {});
      setDirty(false);
      setStatus("saved", "已从服务器加载最新配置");
    } catch (err) {
      setStatus("err", "加载失败：" + (err.message || ""));
    }
  }

  function applySchema(schema) {
    Object.entries(schema).forEach(([key, spec]) => {
      // 填 label / hint
      const labelNode = qLabel(key);
      if (labelNode && spec.label) labelNode.textContent = spec.label;
      const hintNode = qHint(key);
      if (hintNode && spec.hint) hintNode.textContent = spec.hint;

      // 根据 spec 设置输入控件属性
      const input = qBind(key);
      if (!input) return;
      if (spec.type === "float") {
        input.type = "range";
        input.min = String(spec.min ?? 0);
        input.max = String(spec.max ?? 1);
        input.step = String(spec.step ?? 0.01);
      } else if (spec.type === "bool") {
        // checkbox：无需额外属性
      } else if (spec.type === "email") {
        input.type = "email";
        input.placeholder = spec.placeholder || "";
      } else if (spec.type === "url") {
        input.type = "url";
        input.placeholder = spec.placeholder || "";
      } else if (spec.type === "string") {
        input.type = "text";
        if (spec.pattern) input.pattern = spec.pattern;
        if (spec.placeholder) input.placeholder = spec.placeholder;
      }
    });
  }

  function applyEditableToForm(values) {
    Object.entries(state.schema).forEach(([key, spec]) => {
      const input = qBind(key);
      if (!input) return;
      const raw = values[key];
      if (spec.type === "bool") {
        input.checked = !!raw;
      } else if (spec.type === "float") {
        const v =
          typeof raw === "number"
            ? raw
            : parseFloat(raw) || spec.min || 0;
        input.value = String(v);
        const d = qDisplay(key);
        if (d) d.textContent = v.toFixed(2);
      } else {
        input.value = raw ?? "";
      }
      // 清掉旧错误
      clearError(key);
    });
  }

  function applyRuntime(runtime) {
    const set = (key, render) => {
      const el = qRuntime(key);
      if (!el) return;
      render(el, runtime[key]);
    };
    set("jwt_access_expires_seconds", (el, v) => {
      el.textContent = typeof v === "number" ? `${v} 秒 · ≈ ${fmtDuration(v)}` : "—";
    });
    set("jwt_refresh_expires_seconds", (el, v) => {
      el.textContent = typeof v === "number" ? `${v} 秒 · ≈ ${fmtDuration(v)}` : "—";
    });
    set("api_rate_limit", (el, v) => {
      el.textContent = v || "—";
    });
    set("log_integrity_enabled", (el, v) => {
      el.textContent = v ? "已启用 (SHA-256 链式校验)" : "未启用";
    });
    set("allowed_origins", (el, v) => {
      if (!Array.isArray(v) || !v.length) {
        el.innerHTML = '<li class="text-tertiary">—</li>';
        return;
      }
      el.innerHTML = v
        .map(
          (o) =>
            `<li><code class="mono" style="color: var(--info-blue)">${escapeHtml(o)}</code></li>`
        )
        .join("");
    });
  }

  function fmtDuration(seconds) {
    if (seconds >= 86400) return `${(seconds / 86400).toFixed(1)} 天`;
    if (seconds >= 3600) return `${(seconds / 3600).toFixed(1)} 小时`;
    if (seconds >= 60) return `${Math.round(seconds / 60)} 分`;
    return `${seconds} 秒`;
  }

  /* =============================================================
   * 绑定输入 → 更新 current / dirty 标记
   * ============================================================= */
  function bindInputs() {
    Object.entries(state.schema).forEach(([key, spec]) => {
      const input = qBind(key);
      if (!input) return;
      const onChange = () => {
        const v = readInputValue(input, spec);
        state.current[key] = v;
        const d = qDisplay(key);
        if (d && spec.type === "float") {
          d.textContent = Number(v).toFixed(2);
        }
        clearError(key);
        recomputeDirty();
      };
      input.addEventListener("input", onChange);
      input.addEventListener("change", onChange);
    });
  }

  function readInputValue(input, spec) {
    if (spec.type === "bool") return input.checked;
    if (spec.type === "float") return parseFloat(input.value);
    return input.value;
  }

  function recomputeDirty() {
    const d = Object.keys(state.schema).some((k) => {
      const cur = state.current[k];
      const sav = state.saved[k];
      if (state.schema[k].type === "float") {
        return Number(cur) !== Number(sav);
      }
      return cur !== sav;
    });
    setDirty(d);
  }

  function setDirty(d) {
    state.dirty = d;
    btnSave.disabled = !d;
    btnReset.disabled = !d;
    if (d) setStatus("dirty", "有未保存的修改");
  }

  /* =============================================================
   * 保存 / 重置
   * ============================================================= */
  function diffPayload() {
    const out = {};
    Object.keys(state.schema).forEach((k) => {
      const cur = state.current[k];
      const sav = state.saved[k];
      if (state.schema[k].type === "float") {
        if (Number(cur) !== Number(sav)) out[k] = Number(cur);
      } else if (cur !== sav) {
        out[k] = cur;
      }
    });
    return out;
  }

  async function save() {
    const payload = diffPayload();
    if (!Object.keys(payload).length) return;
    setStatus("loading", "保存中…");
    try {
      const result = await fetchApi("/api/settings", {
        method: "PUT",
        body: payload,
      });
      state.saved = Object.assign({}, result.editable || state.saved);
      state.current = Object.assign({}, state.saved);
      applyEditableToForm(state.current);
      applyRuntime(result.runtime || {});
      setDirty(false);
      toast(
        "已保存：" + (result.updated_keys || []).join(", "),
        "info"
      );
      setStatus("saved", "已保存");
    } catch (err) {
      // 后端 400 带 errors
      const payload = err.payload || {};
      const errs = payload.errors;
      if (errs && typeof errs === "object") {
        Object.entries(errs).forEach(([k, m]) => setError(k, String(m)));
        setStatus("err", "部分字段未通过校验");
      } else {
        toast("保存失败：" + (err.message || ""), "error");
        setStatus("err", err.message || "保存失败");
      }
    }
  }

  function resetToSaved() {
    state.current = Object.assign({}, state.saved);
    applyEditableToForm(state.current);
    setDirty(false);
    setStatus("saved", "已回到已保存的配置");
  }

  /* =============================================================
   * 错误处理 & 状态展示
   * ============================================================= */
  function setError(field, msg) {
    const node = qError(field);
    if (node) node.textContent = msg;
  }
  function clearError(field) {
    const node = qError(field);
    if (node) node.textContent = "";
  }
  function setStatus(kind, msg) {
    if (!statusEl || !statusText) return;
    statusText.textContent = msg;
    statusEl.classList.toggle("settings-actions__status--dirty", kind === "dirty");
    statusEl.classList.toggle("settings-actions__status--saved", kind === "saved");
  }

  /* =============================================================
   * 通知测试
   * ============================================================= */
  function bindTests() {
    document.querySelectorAll("[data-test]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const kind = btn.dataset.test;
        const resultNode = document.querySelector(
          `[data-test-result="${kind}"]`
        );
        if (resultNode) {
          resultNode.textContent = "测试中…";
          resultNode.className = "settings-test-result";
        }
        btn.disabled = true;
        try {
          if (kind === "webhook") {
            const val = qBind("alert_webhook").value.trim();
            const resp = await fetchApi("/api/settings/test_webhook", {
              method: "POST",
              body: val ? { url: val } : {},
            });
            renderTestResult(resultNode, resp, "webhook");
          } else if (kind === "email") {
            const val = qBind("alert_email").value.trim();
            const resp = await fetchApi("/api/settings/test_email", {
              method: "POST",
              body: val ? { email: val } : {},
            });
            renderTestResult(resultNode, resp, "email");
          }
        } catch (err) {
          if (resultNode) {
            resultNode.textContent = "测试失败：" + (err.message || "");
            resultNode.className = "settings-test-result settings-test-result--err";
          }
        } finally {
          btn.disabled = false;
        }
      });
    });
  }

  function renderTestResult(node, resp, kind) {
    if (!node) return;
    if (resp.ok) {
      const parts = [];
      if (kind === "webhook") {
        if (resp.status_code !== undefined) parts.push("HTTP " + resp.status_code);
        if (resp.latency_ms !== undefined) parts.push(resp.latency_ms + " ms");
        node.textContent = "✓ 试投成功 · " + parts.join(" · ");
      } else {
        node.textContent = "✓ " + (resp.note || "测试通过");
      }
      node.className = "settings-test-result settings-test-result--ok";
    } else {
      const mapped = {
        empty: "未配置值",
        invalid_email_format: "邮箱格式不合法",
        timeout: "请求超时",
        request_error: "请求失败",
      };
      node.textContent =
        "× " +
        (mapped[resp.reason] || resp.reason || "测试未通过") +
        (resp.detail ? " (" + resp.detail + ")" : "");
      node.className = "settings-test-result settings-test-result--err";
    }
  }

  /* =============================================================
   * 启动
   * ============================================================= */
  async function init() {
    bindInputs();
    bindTests();
    btnSave.addEventListener("click", save);
    btnReset.addEventListener("click", resetToSaved);

    await loadSnapshot();

    const shell = document.getElementById("settings-shell");
    if (shell) shell.setAttribute("aria-busy", "false");
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
