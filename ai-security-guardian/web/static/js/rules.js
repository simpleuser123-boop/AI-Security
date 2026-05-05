/*
 * rules.js — 规则管理控制器（Phase 7，DESIGN.md §8.4）
 *
 * 职责：
 *   1. 加载规则表格，支持 type / enabled / q 筛选
 *   2. 新建 / 编辑抽屉：前端表单校验 + 与后端 /api/rules 对齐
 *   3. 行内启用开关：PATCH /api/rules/<id>/toggle
 *   4. 删除：DELETE /api/rules/<id>，带 confirm
 *   5. 内嵌测试终端：POST /api/rules/test（支持 rule_id 或当前编辑中的草稿）
 *
 * 所有网络调用统一走 window.AGApi.fetchApi。
 */
(function () {
  "use strict";

  if (!window.AGApi) return;
  const { fetchApi } = window.AGApi;
  const { escapeHtml, formatTime, toast } = window.AGUI;

  const RULE_TYPES = ["signature", "threshold", "anomaly"];
  const RULE_ACTIONS = ["alert", "block", "monitor"];
  const RULE_LEVELS = ["low", "medium", "high", "critical"];
  const TYPE_LABEL = {
    signature: "特征",
    threshold: "阈值",
    anomaly: "异常",
  };
  const LEVEL_LABEL = {
    low: "LOW",
    medium: "MEDIUM",
    high: "HIGH",
    critical: "CRITICAL",
  };
  const ACTION_LABEL = {
    alert: "ALERT",
    block: "BLOCK",
    monitor: "MONITOR",
  };
  const PATTERN_HINTS = {
    signature:
      '子串匹配，如 \' OR 1=1；若用 /pattern/ 形式则按正则匹配（需合法 Python 正则）',
    threshold:
      '表达式：<feature> <op> <number>，op ∈ >,>=,<,<=,==,!=；feature ∈ packets_per_sec, avg_packet_size, unique_ports, failed_ratio, payload_entropy, confidence',
    anomaly:
      '逗号分隔的特征名，如 packets_per_sec,failed_ratio；命中条件：这些特征偏离预设常识区间',
  };

  /* =============================================================
   * 状态
   * ============================================================= */
  const state = {
    type: "",
    enabled: "",
    q: "",
    cache: new Map(), // id -> rule
    editingId: null, // null 表示新建
  };

  /* =============================================================
   * DOM
   * ============================================================= */
  const el = {
    tbody: document.getElementById("rules-tbody"),
    countFiltered: document.getElementById("count-filtered"),
    countTotal: document.getElementById("count-total"),
    countEnabled: document.getElementById("count-enabled"),
    activeChips: document.getElementById("active-chips"),
    listStatus: document.getElementById("list-status"),

    btnTypeGroup: document.querySelectorAll(".btn-group [data-type]"),
    selEnabled: document.getElementById("filter-enabled"),
    inputQ: document.getElementById("filter-query"),

    btnRefresh: document.getElementById("btn-refresh"),
    btnNew: document.getElementById("btn-new-rule"),
    btnSeed: document.getElementById("btn-seed"),

    drawer: document.getElementById("rule-drawer"),
    drawerOverlay: document.getElementById("drawer-overlay"),
    drawerClose: document.getElementById("drawer-close"),
    drawerTitle: document.getElementById("drawer-title-text"),

    fName: document.getElementById("f-name"),
    eName: document.getElementById("e-name"),
    fDescription: document.getElementById("f-description"),
    fType: document.getElementById("f-type"),
    fAction: document.getElementById("f-action"),
    fLevel: document.getElementById("f-level"),
    fPriority: document.getElementById("f-priority"),
    fPattern: document.getElementById("f-pattern"),
    ePattern: document.getElementById("e-pattern"),
    fPatternHint: document.getElementById("f-pattern-hint"),
    fEnabled: document.getElementById("f-enabled"),

    tPayload: document.getElementById("t-payload"),
    tSrcIp: document.getElementById("t-src-ip"),
    tFeatures: document.getElementById("t-features"),
    tTerminal: document.getElementById("t-terminal"),
    tInput: document.getElementById("t-input"),
    tRun: document.getElementById("t-run"),

    btnSave: document.getElementById("btn-drawer-save"),
    btnCancel: document.getElementById("btn-drawer-cancel"),
    btnDelete: document.getElementById("btn-drawer-delete"),
  };

  /* =============================================================
   * 工具
   * ============================================================= */
  function debounce(fn, wait) {
    let t = null;
    return function debounced(...args) {
      clearTimeout(t);
      t = setTimeout(() => fn.apply(null, args), wait);
    };
  }

  function typeBadge(type) {
    const safe = RULE_TYPES.includes(type) ? type : "signature";
    return (
      '<span class="badge badge--' +
      safe +
      '">' +
      escapeHtml((TYPE_LABEL[safe] || safe).toUpperCase()) +
      "</span>"
    );
  }

  function levelBadge(level) {
    const safe = RULE_LEVELS.includes(level) ? level : "low";
    return (
      '<span class="badge badge--' +
      safe +
      '">' +
      escapeHtml(LEVEL_LABEL[safe] || safe.toUpperCase()) +
      "</span>"
    );
  }

  function actionBadge(action) {
    const safe = RULE_ACTIONS.includes(action) ? action : "alert";
    return (
      '<span class="badge badge--action-' +
      safe +
      '">' +
      escapeHtml(ACTION_LABEL[safe] || safe.toUpperCase()) +
      "</span>"
    );
  }

  /* =============================================================
   * 渲染
   * ============================================================= */
  function renderCounts(items) {
    const totalFiltered = items.length;
    el.countFiltered.textContent = String(totalFiltered);
  }

  async function refreshGlobalCounts() {
    try {
      const totalItems = await fetchApi("/api/rules");
      el.countTotal.textContent = String(totalItems.length || 0);
      const enabledItems = await fetchApi("/api/rules", {
        query: { enabled: "true" },
      });
      el.countEnabled.textContent = String(enabledItems.length || 0);
    } catch (_) {
      // 计数失败不阻断主流程
    }
  }

  function renderTable(items) {
    if (!items || items.length === 0) {
      el.tbody.innerHTML =
        '<tr><td colspan="10" class="alert-list__empty">' +
        '<div class="empty-state">' +
        '<div class="empty-state__title">当前筛选下暂无规则</div>' +
        '<div class="empty-state__hint">点右上「新建规则」或「生成演示规则」</div>' +
        "</div></td></tr>";
      return;
    }
    el.tbody.innerHTML = items.map(renderRow).join("");
  }

  function renderRow(rule) {
    const id = rule.id || "";
    const enabled = !!rule.enabled;
    const rowClass = enabled ? "" : " table__row--disabled";
    const name = escapeHtml(rule.name || "（未命名）");
    const description = escapeHtml(rule.description || "");
    const pattern = escapeHtml(rule.pattern || "");
    const updated = escapeHtml(formatTime(rule.updated_at));
    const priority = Number.isInteger(rule.priority) ? rule.priority : 100;
    const hits = Number.isInteger(rule.hits) ? rule.hits : 0;

    return (
      '<tr data-id="' +
      escapeHtml(id) +
      '" class="rule-row' +
      rowClass +
      '">' +
      '<td class="center">' +
      '<label class="switch">' +
      '<input type="checkbox" data-action="toggle"' +
      (enabled ? " checked" : "") +
      ' aria-label="启用/禁用" />' +
      '<span class="switch__track"></span>' +
      '<span class="switch__thumb"></span>' +
      "</label>" +
      "</td>" +
      "<td>" +
      '<div style="color: var(--text-primary)">' +
      name +
      "</div>" +
      (description
        ? '<div class="text-tertiary" style="font-size: var(--fs-caption); margin-top: 2px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 360px">' +
          description +
          "</div>"
        : "") +
      "</td>" +
      "<td>" +
      typeBadge(rule.type) +
      "</td>" +
      '<td><code class="table__cell-pattern" title="' +
      pattern +
      '">' +
      pattern +
      "</code></td>" +
      "<td>" +
      actionBadge(rule.action) +
      "</td>" +
      "<td>" +
      levelBadge(rule.level) +
      "</td>" +
      '<td class="num">' +
      priority +
      "</td>" +
      '<td class="num">' +
      hits +
      "</td>" +
      '<td class="mono" style="color: var(--text-tertiary); font-size: var(--fs-caption)">' +
      updated +
      "</td>" +
      '<td><div class="table__actions">' +
      '<button class="btn btn--ghost btn--sm" data-action="test" type="button">测试</button>' +
      '<button class="btn btn--ghost btn--sm" data-action="edit" type="button">编辑</button>' +
      '<button class="btn btn--danger btn--sm" data-action="delete" type="button">删除</button>' +
      "</div></td>" +
      "</tr>"
    );
  }

  function renderChips() {
    const chips = [];
    if (state.type) chips.push(chip("类型：" + (TYPE_LABEL[state.type] || state.type), "type"));
    if (state.enabled !== "")
      chips.push(chip("状态：" + (state.enabled === "true" ? "启用" : "禁用"), "enabled"));
    if (state.q) chips.push(chip('"' + state.q + '"', "q"));
    el.activeChips.innerHTML = chips.join("");
  }

  function chip(label, key) {
    return (
      '<span class="chip">' +
      escapeHtml(label) +
      '<button class="chip__close" type="button" data-clear="' +
      key +
      '" aria-label="清除">×</button>' +
      "</span>"
    );
  }

  /* =============================================================
   * 加载
   * ============================================================= */
  async function loadList() {
    el.tbody.innerHTML =
      '<tr><td colspan="10" class="alert-list__empty"><span class="loader"></span><span style="margin-left: 8px">加载中…</span></td></tr>';
    el.listStatus.textContent = "";
    const query = {};
    if (state.type) query.type = state.type;
    if (state.enabled !== "") query.enabled = state.enabled;
    if (state.q) query.q = state.q;
    try {
      const items = await fetchApi("/api/rules", { query });
      (items || []).forEach((r) => state.cache.set(r.id, r));
      renderTable(items);
      renderCounts(items);
      el.listStatus.textContent = items.length
        ? `共 ${items.length} 条`
        : "";
    } catch (err) {
      el.tbody.innerHTML =
        '<tr><td colspan="10" class="alert-list__empty">' +
        escapeHtml("拉取失败：" + (err.message || "")) +
        "</td></tr>";
    }
  }

  /* =============================================================
   * 筛选交互
   * ============================================================= */
  function bindFilters() {
    el.btnTypeGroup.forEach((btn) => {
      btn.addEventListener("click", () => {
        state.type = btn.dataset.type || "";
        el.btnTypeGroup.forEach((b) =>
          b.classList.toggle("is-active", b === btn)
        );
        applyFilters();
      });
    });

    el.selEnabled.addEventListener("change", () => {
      state.enabled = el.selEnabled.value;
      applyFilters();
    });

    const onSearch = debounce(() => {
      state.q = el.inputQ.value.trim();
      applyFilters();
    }, 250);
    el.inputQ.addEventListener("input", onSearch);

    el.btnRefresh.addEventListener("click", () => {
      applyFilters();
      refreshGlobalCounts();
    });

    el.activeChips.addEventListener("click", (e) => {
      const btn = e.target.closest("[data-clear]");
      if (!btn) return;
      const key = btn.dataset.clear;
      if (key === "type") {
        state.type = "";
        el.btnTypeGroup.forEach((b) =>
          b.classList.toggle("is-active", !b.dataset.type)
        );
      } else if (key === "enabled") {
        state.enabled = "";
        el.selEnabled.value = "";
      } else if (key === "q") {
        state.q = "";
        el.inputQ.value = "";
      }
      applyFilters();
    });
  }

  function applyFilters() {
    renderChips();
    loadList();
  }

  /* =============================================================
   * 表格行交互（开关 / 编辑 / 删除 / 测试）
   * ============================================================= */
  function bindTableHandlers() {
    el.tbody.addEventListener("change", async (e) => {
      const input = e.target.closest('input[data-action="toggle"]');
      if (!input) return;
      const tr = input.closest("tr");
      const id = tr && tr.dataset.id;
      if (!id) return;
      const desired = input.checked;
      input.disabled = true;
      try {
        const updated = await fetchApi(
          "/api/rules/" + encodeURIComponent(id) + "/toggle",
          {
            method: "PATCH",
            body: { enabled: desired },
          }
        );
        state.cache.set(updated.id, updated);
        tr.classList.toggle("table__row--disabled", !updated.enabled);
        toast(
          updated.enabled ? "已启用：" + updated.name : "已禁用：" + updated.name,
          "info"
        );
        refreshGlobalCounts();
      } catch (err) {
        input.checked = !desired;
        toast("切换失败：" + (err.message || ""), "error");
      } finally {
        input.disabled = false;
      }
    });

    el.tbody.addEventListener("click", (e) => {
      const btn = e.target.closest("button[data-action]");
      if (!btn) return;
      const tr = btn.closest("tr");
      const id = tr && tr.dataset.id;
      if (!id) return;
      const action = btn.dataset.action;
      if (action === "edit") {
        openDrawer(id);
      } else if (action === "test") {
        openDrawer(id, { focusTest: true });
      } else if (action === "delete") {
        deleteRule(id);
      }
    });
  }

  async function deleteRule(id) {
    const rule = state.cache.get(id);
    const name = rule ? rule.name : id;
    if (!window.confirm("确认删除规则「" + name + "」？该操作不可撤销。")) {
      return;
    }
    try {
      await fetchApi("/api/rules/" + encodeURIComponent(id), {
        method: "DELETE",
      });
      state.cache.delete(id);
      toast("已删除：" + name, "info");
      applyFilters();
      refreshGlobalCounts();
    } catch (err) {
      toast("删除失败：" + (err.message || ""), "error");
    }
  }

  /* =============================================================
   * 抽屉：新建 / 编辑
   * ============================================================= */
  function openDrawer(id, { focusTest = false } = {}) {
    state.editingId = id || null;
    resetTerminal();
    if (id) {
      const cached = state.cache.get(id);
      el.drawerTitle.textContent = "编辑规则：" + (cached ? cached.name : id);
      el.btnDelete.hidden = false;
      if (cached) fillForm(cached);
      // 再异步取最新
      fetchApi("/api/rules/" + encodeURIComponent(id))
        .then((full) => {
          state.cache.set(id, full);
          fillForm(full);
        })
        .catch(() => {});
    } else {
      el.drawerTitle.textContent = "新建规则";
      el.btnDelete.hidden = true;
      clearForm();
    }
    updatePatternHint();
    showDrawer();
    if (focusTest) {
      requestAnimationFrame(() => {
        document
          .getElementById("section-test")
          .scrollIntoView({ behavior: "smooth", block: "start" });
        el.tInput.focus();
      });
    } else {
      requestAnimationFrame(() => el.fName.focus());
    }
  }

  function showDrawer() {
    el.drawer.classList.add("is-open");
    el.drawerOverlay.classList.add("is-open");
    el.drawer.setAttribute("aria-hidden", "false");
    el.drawerOverlay.setAttribute("aria-hidden", "false");
  }

  function closeDrawer() {
    state.editingId = null;
    el.drawer.classList.remove("is-open");
    el.drawerOverlay.classList.remove("is-open");
    el.drawer.setAttribute("aria-hidden", "true");
    el.drawerOverlay.setAttribute("aria-hidden", "true");
  }

  function clearForm() {
    el.fName.value = "";
    el.fDescription.value = "";
    el.fType.value = "signature";
    el.fAction.value = "alert";
    el.fLevel.value = "high";
    el.fPriority.value = "100";
    el.fPattern.value = "";
    el.fEnabled.checked = true;
    hideError(el.eName);
    hideError(el.ePattern);
  }

  function fillForm(r) {
    el.fName.value = r.name || "";
    el.fDescription.value = r.description || "";
    el.fType.value = RULE_TYPES.includes(r.type) ? r.type : "signature";
    el.fAction.value = RULE_ACTIONS.includes(r.action) ? r.action : "alert";
    el.fLevel.value = RULE_LEVELS.includes(r.level) ? r.level : "high";
    el.fPriority.value = Number.isInteger(r.priority) ? String(r.priority) : "100";
    el.fPattern.value = r.pattern || "";
    el.fEnabled.checked = !!r.enabled;
    hideError(el.eName);
    hideError(el.ePattern);
  }

  function showError(node, msg) {
    if (!node) return;
    node.textContent = msg;
    node.hidden = false;
  }

  function hideError(node) {
    if (!node) return;
    node.textContent = "";
    node.hidden = true;
  }

  function updatePatternHint() {
    const hint = PATTERN_HINTS[el.fType.value] || "";
    el.fPatternHint.textContent = hint;
  }

  function collectForm() {
    return {
      name: el.fName.value.trim(),
      description: el.fDescription.value.trim(),
      type: el.fType.value,
      action: el.fAction.value,
      level: el.fLevel.value,
      priority: Math.max(1, Math.min(999, parseInt(el.fPriority.value, 10) || 100)),
      pattern: el.fPattern.value,
      enabled: el.fEnabled.checked,
    };
  }

  function validateFormClientSide(payload) {
    hideError(el.eName);
    hideError(el.ePattern);
    if (!payload.name) {
      showError(el.eName, "规则名称必填");
      el.fName.focus();
      return false;
    }
    if (!payload.pattern.trim()) {
      showError(el.ePattern, "特征 / 表达式必填");
      el.fPattern.focus();
      return false;
    }
    return true;
  }

  async function saveRule() {
    const payload = collectForm();
    if (!validateFormClientSide(payload)) return;
    el.btnSave.disabled = true;
    try {
      let saved;
      if (state.editingId) {
        saved = await fetchApi(
          "/api/rules/" + encodeURIComponent(state.editingId),
          { method: "PUT", body: payload }
        );
      } else {
        saved = await fetchApi("/api/rules", {
          method: "POST",
          body: payload,
        });
      }
      state.cache.set(saved.id, saved);
      toast(state.editingId ? "已更新：" + saved.name : "已创建：" + saved.name, "info");
      state.editingId = saved.id;
      el.drawerTitle.textContent = "编辑规则：" + saved.name;
      el.btnDelete.hidden = false;
      applyFilters();
      refreshGlobalCounts();
    } catch (err) {
      // 尝试把后端错误挂到最相关字段
      const msg = err.message || "保存失败";
      if (/pattern|threshold|anomaly|signature/i.test(msg)) {
        showError(el.ePattern, msg);
      } else if (/name/i.test(msg)) {
        showError(el.eName, msg);
      } else {
        toast(msg, "error");
      }
    } finally {
      el.btnSave.disabled = false;
    }
  }

  function bindDrawerHandlers() {
    el.btnNew.addEventListener("click", () => openDrawer(null));
    el.drawerClose.addEventListener("click", closeDrawer);
    el.drawerOverlay.addEventListener("click", closeDrawer);
    el.btnCancel.addEventListener("click", closeDrawer);
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && el.drawer.classList.contains("is-open")) {
        closeDrawer();
      }
    });
    el.fType.addEventListener("change", updatePatternHint);
    el.btnSave.addEventListener("click", saveRule);
    el.btnDelete.addEventListener("click", () => {
      if (state.editingId) {
        deleteRule(state.editingId);
        closeDrawer();
      }
    });
  }

  /* =============================================================
   * 内嵌测试终端
   * ============================================================= */
  function resetTerminal() {
    el.tTerminal.querySelectorAll(".terminal__line").forEach((n) => n.remove());
    addTerminalLine("终端就绪：输入样本后运行测试。", "dim");
    el.tInput.value = "";
    el.tPayload.value = "";
    el.tSrcIp.value = "";
    el.tFeatures.value = "";
  }

  function addTerminalLine(text, kind = "") {
    const line = document.createElement("div");
    line.className = "terminal__line";
    if (kind === "cmd") line.classList.add("terminal__line--cmd");
    if (kind === "ok") line.classList.add("terminal__line--ok");
    if (kind === "err") line.classList.add("terminal__line--err");
    if (kind === "dim") line.classList.add("text-tertiary");
    line.textContent = text;
    // 插到 prompt 之前
    const prompt = el.tTerminal.querySelector(".terminal__prompt");
    el.tTerminal.insertBefore(line, prompt);
    el.tTerminal.scrollTop = el.tTerminal.scrollHeight;
  }

  function buildSample() {
    const featuresRaw = el.tFeatures.value.trim();
    let features = undefined;
    if (featuresRaw) {
      try {
        features = JSON.parse(featuresRaw);
        if (typeof features !== "object" || Array.isArray(features)) {
          throw new Error("features 必须是 JSON 对象");
        }
      } catch (err) {
        throw new Error("features 不是合法 JSON：" + err.message);
      }
    }
    const sample = {};
    const payload = el.tPayload.value || el.tInput.value;
    if (payload) sample.payload = payload;
    if (el.tSrcIp.value.trim()) sample.src_ip = el.tSrcIp.value.trim();
    if (features !== undefined) sample.features = features;
    return sample;
  }

  async function runTest() {
    let sample;
    try {
      sample = buildSample();
    } catch (err) {
      addTerminalLine(err.message, "err");
      return;
    }
    addTerminalLine(
      "$ test " +
        (state.editingId ? "rule_id=" + state.editingId : "<草稿规则>") +
        " sample=" +
        JSON.stringify(sample),
      "cmd"
    );
    // 若抽屉里是已保存规则且没有改动，直接用 rule_id；否则发草稿
    const payload = {
      sample,
    };
    if (state.editingId) {
      payload.rule_id = state.editingId;
    } else {
      const draft = collectForm();
      if (!validateFormClientSide(draft)) {
        addTerminalLine("前端校验未通过，请先补全规则字段", "err");
        return;
      }
      payload.rule = draft;
    }
    try {
      const result = await fetchApi("/api/rules/test", {
        method: "POST",
        body: payload,
      });
      const kind = result.matched ? "ok" : "dim";
      addTerminalLine(
        (result.matched ? "✓ 命中" : "· 未命中") +
          "  [" +
          (result.rule_type || "") +
          "]  " +
          (result.reason || ""),
        kind
      );
    } catch (err) {
      addTerminalLine("× 测试失败：" + (err.message || ""), "err");
    }
  }

  function bindTerminalHandlers() {
    el.tRun.addEventListener("click", runTest);
    el.tInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        runTest();
      }
    });
  }

  /* =============================================================
   * DEBUG seed
   * ============================================================= */
  async function maybeEnableSeedButton() {
    if (!el.btnSeed) return;
    // 用已认证的 OPTIONS 探针最简单，但后端未暴露 OPTIONS 逻辑细分；
    // 改为一次受鉴权的 GET /api/alerts/_seed 的兄弟 —— 这里直接用后端的
    // capabilities：只要 DEBUG，alerts 的 _seed 也开放；共享门控即可。
    try {
      const resp = await fetch("/api/alerts/_seed", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: "Bearer " + window.AGApi.getToken(),
        },
        body: JSON.stringify({ count: 0 }),
      });
      if (resp.status === 201 || resp.status === 400) {
        el.btnSeed.hidden = false;
      }
    } catch (_) {
      // 网络异常则保持隐藏
    }
  }

  function bindSeedButton() {
    if (!el.btnSeed) return;
    el.btnSeed.addEventListener("click", async () => {
      try {
        const r = await fetchApi("/api/rules/_seed", { method: "POST" });
        toast("已生成 " + (r.created || 0) + " 条演示规则", "info");
        applyFilters();
        refreshGlobalCounts();
      } catch (err) {
        toast("生成失败：" + (err.message || ""), "error");
      }
    });
  }

  /* =============================================================
   * 启动
   * ============================================================= */
  async function init() {
    bindFilters();
    bindTableHandlers();
    bindDrawerHandlers();
    bindTerminalHandlers();
    bindSeedButton();

    await loadList();
    refreshGlobalCounts();
    maybeEnableSeedButton();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
