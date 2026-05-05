/*
 * alerts.js — 告警中心控制器（Phase 7，DESIGN.md §8.2）
 *
 * 职责：
 *   1. 维护筛选状态（level / status / range / type / q）并与 UI 双向绑定
 *   2. 调用 /api/alerts 拉取分页列表（读取 X-Total-Count 响应头）
 *   3. 点击列表项 → 调 /api/alerts/<id> 拉详情 → 填充右侧抽屉
 *   4. 抽屉操作：确认 / 处理 / 忽略 / 封禁来源 IP（联动 /api/banned_ips）
 *   5. 订阅 WebSocket `alert` / `alert_updated` 事件，实时前插与状态同步
 *
 * 不直接操作 DOM 之外的全局状态；所有网络调用统一走 window.AGApi.fetchApi。
 */
(function () {
  "use strict";

  if (!window.AGApi) return;
  const { fetchApi } = window.AGApi;
  const { escapeHtml, formatTime, levelBadge, toast } = window.AGUI;

  const LEVELS = ["low", "medium", "high", "critical"];
  const STATUSES = ["open", "acknowledged", "resolved", "ignored"];
  const STATUS_LABEL = {
    open: "未处理",
    acknowledged: "已确认",
    resolved: "已处理",
    ignored: "已忽略",
  };
  const PAGE_SIZE = 50;
  const AUTO_REFRESH_MS = 15000;

  /* =============================================================
   * 状态
   * ============================================================= */
  const state = {
    level: "",
    status: "",
    range: "24h",
    type: "",
    q: "",
    offset: 0,
    total: 0,
    cache: new Map(), // id -> alert
    activeId: null,
    autoRefresh: false,
    autoTimer: null,
  };

  /* =============================================================
   * DOM 引用
   * ============================================================= */
  const el = {
    list: document.getElementById("alert-list"),
    countFiltered: document.getElementById("count-filtered"),
    countTotal: document.getElementById("count-total"),
    countOpen: document.getElementById("count-open"),
    activeChips: document.getElementById("active-chips"),
    listStatus: document.getElementById("list-status"),

    btnLevelGroup: document.querySelectorAll(".btn-group [data-level]"),
    selStatus: document.getElementById("filter-status"),
    selRange: document.getElementById("filter-range"),
    selType: document.getElementById("filter-type"),
    inputQ: document.getElementById("filter-query"),

    btnRefresh: document.getElementById("btn-refresh"),
    btnLoadMore: document.getElementById("btn-load-more"),
    btnSeed: document.getElementById("btn-seed"),
    toggleAuto: document.getElementById("toggle-autorefresh"),

    drawer: document.getElementById("alert-drawer"),
    drawerOverlay: document.getElementById("drawer-overlay"),
    drawerClose: document.getElementById("drawer-close"),

    dTitle: document.getElementById("drawer-title-text"),
    dLevelBadge: document.getElementById("drawer-level-badge"),
    dId: document.getElementById("d-id"),
    dTime: document.getElementById("d-time"),
    dType: document.getElementById("d-type"),
    dStatus: document.getElementById("d-status"),
    dSource: document.getElementById("d-source"),
    dDest: document.getElementById("d-dest"),
    dProto: document.getElementById("d-proto"),
    dAction: document.getElementById("d-action"),
    dModel: document.getElementById("d-model"),
    dConfidence: document.getElementById("d-confidence"),
    dConfidenceBar: document.getElementById("d-confidence-bar"),
    dExplanation: document.getElementById("d-explanation"),
    dFeatures: document.querySelector("#d-features tbody"),
    dRaw: document.getElementById("d-raw"),
    dIndicatorsSection: document.getElementById("d-indicators-section"),
    dIndicators: document.getElementById("d-indicators"),
    dHistorySection: document.getElementById("d-history-section"),
    dHistory: document.getElementById("d-history"),

    btnIgnore: document.getElementById("btn-ignore"),
    btnAck: document.getElementById("btn-ack"),
    btnResolve: document.getElementById("btn-resolve"),
    btnBan: document.getElementById("btn-ban"),
  };

  /* =============================================================
   * 工具
   * ============================================================= */
  function rangeSince(key) {
    const now = Date.now();
    switch (key) {
      case "1h":
        return new Date(now - 60 * 60 * 1000).toISOString();
      case "24h":
        return new Date(now - 24 * 60 * 60 * 1000).toISOString();
      case "7d":
        return new Date(now - 7 * 24 * 60 * 60 * 1000).toISOString();
      case "30d":
        return new Date(now - 30 * 24 * 60 * 60 * 1000).toISOString();
      case "all":
      default:
        return "";
    }
  }

  function debounce(fn, wait) {
    let t = null;
    return function debounced(...args) {
      clearTimeout(t);
      t = setTimeout(() => fn.apply(null, args), wait);
    };
  }

  function levelText(level) {
    return (
      { low: "低危", medium: "中危", high: "高危", critical: "严重" }[level] ||
      level
    );
  }

  function statusText(status) {
    return STATUS_LABEL[status] || status || "—";
  }

  function statusPill(status) {
    const safe = STATUSES.includes(status) ? status : "open";
    return (
      '<span class="alert-item__status alert-item__status--' +
      safe +
      '">' +
      escapeHtml(statusText(safe)) +
      "</span>"
    );
  }

  /* =============================================================
   * 渲染
   * ============================================================= */
  function renderList(items, { append = false, markNew = false } = {}) {
    if (!append && (!items || items.length === 0)) {
      el.list.innerHTML =
        '<li class="alert-list__empty">' +
        '<div class="empty-state">' +
        '<div class="empty-state__title">当前筛选下暂无告警</div>' +
        '<div class="empty-state__hint">调整筛选条件，或等待新事件到达</div>' +
        "</div></li>";
      return;
    }
    const html = items.map((item) => renderListItem(item, markNew)).join("");
    if (append) {
      el.list.insertAdjacentHTML("beforeend", html);
    } else {
      el.list.innerHTML = html;
    }
  }

  function renderListItem(alert, markNew = false) {
    const level = LEVELS.includes(alert.level) ? alert.level : "low";
    const title = escapeHtml(alert.title || alert.summary || "未分类告警");
    const summary = escapeHtml(alert.summary || "");
    const sourceIp = alert.source_ip ? escapeHtml(alert.source_ip) : "";
    const time = escapeHtml(formatTime(alert.timestamp));
    const threatType = escapeHtml(alert.threat_type || "unknown");
    const newClass = markNew ? " alert-item--new" : "";

    return (
      '<li class="alert-item alert-item--clickable alert-item--' +
      level +
      newClass +
      '" data-id="' +
      escapeHtml(alert.id || "") +
      '" role="listitem" tabindex="0">' +
      '<span class="alert-item__stripe"></span>' +
      '<div class="alert-item__content">' +
      '<div class="alert-item__title-row">' +
      levelBadge(level) +
      '<span class="alert-item__title">' +
      title +
      "</span>" +
      "</div>" +
      (summary && summary !== title
        ? '<p class="alert-item__summary">' + summary + "</p>"
        : "") +
      '<div class="alert-item__meta">' +
      "<span>" +
      time +
      "</span>" +
      (sourceIp
        ? '<span class="alert-item__ip">' + sourceIp + "</span>"
        : "") +
      '<span>' +
      threatType +
      "</span>" +
      statusPill(alert.status) +
      "</div>" +
      "</div>" +
      '<div class="alert-item__side">' +
      '<button class="btn btn--ghost btn--sm" data-action="detail" type="button">查看</button>' +
      "</div>" +
      "</li>"
    );
  }

  function renderChips() {
    const chips = [];
    if (state.level)
      chips.push(chip("等级：" + levelText(state.level), "level"));
    if (state.status)
      chips.push(chip("状态：" + statusText(state.status), "status"));
    if (state.type) chips.push(chip("类型：" + state.type, "type"));
    if (state.q) chips.push(chip('"' + state.q + '"', "q"));
    if (state.range && state.range !== "all")
      chips.push(chip("近 " + state.range, "range", false));
    el.activeChips.innerHTML = chips.join("");
  }

  function chip(label, key, removable = true) {
    return (
      '<span class="chip">' +
      escapeHtml(label) +
      (removable
        ? '<button class="chip__close" type="button" data-clear="' +
          key +
          '" aria-label="清除">×</button>'
        : "") +
      "</span>"
    );
  }

  function renderCounts({ filteredTotal }) {
    if (filteredTotal !== undefined) {
      el.countFiltered.textContent = String(filteredTotal);
      state.total = filteredTotal;
    }
  }

  async function refreshGlobalCounts() {
    try {
      // 全量（不带 level/status/type/q/range）用于显示"全部"与"未处理"基线
      const { data, headers } = await fetchApi("/api/alerts", {
        query: { limit: 1, offset: 0 },
        returnResponse: true,
      });
      void data;
      const total = parseInt(headers.get("X-Total-Count") || "0", 10);
      el.countTotal.textContent = String(total || 0);

      const { headers: openHeaders } = await fetchApi("/api/alerts", {
        query: { limit: 1, offset: 0, status: "open" },
        returnResponse: true,
      });
      const openCount = parseInt(openHeaders.get("X-Total-Count") || "0", 10);
      el.countOpen.textContent = String(openCount || 0);
    } catch (_) {
      // 计数失败不阻断主流程
    }
  }

  /* =============================================================
   * 数据获取
   * ============================================================= */
  async function loadList({ append = false } = {}) {
    if (!append) {
      el.list.innerHTML =
        '<li class="alert-list__empty"><span class="loader"></span><span style="margin-left: 8px">加载中…</span></li>';
      state.offset = 0;
    }
    el.listStatus.textContent = "";

    const query = {
      limit: PAGE_SIZE,
      offset: state.offset,
    };
    if (state.level) query.level = state.level;
    if (state.status) query.status = state.status;
    if (state.type) query.type = state.type;
    if (state.q) query.q = state.q;
    const since = rangeSince(state.range);
    if (since) query.since = since;

    try {
      const { data, headers } = await fetchApi("/api/alerts", {
        query,
        returnResponse: true,
      });
      const items = Array.isArray(data) ? data : [];
      items.forEach((it) => state.cache.set(it.id, it));

      const total = parseInt(headers.get("X-Total-Count") || "0", 10);
      renderCounts({ filteredTotal: total });
      renderList(items, { append });

      // 分页按钮
      const loaded = state.offset + items.length;
      if (loaded < total) {
        el.btnLoadMore.hidden = false;
        el.btnLoadMore.textContent = `加载更多（已显示 ${loaded} / ${total}）`;
      } else {
        el.btnLoadMore.hidden = true;
      }
      el.listStatus.textContent = total
        ? `共 ${total} 条，本页 ${items.length}`
        : "";
    } catch (err) {
      el.list.innerHTML =
        '<li class="alert-list__empty">' +
        escapeHtml("拉取失败：" + (err.message || "")) +
        "</li>";
      el.btnLoadMore.hidden = true;
    }
  }

  async function loadTypes() {
    try {
      const types = await fetchApi("/api/alerts/types");
      const current = state.type;
      const frag = ['<option value="">全部类型</option>'];
      (types || []).forEach((t) => {
        frag.push(
          '<option value="' +
            escapeHtml(t) +
            '"' +
            (t === current ? " selected" : "") +
            ">" +
            escapeHtml(t) +
            "</option>"
        );
      });
      el.selType.innerHTML = frag.join("");
    } catch (_) {
      // 忽略——筛选器降级为只显示"全部类型"
    }
  }

  /* =============================================================
   * 筛选交互
   * ============================================================= */
  function bindFilterHandlers() {
    el.btnLevelGroup.forEach((btn) => {
      btn.addEventListener("click", () => {
        const level = btn.dataset.level || "";
        state.level = level;
        el.btnLevelGroup.forEach((b) => b.classList.toggle("is-active", b === btn));
        applyFilters();
      });
    });

    el.selStatus.addEventListener("change", () => {
      state.status = el.selStatus.value;
      applyFilters();
    });
    el.selRange.addEventListener("change", () => {
      state.range = el.selRange.value;
      applyFilters();
    });
    el.selType.addEventListener("change", () => {
      state.type = el.selType.value;
      applyFilters();
    });

    const onSearch = debounce(() => {
      state.q = el.inputQ.value.trim();
      applyFilters();
    }, 250);
    el.inputQ.addEventListener("input", onSearch);

    el.btnRefresh.addEventListener("click", () => {
      applyFilters();
      loadTypes();
      refreshGlobalCounts();
    });
    el.btnLoadMore.addEventListener("click", () => {
      state.offset += PAGE_SIZE;
      loadList({ append: true });
    });

    el.activeChips.addEventListener("click", (e) => {
      const btn = e.target.closest("[data-clear]");
      if (!btn) return;
      const key = btn.dataset.clear;
      if (key === "level") {
        state.level = "";
        el.btnLevelGroup.forEach((b) =>
          b.classList.toggle("is-active", !b.dataset.level)
        );
      } else if (key === "status") {
        state.status = "";
        el.selStatus.value = "";
      } else if (key === "type") {
        state.type = "";
        el.selType.value = "";
      } else if (key === "q") {
        state.q = "";
        el.inputQ.value = "";
      }
      applyFilters();
    });

    el.toggleAuto.addEventListener("change", () => {
      state.autoRefresh = el.toggleAuto.checked;
      if (state.autoRefresh) {
        state.autoTimer = setInterval(applyFilters, AUTO_REFRESH_MS);
      } else if (state.autoTimer) {
        clearInterval(state.autoTimer);
        state.autoTimer = null;
      }
    });
  }

  function applyFilters() {
    renderChips();
    state.offset = 0;
    loadList({ append: false });
  }

  /* =============================================================
   * 列表点击 → 抽屉
   * ============================================================= */
  function bindListHandlers() {
    el.list.addEventListener("click", (e) => {
      const li = e.target.closest(".alert-item");
      if (!li) return;
      const id = li.dataset.id;
      if (!id) return;
      openDrawer(id);
    });
    el.list.addEventListener("keydown", (e) => {
      if (e.key !== "Enter" && e.key !== " ") return;
      const li = e.target.closest(".alert-item");
      if (!li) return;
      e.preventDefault();
      openDrawer(li.dataset.id);
    });
  }

  /* =============================================================
   * 抽屉
   * ============================================================= */
  async function openDrawer(id) {
    state.activeId = id;
    highlightActive(id);
    // 先展示缓存，再拉最新详情
    const cached = state.cache.get(id);
    if (cached) populateDrawer(cached);
    showDrawer();
    try {
      const full = await fetchApi("/api/alerts/" + encodeURIComponent(id));
      state.cache.set(id, full);
      populateDrawer(full);
    } catch (err) {
      toast("获取告警详情失败：" + (err.message || ""), "error");
    }
  }

  function highlightActive(id) {
    el.list.querySelectorAll(".alert-item").forEach((li) => {
      li.classList.toggle("is-active", li.dataset.id === id);
    });
  }

  function showDrawer() {
    el.drawer.classList.add("is-open");
    el.drawerOverlay.classList.add("is-open");
    el.drawer.setAttribute("aria-hidden", "false");
    el.drawerOverlay.setAttribute("aria-hidden", "false");
  }

  function closeDrawer() {
    state.activeId = null;
    el.drawer.classList.remove("is-open");
    el.drawerOverlay.classList.remove("is-open");
    el.drawer.setAttribute("aria-hidden", "true");
    el.drawerOverlay.setAttribute("aria-hidden", "true");
    el.list
      .querySelectorAll(".alert-item.is-active")
      .forEach((li) => li.classList.remove("is-active"));
  }

  function populateDrawer(alert) {
    const level = LEVELS.includes(alert.level) ? alert.level : "low";
    el.dTitle.textContent = alert.title || alert.summary || "告警详情";
    el.dLevelBadge.innerHTML = levelBadge(level);

    el.dId.textContent = alert.id || "—";
    el.dTime.textContent = formatTime(alert.timestamp) || "—";
    el.dType.textContent = alert.threat_type || "—";
    el.dStatus.innerHTML = statusPill(alert.status);

    const src = alert.source_ip
      ? alert.source_ip + (alert.source_port ? ":" + alert.source_port : "")
      : "—";
    const dst = alert.dest_ip
      ? alert.dest_ip + (alert.dest_port ? ":" + alert.dest_port : "")
      : "—";
    el.dSource.textContent = src;
    el.dDest.textContent = dst;
    el.dProto.textContent = alert.protocol || "—";
    el.dAction.textContent = alert.recommended_action || "—";

    el.dModel.textContent = alert.model_version || "—";
    const conf = typeof alert.confidence === "number" ? alert.confidence : null;
    el.dConfidence.textContent =
      conf === null ? "—" : (conf * 100).toFixed(1) + " %";
    el.dConfidenceBar.style.width =
      conf === null ? "0%" : Math.min(100, Math.max(0, conf * 100)) + "%";

    el.dExplanation.textContent = alert.explanation || "（模型未提供推理说明）";

    // 特征表
    const features = alert.features || {};
    const rows = Object.keys(features).map((k) => {
      const v = features[k];
      const rendered =
        typeof v === "number"
          ? Number.isInteger(v)
            ? v.toLocaleString()
            : v.toFixed(3)
          : escapeHtml(String(v));
      return "<tr><th>" + escapeHtml(k) + "</th><td>" + rendered + "</td></tr>";
    });
    el.dFeatures.innerHTML =
      rows.length > 0
        ? rows.join("")
        : '<tr><td colspan="2" class="text-tertiary" style="text-align:center">无特征数据</td></tr>';

    // 原始数据
    el.dRaw.textContent = alert.raw || "（无原始载荷）";

    // IOC
    const indicators = Array.isArray(alert.indicators) ? alert.indicators : [];
    if (indicators.length) {
      el.dIndicatorsSection.hidden = false;
      el.dIndicators.innerHTML = indicators
        .map((x) => "<li>" + escapeHtml(String(x)) + "</li>")
        .join("");
    } else {
      el.dIndicatorsSection.hidden = true;
    }

    // 历史
    const history = Array.isArray(alert.history) ? alert.history : [];
    if (history.length) {
      el.dHistorySection.hidden = false;
      el.dHistory.innerHTML = history
        .map(
          (h) =>
            '<li class="timeline__item">' +
            '<span class="timeline__time">' +
            escapeHtml(formatTime(h.timestamp)) +
            "</span>" +
            '<span>' +
            escapeHtml(statusText(h.status)) +
            "</span></li>"
        )
        .join("");
    } else {
      el.dHistorySection.hidden = true;
    }

    // 按钮可用态：已处理 / 已忽略不能再点状态按钮
    const terminal = alert.status === "resolved" || alert.status === "ignored";
    el.btnAck.disabled = alert.status !== "open";
    el.btnResolve.disabled = terminal;
    el.btnIgnore.disabled = terminal;
    el.btnBan.disabled = !alert.source_ip;
  }

  function bindDrawerHandlers() {
    el.drawerClose.addEventListener("click", closeDrawer);
    el.drawerOverlay.addEventListener("click", closeDrawer);
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && el.drawer.classList.contains("is-open")) {
        closeDrawer();
      }
    });

    el.btnAck.addEventListener("click", () => transition("acknowledged"));
    el.btnResolve.addEventListener("click", () => transition("resolved"));
    el.btnIgnore.addEventListener("click", () => transition("ignored"));
    el.btnBan.addEventListener("click", banActiveSource);
  }

  async function transition(newStatus) {
    if (!state.activeId) return;
    try {
      const updated = await fetchApi(
        "/api/alerts/" + encodeURIComponent(state.activeId) + "/status",
        {
          method: "POST",
          body: { status: newStatus },
        }
      );
      state.cache.set(updated.id, updated);
      populateDrawer(updated);
      updateListItemStatus(updated);
      toast("已更新为：" + statusText(newStatus), "info");
      refreshGlobalCounts();
    } catch (err) {
      toast("状态更新失败：" + (err.message || ""), "error");
    }
  }

  async function banActiveSource() {
    const alert = state.cache.get(state.activeId);
    if (!alert || !alert.source_ip) return;
    if (
      !window.confirm(
        "确认封禁来源 IP " + alert.source_ip + "？\n该操作会立即生效。"
      )
    ) {
      return;
    }
    try {
      await fetchApi("/api/banned_ips", {
        method: "POST",
        body: {
          ip: alert.source_ip,
          reason: "来自告警 " + (alert.id || "") + "：" + (alert.title || ""),
        },
      });
      toast("已封禁 " + alert.source_ip, "info");
      // 联动：自动标为已处理
      await transition("resolved");
    } catch (err) {
      toast("封禁失败：" + (err.message || ""), "error");
    }
  }

  function updateListItemStatus(alert) {
    const li = el.list.querySelector(
      '.alert-item[data-id="' + CSS.escape(alert.id) + '"]'
    );
    if (!li) return;
    const pill = li.querySelector(".alert-item__status");
    if (pill) {
      pill.className =
        "alert-item__status alert-item__status--" + (alert.status || "open");
      pill.textContent = statusText(alert.status);
    }
  }

  /* =============================================================
   * WebSocket 订阅：新告警入场 + 状态同步
   * ============================================================= */
  function bindSocket() {
    if (!window.io) return;
    const socket = window.io({ transports: ["websocket", "polling"] });
    socket.on("alert", (a) => {
      if (!a || !a.id) return;
      state.cache.set(a.id, a);
      if (!matchesFilters(a)) {
        refreshGlobalCounts();
        return;
      }
      // 从空态切换为列表
      const empty = el.list.querySelector(".alert-list__empty");
      if (empty) el.list.innerHTML = "";
      el.list.insertAdjacentHTML("afterbegin", renderListItem(a, true));
      state.total += 1;
      renderCounts({ filteredTotal: state.total });
      refreshGlobalCounts();
    });
    socket.on("alert_updated", (evt) => {
      if (!evt || !evt.id) return;
      const cached = state.cache.get(evt.id);
      if (cached) {
        cached.status = evt.status;
        updateListItemStatus(cached);
      }
      if (state.activeId === evt.id && cached) {
        populateDrawer(cached);
      }
      refreshGlobalCounts();
    });
  }

  function matchesFilters(a) {
    if (state.level && a.level !== state.level) return false;
    if (state.status && a.status !== state.status) return false;
    if (state.type && a.threat_type !== state.type) return false;
    if (state.q) {
      const needle = state.q.toLowerCase();
      const hay = [a.title, a.summary, a.threat_type, a.source_ip, a.dest_ip]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      if (!hay.includes(needle)) return false;
    }
    const since = rangeSince(state.range);
    if (since && a.timestamp && new Date(a.timestamp) < new Date(since)) {
      return false;
    }
    return true;
  }

  /* =============================================================
   * 开发用：生成演示数据按钮（仅在 DEBUG 后端允许时显示）
   * ============================================================= */
  async function maybeEnableSeedButton() {
    // 探针：若 DEBUG 后端允许 seed，则按钮可见。403/其它状态 → 保持隐藏。
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
    el.btnSeed.addEventListener("click", async () => {
      try {
        await fetchApi("/api/alerts/_seed", {
          method: "POST",
          body: { count: 12 },
        });
        toast("已生成 12 条演示告警", "info");
        await loadTypes();
        await applyFilters();
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
    bindFilterHandlers();
    bindListHandlers();
    bindDrawerHandlers();
    bindSeedButton();
    bindSocket();

    // 初始化下拉与列表
    await loadTypes();
    await applyFilters();
    refreshGlobalCounts();
    maybeEnableSeedButton();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
