/*
 * threat_intel.js — 威胁情报控制器（Phase 7）
 *
 * 职责：
 *   1. 加载 providers 状态 → 未配置的 provider 显示为 disabled
 *   2. 查询面板：并行查询本地 / AbuseIPDB / VirusTotal（带 mock 标识）
 *   3. IOC 列表：类型 / 来源 / 搜索筛选；行内删除
 *   4. 新增 IOC 抽屉：前端基础校验，后端二次校验
 */
(function () {
  "use strict";

  if (!window.AGApi) return;
  const { fetchApi } = window.AGApi;
  const { escapeHtml, formatTime, toast } = window.AGUI;

  const IOC_TYPES = ["ip", "domain"];
  const IP_RE = /^(?:\d{1,3}\.){3}\d{1,3}$/;
  const DOMAIN_RE =
    /^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

  /* =============================================================
   * 状态
   * ============================================================= */
  const state = {
    queryType: "ip",
    filter: { type: "", source: "", q: "" },
    providers: {
      local: { enabled: true, configured: true, mock: false },
      abuseipdb: { enabled: false, configured: false, mock: false },
      virustotal: { enabled: false, configured: false, mock: false },
    },
    iocs: [],
  };

  /* =============================================================
   * DOM
   * ============================================================= */
  const el = {
    countTotal: document.getElementById("count-total"),
    countIp: document.getElementById("count-ip"),
    countDomain: document.getElementById("count-domain"),
    providerStatus: document.getElementById("provider-status"),

    btnQueryTypes: document.querySelectorAll("[data-query-type]"),
    qValue: document.getElementById("q-value"),
    btnQuery: document.getElementById("btn-query"),
    btnQueryClear: document.getElementById("btn-query-clear"),
    verdict: document.getElementById("query-verdict"),
    verdictStatus: document.getElementById("verdict-status"),
    verdictDetail: document.getElementById("verdict-detail"),
    verdictValue: document.getElementById("verdict-value"),
    providerGrid: document.getElementById("provider-grid"),

    btnListTypes: document.querySelectorAll("[data-list-type]"),
    selSource: document.getElementById("filter-source"),
    inputListQ: document.getElementById("filter-q"),
    listStatus: document.getElementById("list-status"),
    tbody: document.getElementById("iocs-tbody"),

    btnNew: document.getElementById("btn-new-ioc"),
    btnRefresh: document.getElementById("btn-refresh"),
    btnSeed: document.getElementById("btn-seed"),

    drawer: document.getElementById("ioc-drawer"),
    drawerOverlay: document.getElementById("drawer-overlay"),
    drawerClose: document.getElementById("drawer-close"),
    fType: document.getElementById("f-type"),
    fValue: document.getElementById("f-value"),
    eValue: document.getElementById("e-value"),
    fSource: document.getElementById("f-source"),
    fScore: document.getElementById("f-score"),
    fReason: document.getElementById("f-reason"),
    fNote: document.getElementById("f-note"),
    btnSave: document.getElementById("btn-drawer-save"),
    btnCancel: document.getElementById("btn-drawer-cancel"),
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

  function validateValue(type, value) {
    if (!value) return "请输入 IOC 值";
    if (type === "ip" && !IP_RE.test(value)) return "IP 地址格式不合法";
    if (type === "domain" && !DOMAIN_RE.test(value)) return "域名格式不合法";
    return null;
  }

  function providerLabel(p) {
    return (
      { local: "本地黑名单", abuseipdb: "AbuseIPDB", virustotal: "VirusTotal" }[p] ||
      p
    );
  }

  /* =============================================================
   * Provider 状态
   * ============================================================= */
  async function loadProviders() {
    try {
      const data = await fetchApi("/api/threat_intel/providers");
      state.providers = {
        local: data.local || { enabled: true, configured: true, mock: false },
        abuseipdb: data.abuseipdb || {
          enabled: false,
          configured: false,
          mock: false,
        },
        virustotal: data.virustotal || {
          enabled: false,
          configured: false,
          mock: false,
        },
      };
    } catch (_) {
      // 拉取失败时保持默认值
    }
    renderProviderStatus();
  }

  function renderProviderStatus() {
    const parts = Object.keys(state.providers).map((p) => {
      const info = state.providers[p];
      const label = providerLabel(p);
      let suffix = "";
      if (info.configured) suffix = '<strong style="color: var(--accent-emerald)">已配置</strong>';
      else if (info.mock) suffix = '<strong style="color: var(--threat-medium)">MOCK 模式</strong>';
      else suffix = '<strong style="color: var(--text-tertiary)">未启用</strong>';
      return `<span>${escapeHtml(label)} ${suffix}</span>`;
    });
    el.providerStatus.innerHTML = parts.join("");
  }

  /* =============================================================
   * 查询面板
   * ============================================================= */
  function bindQueryHandlers() {
    el.btnQueryTypes.forEach((btn) => {
      btn.addEventListener("click", () => {
        state.queryType = btn.dataset.queryType;
        el.btnQueryTypes.forEach((b) =>
          b.classList.toggle("is-active", b === btn)
        );
        el.qValue.placeholder =
          state.queryType === "ip" ? "1.2.3.4" : "evil-example.com";
      });
    });
    el.btnQuery.addEventListener("click", runQuery);
    el.qValue.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        runQuery();
      }
    });
    el.btnQueryClear.addEventListener("click", () => {
      el.qValue.value = "";
      el.providerGrid.innerHTML = "";
      el.verdict.hidden = true;
    });
  }

  async function runQuery() {
    const value = el.qValue.value.trim();
    const type = state.queryType;
    const err = validateValue(type, value);
    if (err) {
      toast(err, "error");
      el.qValue.focus();
      return;
    }

    // providers 选择：能用的全部并行请求
    const providers = ["local"]; // local 始终可查
    if (state.providers.abuseipdb.enabled && type === "ip") providers.push("abuseipdb");
    if (state.providers.virustotal.enabled) providers.push("virustotal");

    renderLoadingCards(providers);

    try {
      const resp = await fetchApi("/api/threat_intel/query", {
        method: "POST",
        body: { type, value, providers },
      });
      renderVerdict(resp, type, value);
      renderResults(resp.results, type);
    } catch (err) {
      el.verdict.hidden = true;
      el.providerGrid.innerHTML = `<div class="provider-card"><div class="provider-card__header"><h4 class="provider-card__title">查询失败</h4></div><div class="text-tertiary" style="font-size: var(--fs-caption)">${escapeHtml(
        err.message || ""
      )}</div></div>`;
    }
  }

  function renderLoadingCards(providers) {
    el.verdict.hidden = true;
    el.providerGrid.innerHTML = providers
      .map(
        (p) => `
        <div class="provider-card" data-provider="${escapeHtml(p)}">
          <div class="provider-card__header">
            <h4 class="provider-card__title">${escapeHtml(providerLabel(p))}</h4>
            <span class="provider-card__status"><span class="loader" style="vertical-align: middle"></span> 查询中</span>
          </div>
        </div>`
      )
      .join("");
  }

  function renderVerdict(resp, type, value) {
    const overall = resp.overall || {};
    el.verdict.hidden = false;
    el.verdict.classList.toggle("query-verdict--threat", !!overall.is_malicious);
    el.verdict.classList.toggle("query-verdict--clean", !overall.is_malicious);
    el.verdictStatus.textContent = overall.is_malicious ? "威胁命中" : "未命中威胁情报";
    const hits = overall.providers_hit || [];
    const maxScore = overall.max_score;
    el.verdictDetail.textContent =
      (hits.length ? `命中来源：${hits.map(providerLabel).join(" / ")}` : "所有 provider 均未命中") +
      (typeof maxScore === "number" ? ` · 最高评分 ${maxScore}` : "");
    el.verdictValue.textContent = `[${type.toUpperCase()}] ${value}`;
  }

  function renderResults(results, type) {
    if (!results) {
      el.providerGrid.innerHTML = "";
      return;
    }
    const order = ["local", "abuseipdb", "virustotal"];
    el.providerGrid.innerHTML = order
      .filter((p) => results[p])
      .map((p) => renderProviderCard(p, results[p], type))
      .join("");
  }

  function renderProviderCard(provider, r, type) {
    const label = providerLabel(provider);
    const notOk = !r.ok;
    const hit = !!(r.is_malicious || r.hit);
    const cardClass =
      "provider-card" +
      (notOk ? " provider-card--disabled" : "") +
      (!notOk && hit ? " provider-card--hit" : "") +
      (!notOk && !hit ? " provider-card--clean" : "");

    const headerBadges = [];
    if (r.mocked) headerBadges.push('<span class="badge badge--mock">MOCK</span>');
    if (!notOk) {
      headerBadges.push(
        hit
          ? '<span class="badge badge--hit">HIT</span>'
          : '<span class="badge badge--clean">CLEAN</span>'
      );
    }

    let body = "";
    let footer = "";

    if (notOk) {
      body = `<div class="text-tertiary" style="font-size: var(--fs-caption)">${escapeHtml(reasonToZh(r.reason))}</div>`;
    } else if (provider === "local") {
      const rows = [];
      rows.push(kv("命中", hit ? "是" : "否"));
      if (r.score !== null && r.score !== undefined) rows.push(kv("评分", r.score));
      if (r.sources && r.sources.length)
        rows.push(kv("来源", r.sources.join(", ")));
      if (r.added_at) rows.push(kv("加入", formatTime(r.added_at)));
      rows.push(kv("命中次数", r.hits ?? 0));
      body = '<dl class="provider-card__body">' + rows.join("") + "</dl>";
      if (r.reason) footer = `<div>${escapeHtml(r.reason)}</div>`;
    } else if (provider === "abuseipdb") {
      const rows = [
        kv("置信度", `${r.score ?? 0} / 100`),
        kv("国家", r.country_code || "—"),
        kv("ISP", r.isp || "—"),
        kv("用途", r.usage_type || "—"),
        kv("举报总数", r.total_reports ?? 0),
      ];
      if (r.last_reported_at)
        rows.push(kv("最后举报", formatTime(r.last_reported_at)));
      body = '<dl class="provider-card__body">' + rows.join("") + "</dl>";
    } else if (provider === "virustotal") {
      const rows = [
        kv("恶意", r.malicious ?? 0),
        kv("可疑", r.suspicious ?? 0),
        kv("无害", r.harmless ?? 0),
        kv("未知", r.undetected ?? 0),
        kv("声誉", r.reputation ?? 0),
      ];
      if (type === "ip") {
        if (r.country) rows.push(kv("国家", r.country));
        if (r.as_owner) rows.push(kv("AS", r.as_owner));
        if (r.network) rows.push(kv("网段", r.network));
      } else {
        if (r.registrar) rows.push(kv("注册商", r.registrar));
        if (r.categories && Object.keys(r.categories).length) {
          const cats = Object.entries(r.categories)
            .map(([k, v]) => `${k}:${v}`)
            .join(", ");
          rows.push(kv("分类", cats));
        }
      }
      body = '<dl class="provider-card__body">' + rows.join("") + "</dl>";
    }

    return `
      <div class="${cardClass}">
        <div class="provider-card__header">
          <h4 class="provider-card__title">${escapeHtml(label)}</h4>
          <div style="display: flex; gap: 6px">${headerBadges.join("")}</div>
        </div>
        ${body}
        ${footer ? `<div class="provider-card__footer">${footer}</div>` : ""}
      </div>`;
  }

  function kv(k, v) {
    return `<dt>${escapeHtml(k)}</dt><dd>${escapeHtml(String(v))}</dd>`;
  }

  function reasonToZh(reason) {
    return (
      {
        api_key_missing: "未配置 API Key（生产环境请在 .env 中填入）",
        invalid_ip_format: "IP 地址格式非法",
        invalid_domain_format: "域名格式非法",
        timeout: "请求超时",
        request_error: "请求失败",
        parse_error: "响应解析失败",
      }[reason] || reason || "未知错误"
    );
  }

  /* =============================================================
   * IOC 列表
   * ============================================================= */
  async function loadList() {
    el.tbody.innerHTML =
      '<tr><td colspan="8" class="alert-list__empty"><span class="loader"></span><span style="margin-left: 8px">加载中…</span></td></tr>';
    const query = {};
    if (state.filter.type) query.type = state.filter.type;
    if (state.filter.source) query.source = state.filter.source;
    if (state.filter.q) query.q = state.filter.q;
    try {
      const data = await fetchApi("/api/threat_intel", { query });
      state.iocs = data.entries || [];
      updateStats(data.stats || {});
      refreshSourceOptions(data.stats || {});
      renderTable(state.iocs);
      el.listStatus.textContent = state.iocs.length
        ? `共 ${state.iocs.length} 条`
        : "";
    } catch (err) {
      el.tbody.innerHTML =
        '<tr><td colspan="8" class="alert-list__empty">' +
        escapeHtml("拉取失败：" + (err.message || "")) +
        "</td></tr>";
    }
  }

  function updateStats(stats) {
    el.countTotal.textContent = String(stats.total || 0);
    el.countIp.textContent = String(stats.ip_count || 0);
    el.countDomain.textContent = String(stats.domain_count || 0);
  }

  function refreshSourceOptions(stats) {
    const current = el.selSource.value;
    const sources = Object.keys(stats.by_source || {});
    const frag = ['<option value="">全部来源</option>'];
    sources.sort().forEach((s) => {
      frag.push(
        `<option value="${escapeHtml(s)}"${s === current ? " selected" : ""}>${escapeHtml(s)}</option>`
      );
    });
    el.selSource.innerHTML = frag.join("");
  }

  function renderTable(items) {
    if (!items.length) {
      el.tbody.innerHTML =
        '<tr><td colspan="8" class="alert-list__empty">' +
        '<div class="empty-state">' +
        '<div class="empty-state__title">当前筛选下暂无 IOC</div>' +
        '<div class="empty-state__hint">点右上「新增 IOC」或「生成演示 IOC」</div>' +
        "</div></td></tr>";
      return;
    }
    el.tbody.innerHTML = items.map(renderRow).join("");
  }

  function renderRow(e) {
    const typeBadge =
      '<span class="badge badge--' +
      (e.type === "ip" ? "signature" : "anomaly") +
      '">' +
      e.type.toUpperCase() +
      "</span>";
    const sources = Array.isArray(e.sources) ? e.sources : [];
    const sourceBadges = sources
      .map((s) => `<span class="badge badge--source">${escapeHtml(s)}</span>`)
      .join(" ");
    const reason = escapeHtml(e.reason || "");
    const note = escapeHtml(e.note || "");
    const reasonCell = reason + (note ? `<div class="text-tertiary" style="font-size: var(--fs-caption); margin-top: 2px">${note}</div>` : "");
    const score = e.score === null || e.score === undefined ? "—" : e.score;

    return `
      <tr data-type="${escapeHtml(e.type)}" data-value="${escapeHtml(e.value)}">
        <td>${typeBadge}</td>
        <td><code class="mono" style="color: var(--info-blue)">${escapeHtml(e.value)}</code></td>
        <td>${sourceBadges}</td>
        <td class="num">${score}</td>
        <td class="num">${e.hits ?? 0}</td>
        <td>${reasonCell}</td>
        <td class="mono" style="color: var(--text-tertiary); font-size: var(--fs-caption)">${escapeHtml(formatTime(e.added_at))}</td>
        <td>
          <div class="table__actions">
            <button class="btn btn--ghost btn--sm" data-action="query" type="button">查询</button>
            <button class="btn btn--danger btn--sm" data-action="delete" type="button">删除</button>
          </div>
        </td>
      </tr>`;
  }

  function bindListHandlers() {
    el.btnListTypes.forEach((btn) => {
      btn.addEventListener("click", () => {
        state.filter.type = btn.dataset.listType || "";
        el.btnListTypes.forEach((b) =>
          b.classList.toggle("is-active", b === btn)
        );
        loadList();
      });
    });
    el.selSource.addEventListener("change", () => {
      state.filter.source = el.selSource.value;
      loadList();
    });
    const onSearch = debounce(() => {
      state.filter.q = el.inputListQ.value.trim();
      loadList();
    }, 250);
    el.inputListQ.addEventListener("input", onSearch);

    el.btnRefresh.addEventListener("click", () => {
      loadList();
      loadProviders();
    });

    el.tbody.addEventListener("click", (e) => {
      const btn = e.target.closest("button[data-action]");
      if (!btn) return;
      const tr = btn.closest("tr");
      const type = tr.dataset.type;
      const value = tr.dataset.value;
      if (btn.dataset.action === "delete") {
        deleteIoc(type, value);
      } else if (btn.dataset.action === "query") {
        state.queryType = type;
        el.btnQueryTypes.forEach((b) =>
          b.classList.toggle("is-active", b.dataset.queryType === type)
        );
        el.qValue.value = value;
        runQuery();
        document
          .querySelector(".card")
          .scrollIntoView({ behavior: "smooth", block: "start" });
      }
    });
  }

  async function deleteIoc(type, value) {
    if (!window.confirm(`确认移除 ${type.toUpperCase()} 「${value}」？`)) return;
    try {
      await fetchApi(
        `/api/threat_intel/iocs/${encodeURIComponent(type)}/${encodeURIComponent(value)}`,
        { method: "DELETE" }
      );
      toast(`已移除：${value}`, "info");
      loadList();
    } catch (err) {
      toast("删除失败：" + (err.message || ""), "error");
    }
  }

  /* =============================================================
   * 新增抽屉
   * ============================================================= */
  function bindDrawer() {
    el.btnNew.addEventListener("click", () => openDrawer());
    el.drawerClose.addEventListener("click", closeDrawer);
    el.drawerOverlay.addEventListener("click", closeDrawer);
    el.btnCancel.addEventListener("click", closeDrawer);
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && el.drawer.classList.contains("is-open")) closeDrawer();
    });
    el.btnSave.addEventListener("click", saveIoc);
    el.fType.addEventListener("change", () => {
      el.fValue.placeholder =
        el.fType.value === "ip" ? "1.2.3.4" : "evil-example.com";
    });
  }

  function openDrawer() {
    clearForm();
    el.drawer.classList.add("is-open");
    el.drawerOverlay.classList.add("is-open");
    el.drawer.setAttribute("aria-hidden", "false");
    el.drawerOverlay.setAttribute("aria-hidden", "false");
    requestAnimationFrame(() => el.fValue.focus());
  }

  function closeDrawer() {
    el.drawer.classList.remove("is-open");
    el.drawerOverlay.classList.remove("is-open");
    el.drawer.setAttribute("aria-hidden", "true");
    el.drawerOverlay.setAttribute("aria-hidden", "true");
  }

  function clearForm() {
    el.fType.value = "ip";
    el.fValue.value = "";
    el.fSource.value = "manual";
    el.fScore.value = "";
    el.fReason.value = "";
    el.fNote.value = "";
    el.eValue.hidden = true;
    el.fValue.placeholder = "1.2.3.4";
  }

  async function saveIoc() {
    const type = el.fType.value;
    const value = el.fValue.value.trim();
    const err = validateValue(type, value);
    el.eValue.hidden = true;
    if (err) {
      el.eValue.textContent = err;
      el.eValue.hidden = false;
      el.fValue.focus();
      return;
    }
    const payload = {
      type,
      value,
      source: el.fSource.value.trim() || "manual",
      reason: el.fReason.value.trim(),
      note: el.fNote.value.trim(),
    };
    if (el.fScore.value !== "") payload.score = parseInt(el.fScore.value, 10);

    el.btnSave.disabled = true;
    try {
      const saved = await fetchApi("/api/threat_intel/iocs", {
        method: "POST",
        body: payload,
      });
      toast(`已添加：${saved.value}`, "info");
      closeDrawer();
      loadList();
    } catch (err) {
      el.eValue.textContent = err.message || "保存失败";
      el.eValue.hidden = false;
    } finally {
      el.btnSave.disabled = false;
    }
  }

  /* =============================================================
   * DEBUG seed
   * ============================================================= */
  async function maybeEnableSeedButton() {
    if (!el.btnSeed) return;
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
    } catch (_) {}
  }

  function bindSeedButton() {
    if (!el.btnSeed) return;
    el.btnSeed.addEventListener("click", async () => {
      try {
        const r = await fetchApi("/api/threat_intel/_seed", { method: "POST" });
        toast(`已生成 ${r.created || 0} 条演示 IOC`, "info");
        loadList();
      } catch (err) {
        toast("生成失败：" + (err.message || ""), "error");
      }
    });
  }

  /* =============================================================
   * 启动
   * ============================================================= */
  async function init() {
    bindQueryHandlers();
    bindListHandlers();
    bindDrawer();
    bindSeedButton();

    await loadProviders();
    await loadList();
    maybeEnableSeedButton();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
