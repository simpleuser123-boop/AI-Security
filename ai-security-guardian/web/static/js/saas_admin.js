(function () {
  "use strict";

  const state = { me: null, tenants: [], plans: [], selected: "" };
  const $ = (id) => document.getElementById(id);
  const esc = (v) => window.AGUI.escapeHtml(v == null ? "" : String(v));
  const isPlatformAdmin = () => state.me && state.me.role === "admin" && state.me.tenant_id === "tenant_default";

  async function boot() {
    state.me = await window.AGApi.fetchApi("/api/auth/me");
    if (isPlatformAdmin()) {
      await loadPlatform();
    } else {
      await loadTenantStatus();
    }
  }

  async function loadPlatform() {
    $("saas-admin").setAttribute("data-mode", "platform");
    const q = $("tenant-q").value.trim();
    const [tenants, plans] = await Promise.all([
      window.AGApi.fetchApi("/api/admin/saas/tenants", { query: { q } }),
      window.AGApi.fetchApi("/api/admin/saas/plans"),
    ]);
    state.tenants = tenants.items || [];
    state.plans = plans.items || [];
    renderTenants();
    if (state.selected) await loadDetail(state.selected);
  }

  async function loadTenantStatus() {
    $("saas-admin").setAttribute("data-mode", "tenant");
    const data = await window.AGApi.fetchApi("/api/tenant/commercial/status");
    $("tenant-rows").innerHTML = tenantSummaryRows(data);
    $("tenant-detail-caption").textContent = `${data.tenant.name} · ${data.tenant.id}`;
    $("tenant-detail").innerHTML = tenantStatusMarkup(data);
  }

  function tenantSummaryRows(data) {
    const plan = data.current_plan || {};
    const alerts = (data.quotas || []).find((q) => q.metric === "alerts") || {};
    return `<tr>
      <td><strong>${esc(data.tenant.name)}</strong><br><span class="text-tertiary mono">${esc(data.tenant.id)}</span></td>
      <td><span class="badge">${esc(data.tenant.status)}</span></td>
      <td>${esc(plan.code || data.tenant.plan || "-")}</td>
      <td>${esc(alerts.used || 0)}</td>
      <td>${data.has_overage ? '<span class="badge badge--danger">超额</span>' : '<span class="badge">正常</span>'}</td>
    </tr>`;
  }

  function tenantStatusMarkup(data) {
    const plan = data.current_plan || {};
    const sub = data.subscription || {};
    const overage = data.has_overage
      ? `<div class="alert-banner alert-banner--warning">当前有 ${data.overages.length} 项配额超额，请联系平台管理员调整套餐或配额。</div>`
      : "";
    const licenseRows = (data.licenses || []).map(licenseRow).join("") ||
      '<tr><td colspan="5" class="text-tertiary">暂无 License</td></tr>';
    return `
      ${overage}
      <div class="settings-field">
        <div class="settings-field__head">
          <span class="settings-field__label">当前套餐</span>
          <span class="settings-field__hint">${esc(sub.effective_status || sub.status || "-")}</span>
        </div>
        <div class="settings-field__control">
          <strong>${esc(plan.name || "-")}</strong>
          <span class="text-tertiary mono">${esc(plan.code || "")}</span>
        </div>
      </div>
      <div class="table-wrap">
        <table class="table"><thead><tr><th>License</th><th>状态</th><th>发放对象</th><th>过期时间</th><th>限制覆盖</th></tr></thead><tbody>${licenseRows}</tbody></table>
      </div>
      ${quotaTable(data.quotas || [], false)}
    `;
  }

  function renderTenants() {
    const body = $("tenant-rows");
    if (!state.tenants.length) {
      body.innerHTML = '<tr><td colspan="5" class="text-tertiary">暂无租户</td></tr>';
      return;
    }
    body.innerHTML = state.tenants.map((t) => {
      const sub = t.active_subscription || {};
      return `<tr>
        <td><strong>${esc(t.name)}</strong><br><span class="text-tertiary mono">${esc(t.id)}</span></td>
        <td><span class="badge">${esc(t.status)}</span></td>
        <td>${esc(sub.plan_code || t.plan || "-")}</td>
        <td>${esc((t.usage_summary && t.usage_summary.alerts) || 0)}</td>
        <td><button class="btn btn--ghost btn--sm" data-open="${esc(t.id)}" type="button">详情</button></td>
      </tr>`;
    }).join("");
    body.querySelectorAll("[data-open]").forEach((btn) => {
      btn.addEventListener("click", () => loadDetail(btn.getAttribute("data-open")));
    });
  }

  async function loadDetail(id) {
    state.selected = id;
    const data = await window.AGApi.fetchApi(`/api/admin/saas/tenants/${encodeURIComponent(id)}`);
    renderDetail(data);
  }

  function renderDetail(t) {
    $("tenant-detail-caption").textContent = `${t.name} · ${t.id}`;
    const currentCode = (t.active_subscription && t.active_subscription.plan_code) || t.plan || "";
    const planOptions = state.plans
      .map((p) => `<option value="${esc(p.code)}" ${p.code === currentCode ? "selected" : ""}>${esc(p.name)} (${esc(p.code)})</option>`)
      .join("");
    const licenseRows = (t.licenses || []).map((lic) => platformLicenseRow(t.id, lic)).join("") ||
      '<tr><td colspan="6" class="text-tertiary">暂无 License</td></tr>';
    $("tenant-detail").innerHTML = `
      <div class="settings-field">
        <div class="settings-field__head">
          <span class="settings-field__label">租户状态</span>
          <span class="settings-field__hint">suspended / expired 会阻断普通租户访问</span>
        </div>
        <div class="settings-field__control">
          <div class="settings-inline">
            <select class="form-input" id="tenant-status">
              ${["active", "suspended", "expired"].map((s) => `<option value="${s}" ${t.status === s ? "selected" : ""}>${s}</option>`).join("")}
            </select>
            <button class="btn btn--primary btn--sm" id="tenant-status-save" type="button">保存状态</button>
          </div>
        </div>
      </div>
      <div class="settings-field">
        <div class="settings-field__head">
          <span class="settings-field__label">套餐绑定</span>
          <span class="settings-field__hint">创建新的 active 订阅并停用旧订阅</span>
        </div>
        <div class="settings-field__control">
          <div class="settings-inline">
            <select class="form-input" id="tenant-plan">${planOptions}</select>
            <button class="btn btn--primary btn--sm" id="tenant-plan-save" type="button">绑定套餐</button>
          </div>
        </div>
      </div>
      ${quotaTable(t.quotas || [], true)}
      <div class="settings-inline">
        <input class="form-input" id="license-issued-to" placeholder="License 发放对象" />
        <input class="form-input" id="license-expires-at" type="datetime-local" />
        <button class="btn btn--ghost btn--sm" id="license-create" type="button">生成 License</button>
      </div>
      <div class="table-wrap">
        <table class="table"><thead><tr><th>前缀</th><th>状态</th><th>发放对象</th><th>过期</th><th>限制覆盖</th><th>操作</th></tr></thead><tbody>${licenseRows}</tbody></table>
      </div>
    `;

    $("tenant-status-save").addEventListener("click", () => saveStatus(t.id));
    $("tenant-plan-save").addEventListener("click", () => bindPlan(t.id));
    $("license-create").addEventListener("click", () => createLicense(t.id));
    document.querySelectorAll("[data-save-quota]").forEach((btn) => {
      btn.addEventListener("click", () => saveQuota(t.id, btn.getAttribute("data-save-quota")));
    });
    document.querySelectorAll("[data-license-status]").forEach((btn) => {
      btn.addEventListener("click", () =>
        updateLicense(t.id, btn.getAttribute("data-license-status"), { status: btn.getAttribute("data-next") })
      );
    });
    document.querySelectorAll("[data-license-renew]").forEach((btn) => {
      btn.addEventListener("click", () => renewLicense(t.id, btn.getAttribute("data-license-renew")));
    });
  }

  function quotaTable(quotas, editable) {
    const rows = quotas.map((q) => {
      const limitText = q.limit === null ? "无限制" : esc(q.limit);
      const status = q.exceeded ? '<span class="badge badge--danger">超额</span>' : '<span class="badge">正常</span>';
      const limitCell = editable
        ? `<input class="form-input form-input--mono" data-quota="${esc(q.metric)}" value="${q.limit === null ? "" : esc(q.limit)}" placeholder="无限制" />`
        : limitText;
      const action = editable
        ? `<button class="btn btn--ghost btn--sm" data-save-quota="${esc(q.metric)}" type="button">保存</button>`
        : status;
      return `<tr>
        <td class="mono">${esc(q.metric)}</td>
        <td>${esc(q.used)}</td>
        <td>${limitCell}</td>
        <td>${esc(q.remaining === null ? "-" : q.remaining)}</td>
        <td>${esc(q.source || "-")}</td>
        <td>${action}</td>
      </tr>`;
    }).join("");
    return `<div class="table-wrap">
      <table class="table"><thead><tr><th>指标</th><th>已用</th><th>上限</th><th>剩余</th><th>来源</th><th>${editable ? "操作" : "状态"}</th></tr></thead><tbody>${rows}</tbody></table>
    </div>`;
  }

  function licenseRow(lic) {
    return `<tr>
      <td class="mono">${esc(lic.key_prefix)}</td>
      <td>${esc(lic.effective_status || lic.status)}</td>
      <td>${esc(lic.issued_to || "-")}</td>
      <td>${esc(lic.expires_at || "-")}</td>
      <td class="mono">${esc(JSON.stringify(lic.limits || {}))}</td>
    </tr>`;
  }

  function platformLicenseRow(tenantId, lic) {
    const next = lic.status === "active" ? "disabled" : "active";
    return `<tr>
      <td class="mono">${esc(lic.key_prefix)}</td>
      <td>${esc(lic.effective_status || lic.status)}</td>
      <td>${esc(lic.issued_to || "-")}</td>
      <td><input class="form-input" id="expires-${esc(lic.id)}" type="datetime-local" value="${toLocalInputValue(lic.expires_at)}" /></td>
      <td class="mono">${esc(JSON.stringify(lic.limits || {}))}</td>
      <td>
        <button class="btn btn--ghost btn--sm" data-license-status="${esc(lic.id)}" data-next="${next}" type="button">${lic.status === "active" ? "停用" : "启用"}</button>
        <button class="btn btn--ghost btn--sm" data-license-renew="${esc(lic.id)}" type="button">续期</button>
      </td>
    </tr>`;
  }

  function toLocalInputValue(value) {
    if (!value) return "";
    const d = new Date(value);
    if (Number.isNaN(d.getTime())) return "";
    const pad = (n) => String(n).padStart(2, "0");
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
  }

  async function saveStatus(id) {
    await window.AGApi.fetchApi(`/api/admin/saas/tenants/${encodeURIComponent(id)}`, {
      method: "PATCH",
      body: { status: $("tenant-status").value },
    });
    window.AGUI.toast("租户状态已更新");
    await loadPlatform();
  }

  async function bindPlan(id) {
    await window.AGApi.fetchApi(`/api/admin/saas/tenants/${encodeURIComponent(id)}/subscription`, {
      method: "PUT",
      body: { plan_code: $("tenant-plan").value },
    });
    window.AGUI.toast("套餐已绑定");
    await loadDetail(id);
  }

  async function saveQuota(id, metric) {
    const input = document.querySelector(`[data-quota="${CSS.escape(metric)}"]`);
    await window.AGApi.fetchApi(`/api/admin/saas/tenants/${encodeURIComponent(id)}/quotas/${encodeURIComponent(metric)}`, {
      method: "PUT",
      body: { limit: input.value.trim() === "" ? null : Number(input.value) },
    });
    window.AGUI.toast("配额已更新");
    await loadDetail(id);
  }

  async function createLicense(id) {
    const issuedTo = $("license-issued-to").value.trim();
    const expiresAt = $("license-expires-at").value ? new Date($("license-expires-at").value).toISOString() : null;
    const lic = await window.AGApi.fetchApi(`/api/admin/saas/tenants/${encodeURIComponent(id)}/licenses`, {
      method: "POST",
      body: { issued_to: issuedTo, expires_at: expiresAt },
    });
    window.AGUI.toast(`License 已生成：${lic.license_key}`, "info", 7000);
    await loadDetail(id);
  }

  async function updateLicense(id, licenseId, body) {
    await window.AGApi.fetchApi(`/api/admin/saas/tenants/${encodeURIComponent(id)}/licenses/${encodeURIComponent(licenseId)}`, {
      method: "PATCH",
      body,
    });
    window.AGUI.toast("License 已更新");
    await loadDetail(id);
  }

  async function renewLicense(id, licenseId) {
    const input = $(`expires-${licenseId}`);
    await updateLicense(id, licenseId, {
      expires_at: input && input.value ? new Date(input.value).toISOString() : null,
    });
  }

  document.addEventListener("DOMContentLoaded", () => {
    $("saas-refresh").addEventListener("click", () => (isPlatformAdmin() ? loadPlatform() : loadTenantStatus()));
    $("tenant-search").addEventListener("click", loadPlatform);
    $("tenant-q").addEventListener("keydown", (event) => {
      if (event.key === "Enter") loadPlatform();
    });
    boot().catch((err) => window.AGUI.toast(err.message || "加载失败", "error"));
  });
})();
