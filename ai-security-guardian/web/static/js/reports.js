/*
 * reports.js — 审计报告控制器（Phase 7，DESIGN.md §8.6）
 *
 * 职责：
 *   1. 拉取 /api/reports/summary，按 period 刷新
 *   2. 填充封面 / 概览 / 威胁统计 / 响应记录 / 模型性能 / 建议
 *   3. 浅色 ECharts（威胁等级饼 / 攻击类型条 / 时间线 / 置信度分布）
 *   4. 导出：
 *      - JSON  → 直接下载 summary 原始 JSON
 *      - HTML  → 下载当前页面的自包含快照
 *      - PDF   → 调 window.print()，由用户选择打印为 PDF
 */
(function () {
  "use strict";

  if (!window.AGApi) return;
  const { fetchApi } = window.AGApi;
  const { escapeHtml, formatTime, toast } = window.AGUI;

  const PERIOD_LABELS = { day: "日报", week: "周报", month: "月报" };
  const PERIOD_WINDOW_LABEL = {
    day: "近 24 小时",
    week: "近 7 天",
    month: "近 30 天",
  };
  const LEVEL_COLOR = {
    low: "#3B82F6",
    medium: "#F59E0B",
    high: "#EF4444",
    critical: "#EC4899",
  };
  const STATUS_LABEL = {
    open: "未处理",
    acknowledged: "已确认",
    resolved: "已处理",
    ignored: "已忽略",
  };
  const ACTION_LABEL = {
    ban_ip: "封禁 IP",
    mark_acknowledged: "标记已确认",
    mark_resolved: "标记已处理",
    mark_ignored: "标记已忽略",
  };

  /* =============================================================
   * 状态 & DOM
   * ============================================================= */
  const state = {
    period: "day",
    summary: null,
    charts: {},
  };

  const el = {
    btnPeriods: document.querySelectorAll("[data-period]"),
    btnRefresh: document.getElementById("btn-refresh"),
    btnExportJson: document.getElementById("btn-export-json"),
    btnExportHtml: document.getElementById("btn-export-html"),
    btnExportPdf: document.getElementById("btn-export-pdf"),

    coverTitle: document.getElementById("cover-title"),
    coverSubtitle: document.getElementById("cover-subtitle"),
    coverGenerated: document.getElementById("cover-generated"),
    coverWindow: document.getElementById("cover-window"),
    coverModel: document.getElementById("cover-model"),
    coverScore: document.getElementById("cover-score"),

    overviewGrid: document.getElementById("overview-grid"),
    chartLevel: document.getElementById("chart-level"),
    chartType: document.getElementById("chart-type"),
    chartTimeline: document.getElementById("chart-timeline"),
    chartConfidence: document.getElementById("chart-confidence"),
    tableTopSources: document.querySelector("#table-top-sources tbody"),
    tableResponses: document.querySelector("#table-responses tbody"),
    recommendations: document.getElementById("recommendations-list"),
  };

  /* =============================================================
   * 工具
   * ============================================================= */
  function fmtInt(v) {
    return v === null || v === undefined || v === "" ? "—" : v.toLocaleString();
  }

  function fmtPercent(v) {
    if (typeof v !== "number") return "—";
    return (v * 100).toFixed(1) + "%";
  }

  function fmtDuration(sec) {
    if (!sec || sec <= 0) return "—";
    if (sec < 60) return `${sec} 秒`;
    if (sec < 3600) return `${Math.round(sec / 60)} 分`;
    return `${(sec / 3600).toFixed(1)} 小时`;
  }

  function setText(node, value) {
    if (node) node.textContent = value === null || value === undefined ? "—" : String(value);
  }

  /* =============================================================
   * 数据加载
   * ============================================================= */
  async function loadSummary() {
    try {
      const summary = await fetchApi("/api/reports/summary", {
        query: { period: state.period },
      });
      state.summary = summary;
      render(summary);
    } catch (err) {
      toast("生成报告失败：" + (err.message || ""), "error");
    }
  }

  /* =============================================================
   * 渲染
   * ============================================================= */
  function render(s) {
    renderCover(s);
    renderOverview(s.overview || {});
    renderThreats(s.threats || {});
    renderResponses(s.responses || []);
    renderModelPerf(s.model_performance || {});
    renderRecommendations(s.recommendations || []);
  }

  function renderCover(s) {
    el.coverTitle.textContent =
      "AI 安全守卫 · 安全审计" + (PERIOD_LABELS[s.period] || "报告");
    setText(el.coverGenerated, formatTime(s.generated_at));
    setText(
      el.coverWindow,
      s.window ? `${formatTime(s.window.start)} → ${formatTime(s.window.end)}` : "—"
    );
    setText(el.coverModel, (s.model_performance && s.model_performance.version) || "v1");
    setText(el.coverScore, s.overview && s.overview.security_score);
  }

  function renderOverview(o) {
    const m = el.overviewGrid;
    if (!m) return;
    setText(m.querySelector('[data-metric="total_alerts"]'), fmtInt(o.total_alerts));
    setText(
      m.querySelector('[data-metric="critical_high"]'),
      fmtInt((o.critical_alerts || 0) + (o.high_alerts || 0))
    );
    setText(m.querySelector('[data-metric="open_alerts"]'), fmtInt(o.open_alerts));
    setText(m.querySelector('[data-metric="resolved_alerts"]'), fmtInt(o.resolved_alerts));
    setText(m.querySelector('[data-metric="banned_ips"]'), fmtInt(o.banned_ips));
    setText(m.querySelector('[data-metric="iocs_total"]'), fmtInt(o.iocs_total));
    setText(
      m.querySelector('[data-metric="rules_ratio"]'),
      `${fmtInt(o.rules_enabled)} / ${fmtInt(o.rules_total)}`
    );
    setText(m.querySelector('[data-metric="security_score"]'), fmtInt(o.security_score));
  }

  function renderThreats(t) {
    renderLevelChart(t.by_level || []);
    renderTypeChart(t.by_type || []);
    renderTimelineChart(t.timeline || []);
    renderTopSources(t.top_sources || []);
  }

  function reportChartTheme() {
    return {
      textStyle: {
        fontFamily: "Inter, system-ui, sans-serif",
        color: "#111827",
      },
      title: { textStyle: { color: "#111827" } },
    };
  }

  function ensureChart(id, node) {
    if (state.charts[id]) {
      state.charts[id].dispose();
    }
    state.charts[id] = echarts.init(node, null, { renderer: "canvas" });
    return state.charts[id];
  }

  function renderLevelChart(data) {
    if (!window.echarts) return;
    const chart = ensureChart("level", el.chartLevel);
    chart.setOption({
      ...reportChartTheme(),
      tooltip: { trigger: "item", confine: true },
      legend: {
        orient: "vertical",
        left: "right",
        top: "middle",
        textStyle: { color: "#4B5563", fontSize: 12 },
      },
      series: [
        {
          type: "pie",
          radius: ["50%", "72%"],
          center: ["35%", "50%"],
          avoidLabelOverlap: true,
          label: { show: false },
          data: data.map((d) => ({
            name: d.level.toUpperCase(),
            value: d.count,
            itemStyle: { color: LEVEL_COLOR[d.level] || "#9CA3AF" },
          })),
        },
      ],
    });
  }

  function renderTypeChart(data) {
    if (!window.echarts) return;
    const chart = ensureChart("type", el.chartType);
    const categories = data.map((d) => d.type);
    const values = data.map((d) => d.count);
    chart.setOption({
      ...reportChartTheme(),
      grid: { left: 100, right: 20, top: 10, bottom: 20 },
      tooltip: { trigger: "axis", axisPointer: { type: "shadow" } },
      xAxis: {
        type: "value",
        axisLine: { lineStyle: { color: "#E5E7EB" } },
        splitLine: { lineStyle: { color: "#F3F4F6" } },
        axisLabel: { color: "#6B7280" },
      },
      yAxis: {
        type: "category",
        data: categories,
        inverse: true,
        axisLine: { lineStyle: { color: "#E5E7EB" } },
        axisLabel: { color: "#4B5563", fontSize: 12 },
      },
      series: [
        {
          type: "bar",
          data: values,
          barMaxWidth: 14,
          itemStyle: { color: "#10B981", borderRadius: [0, 3, 3, 0] },
          label: { show: true, position: "right", color: "#111827", fontSize: 11 },
        },
      ],
    });
  }

  function renderTimelineChart(buckets) {
    if (!window.echarts) return;
    const chart = ensureChart("timeline", el.chartTimeline);
    const xs = buckets.map((b) => formatTime(b.start).slice(5));
    const ys = buckets.map((b) => b.count);
    chart.setOption({
      ...reportChartTheme(),
      grid: { left: 40, right: 20, top: 20, bottom: 40 },
      tooltip: { trigger: "axis" },
      xAxis: {
        type: "category",
        data: xs,
        axisLine: { lineStyle: { color: "#E5E7EB" } },
        axisLabel: { color: "#6B7280", fontSize: 11 },
      },
      yAxis: {
        type: "value",
        axisLine: { lineStyle: { color: "#E5E7EB" } },
        splitLine: { lineStyle: { color: "#F3F4F6" } },
        axisLabel: { color: "#6B7280" },
      },
      series: [
        {
          type: "line",
          data: ys,
          smooth: true,
          showSymbol: false,
          lineStyle: { color: "#10B981", width: 2 },
          areaStyle: { color: "rgba(16,185,129,0.12)" },
        },
      ],
    });
  }

  function renderTopSources(rows) {
    if (!rows.length) {
      el.tableTopSources.innerHTML =
        '<tr><td colspan="3" class="text-tertiary" style="text-align: center">本周期无可归因来源</td></tr>';
      return;
    }
    el.tableTopSources.innerHTML = rows
      .map(
        (r, i) => `
        <tr>
          <td>${i + 1}</td>
          <td><code class="mono">${escapeHtml(r.ip)}</code></td>
          <td>${fmtInt(r.count)}</td>
        </tr>`
      )
      .join("");
  }

  function renderResponses(rows) {
    if (!rows.length) {
      el.tableResponses.innerHTML =
        '<tr><td colspan="5" class="text-tertiary" style="text-align: center">本周期无处置动作</td></tr>';
      return;
    }
    el.tableResponses.innerHTML = rows
      .map((r) => {
        const actLabel = ACTION_LABEL[r.action] || r.action || "—";
        const title = r.alert_title
          ? `${escapeHtml(r.alert_title)}（${escapeHtml(r.reason || "")}）`
          : escapeHtml(r.reason || "—");
        return `
          <tr>
            <td class="mono" style="font-size: 12px; color: #6B7280">${escapeHtml(
              formatTime(r.timestamp)
            )}</td>
            <td>${escapeHtml(actLabel)}</td>
            <td><code class="mono">${escapeHtml(r.target || "—")}</code></td>
            <td>${title}</td>
            <td style="color: #6B7280">${escapeHtml(r.operator || "—")}</td>
          </tr>`;
      })
      .join("");
  }

  function renderModelPerf(m) {
    const grid = document.querySelector("#section-model .report-overview");
    if (!grid) return;
    setText(grid.querySelector('[data-model="version"]'), m.version);
    setText(grid.querySelector('[data-model="total_checked"]'), fmtInt(m.total_checked));
    setText(grid.querySelector('[data-model="avg_confidence"]'), (m.avg_confidence ?? 0).toFixed(2));
    setText(
      grid.querySelector('[data-model="high_confidence_ratio"]'),
      fmtPercent(m.high_confidence_ratio)
    );
    setText(grid.querySelector('[data-model="detection_rate"]'), fmtPercent(m.detection_rate));
    setText(
      grid.querySelector('[data-model="mean_resolution"]'),
      fmtDuration(m.mean_resolution_latency_sec)
    );

    if (!window.echarts) return;
    const chart = ensureChart("conf", el.chartConfidence);
    const dist = m.confidence_distribution || [];
    chart.setOption({
      ...reportChartTheme(),
      grid: { left: 60, right: 20, top: 20, bottom: 30 },
      tooltip: { trigger: "axis", axisPointer: { type: "shadow" } },
      xAxis: {
        type: "category",
        data: dist.map((d) => d.range),
        axisLine: { lineStyle: { color: "#E5E7EB" } },
        axisLabel: { color: "#6B7280" },
      },
      yAxis: {
        type: "value",
        axisLine: { lineStyle: { color: "#E5E7EB" } },
        splitLine: { lineStyle: { color: "#F3F4F6" } },
        axisLabel: { color: "#6B7280" },
      },
      series: [
        {
          type: "bar",
          data: dist.map((d) => d.count),
          barMaxWidth: 28,
          itemStyle: { color: "#60A5FA", borderRadius: [4, 4, 0, 0] },
          label: { show: true, position: "top", color: "#111827", fontSize: 11 },
        },
      ],
    });
  }

  function renderRecommendations(items) {
    if (!items.length) {
      el.recommendations.innerHTML = "";
      return;
    }
    el.recommendations.innerHTML = items
      .map(
        (r) => `
        <li class="report-recommendations__item report-recommendations__item--${escapeHtml(r.severity || "info")}">
          <h3 class="report-recommendations__title">${escapeHtml(r.title || "—")}</h3>
          <p class="report-recommendations__body">${escapeHtml(r.body || "")}</p>
        </li>`
      )
      .join("");
  }

  /* =============================================================
   * 交互：周期切换 / 刷新 / 导出
   * ============================================================= */
  function bindHandlers() {
    el.btnPeriods.forEach((btn) => {
      btn.addEventListener("click", () => {
        state.period = btn.dataset.period;
        el.btnPeriods.forEach((b) =>
          b.classList.toggle("is-active", b === btn)
        );
        loadSummary();
      });
    });

    el.btnRefresh.addEventListener("click", loadSummary);

    el.btnExportJson.addEventListener("click", () => {
      if (!state.summary) return;
      const blob = new Blob([JSON.stringify(state.summary, null, 2)], {
        type: "application/json",
      });
      triggerDownload(blob, `report-${state.period}-${stampNow()}.json`);
    });

    el.btnExportHtml.addEventListener("click", exportHtmlSnapshot);
    el.btnExportPdf.addEventListener("click", () => {
      toast("即将唤起打印窗口；选择「另存为 PDF」即可", "info");
      setTimeout(() => window.print(), 300);
    });

    // 窗口尺寸变化时 ECharts 跟随
    window.addEventListener("resize", () => {
      Object.values(state.charts).forEach((c) => c && c.resize());
    });
  }

  function stampNow() {
    const d = new Date();
    const pad = (n) => String(n).padStart(2, "0");
    return (
      d.getFullYear().toString() +
      pad(d.getMonth() + 1) +
      pad(d.getDate()) +
      "-" +
      pad(d.getHours()) +
      pad(d.getMinutes())
    );
  }

  function triggerDownload(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => {
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }, 0);
  }

  function exportHtmlSnapshot() {
    // 把报告主体 + 关键样式打成一个自包含 HTML
    const report = document.getElementById("report-root");
    if (!report) return;
    const theme = document.querySelector('link[href*="theme.css"]');
    const components = document.querySelector('link[href*="components.css"]');
    const reportsCss = document.querySelector('link[href*="reports.css"]');
    const links = [theme, components, reportsCss]
      .filter(Boolean)
      .map((n) => `<link rel="stylesheet" href="${n.href}" />`)
      .join("\n");

    const html = `<!DOCTYPE html>
<html lang="zh-CN" data-theme="report">
<head>
<meta charset="UTF-8" />
<title>${escapeHtml(el.coverTitle.textContent)}</title>
${links}
<style>body{margin:0;padding:24px;background:#fff;color:#111827}</style>
</head>
<body>
${report.outerHTML}
</body>
</html>`;
    const blob = new Blob([html], { type: "text/html;charset=utf-8" });
    triggerDownload(blob, `report-${state.period}-${stampNow()}.html`);
  }

  /* =============================================================
   * 启动
   * ============================================================= */
  async function init() {
    // 兜底：若 base.html 没挂 data-theme，也强制浅色
    if (document.documentElement.getAttribute("data-theme") !== "report") {
      document.documentElement.setAttribute("data-theme", "report");
    }
    bindHandlers();
    await loadSummary();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
