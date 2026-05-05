/*
 * dashboard.js — Phase 7 安全态势仪表盘
 *
 * 职责：
 *   - 初始化三张 ECharts 图表（流量 / 攻击类型 / Top10 攻击来源）
 *   - 拉取 `/api/stats`、`/api/alerts`、`/api/metrics/*`
 *   - 建立 WebSocket 订阅（Phase 7 P2 已统一事件名）：
 *       `alert`           -> 实时告警列表 + 时间线；高/严重等级同时弹 toast
 *       `metrics_update`  -> 指标卡刷新
 *       `alert_updated`   -> 告警状态同步（透传）
 *     旧 `new_alert` / `threat_detected` 已下线。
 *
 * 所有数据渲染都走 AGUI.escapeHtml 做 XSS 防护。
 */
(function () {
  "use strict";

  if (!window.AGApi) return; // base.html 已保证加载顺序，这里是保险

  const { fetchApi } = window.AGApi;
  const { escapeHtml, formatTime, levelBadge, toast } = window.AGUI;

  // ECharts 共用配色
  const CHART_COLORS = {
    emerald: "#10B981",
    low: "#3B82F6",
    medium: "#F59E0B",
    high: "#EF4444",
    critical: "#EC4899",
    purple: "#8B5CF6",
    text: "#E8E8EC",
    subtle: "#2A2A2E",
    secondary: "#8B8B96",
  };

  let trafficChart;
  let attackTypeChart;
  let topAttackerChart;
  let currentRange = "24h";

  document.addEventListener("DOMContentLoaded", () => {
    initCharts();
    bindRangeTabs();
    bindRefresh();
    loadInitial();
    connectWebSocket();

    window.addEventListener("resize", () => {
      [trafficChart, attackTypeChart, topAttackerChart].forEach(
        (c) => c && c.resize()
      );
    });
  });

  /* ----------------------------- 图表初始化 ----------------------------- */
  function initCharts() {
    if (!window.echarts) return;

    trafficChart = window.echarts.init(
      document.getElementById("chart-traffic"),
      null,
      { renderer: "canvas" }
    );
    trafficChart.setOption(buildTrafficOption([], []));

    attackTypeChart = window.echarts.init(
      document.getElementById("chart-attack-types")
    );
    attackTypeChart.setOption(buildAttackTypeOption([]));

    topAttackerChart = window.echarts.init(
      document.getElementById("chart-top-attackers")
    );
    topAttackerChart.setOption(buildTopAttackerOption([]));
  }

  function buildTrafficOption(xaxis, series) {
    return {
      grid: { left: 40, right: 24, top: 24, bottom: 36 },
      tooltip: {
        trigger: "axis",
        backgroundColor: "#141416",
        borderColor: "#2A2A2E",
        textStyle: { color: CHART_COLORS.text },
      },
      xAxis: {
        type: "category",
        data: xaxis,
        axisLine: { lineStyle: { color: CHART_COLORS.subtle } },
        axisLabel: { color: CHART_COLORS.secondary, fontSize: 11 },
      },
      yAxis: {
        type: "value",
        splitLine: { lineStyle: { color: CHART_COLORS.subtle } },
        axisLabel: { color: CHART_COLORS.secondary, fontSize: 11 },
      },
      series: [
        {
          name: "流量",
          data: series,
          type: "line",
          smooth: true,
          symbol: "circle",
          symbolSize: 6,
          areaStyle: {
            color: {
              type: "linear",
              x: 0,
              y: 0,
              x2: 0,
              y2: 1,
              colorStops: [
                { offset: 0, color: "rgba(16,185,129,0.25)" },
                { offset: 1, color: "rgba(16,185,129,0.01)" },
              ],
            },
          },
          lineStyle: { color: CHART_COLORS.emerald, width: 2 },
          itemStyle: { color: CHART_COLORS.emerald },
        },
      ],
    };
  }

  function buildAttackTypeOption(distribution) {
    const fallbackColors = {
      ddos: CHART_COLORS.high,
      web_attack: CHART_COLORS.medium,
      intrusion: CHART_COLORS.low,
      anomaly: CHART_COLORS.emerald,
      threat_intel: CHART_COLORS.critical,
      unknown: CHART_COLORS.purple,
    };

    const data = (distribution || []).map((d) => ({
      name: d.name || "未知",
      value: d.value || 0,
      itemStyle: { color: fallbackColors[d.name] || CHART_COLORS.purple },
    }));

    return {
      tooltip: {
        trigger: "item",
        backgroundColor: "#141416",
        borderColor: "#2A2A2E",
        textStyle: { color: CHART_COLORS.text },
      },
      legend: {
        bottom: 0,
        textStyle: { color: CHART_COLORS.secondary, fontSize: 11 },
        icon: "circle",
      },
      series: [
        {
          type: "pie",
          radius: ["40%", "70%"],
          center: ["50%", "45%"],
          avoidLabelOverlap: true,
          label: {
            color: CHART_COLORS.text,
            fontSize: 11,
            formatter: "{b}\n{d}%",
          },
          labelLine: { lineStyle: { color: CHART_COLORS.subtle } },
          data:
            data.length > 0
              ? data
              : [
                  {
                    name: "暂无数据",
                    value: 1,
                    itemStyle: { color: CHART_COLORS.subtle },
                  },
                ],
        },
      ],
    };
  }

  function buildTopAttackerOption(list) {
    const rows = (list || []).slice().reverse();
    return {
      grid: { left: 110, right: 24, top: 16, bottom: 24 },
      tooltip: {
        trigger: "axis",
        axisPointer: { type: "shadow" },
        backgroundColor: "#141416",
        borderColor: "#2A2A2E",
        textStyle: { color: CHART_COLORS.text },
      },
      xAxis: {
        type: "value",
        splitLine: { lineStyle: { color: CHART_COLORS.subtle } },
        axisLabel: { color: CHART_COLORS.secondary, fontSize: 11 },
      },
      yAxis: {
        type: "category",
        data: rows.map((r) => r.ip),
        axisLine: { lineStyle: { color: CHART_COLORS.subtle } },
        axisLabel: {
          color: CHART_COLORS.secondary,
          fontSize: 11,
          fontFamily: "JetBrains Mono, monospace",
        },
      },
      series: [
        {
          name: "命中次数",
          type: "bar",
          data: rows.map((r) => r.count),
          itemStyle: { color: CHART_COLORS.high, borderRadius: [0, 4, 4, 0] },
          barMaxWidth: 16,
        },
      ],
    };
  }

  /* ----------------------------- 数据拉取 ----------------------------- */
  async function loadInitial() {
    await Promise.allSettled([
      refreshStats(),
      refreshTraffic(),
      refreshAttackTypes(),
      refreshTopAttackers(),
      refreshAlerts(),
    ]);
  }

  async function refreshStats() {
    try {
      const stats = await fetchApi("/api/stats");
      applyMetrics(stats);
    } catch (err) {
      console.warn("拉取统计失败", err);
    }
  }

  async function refreshAttackTypes() {
    try {
      const data = await fetchApi("/api/metrics/attack_types");
      attackTypeChart && attackTypeChart.setOption(buildAttackTypeOption(data));
    } catch (err) {
      console.warn("拉取攻击类型失败", err);
    }
  }

  async function refreshTraffic() {
    try {
      const data = await fetchApi("/api/metrics/traffic", {
        query: { range: currentRange },
      });
      const xaxis = Array.isArray(data.xaxis) ? data.xaxis : [];
      const series = Array.isArray(data.series) ? data.series : [];
      trafficChart && trafficChart.setOption(buildTrafficOption(xaxis, series));
    } catch (err) {
      console.warn("拉取流量趋势失败", err);
      trafficChart && trafficChart.setOption(buildTrafficOption([], []));
    }
  }

  async function refreshTopAttackers() {
    try {
      const data = await fetchApi("/api/metrics/top_attackers");
      topAttackerChart && topAttackerChart.setOption(buildTopAttackerOption(data));
    } catch (err) {
      console.warn("拉取攻击 Top10 失败", err);
    }
  }

  async function refreshAlerts() {
    try {
      const list = await fetchApi("/api/alerts", { query: { limit: 20 } });
      renderAlertList(list);
      renderTimeline(list.slice(0, 10));
    } catch (err) {
      console.warn("拉取告警失败", err);
    }
  }

  /* ----------------------------- 指标卡渲染 ----------------------------- */
  const _prevMetrics = {};

  function applyMetrics(stats) {
    if (!stats || typeof stats !== "object") return;

    [
      ["total_packets", ""],
      ["total_threats", ""],
      ["security_score", ""],
      ["banned_ips", ""],
    ].forEach(([key]) => {
      const node = document.querySelector(`[data-metric="${key}"]`);
      const trendNode = document.querySelector(`[data-trend="${key}"]`);
      if (!node) return;
      const next = stats[key];
      if (next === undefined || next === null) return;

      node.textContent = Number(next).toLocaleString();
      if (trendNode) {
        const prev = _prevMetrics[key];
        if (typeof prev === "number" && prev !== next) {
          const delta = next - prev;
          trendNode.textContent = (delta > 0 ? "▲ +" : "▼ ") + Math.abs(delta);
          trendNode.classList.toggle("metric-card__trend--up", delta > 0);
          trendNode.classList.toggle("metric-card__trend--down", delta < 0);
        }
      }
      _prevMetrics[key] = Number(next);
    });

    // 安全评分变红的联动（<60 强制红色）
    const scoreNode = document.querySelector('[data-metric="security_score"]');
    if (scoreNode) {
      const score = Number(stats.security_score);
      scoreNode.classList.toggle("metric-card__value--danger", score < 60);
      scoreNode.classList.toggle(
        "metric-card__value--emerald",
        score >= 60
      );
    }
  }

  /* ----------------------------- 告警列表 ----------------------------- */
  function renderAlertList(items) {
    const list = document.getElementById("alert-list");
    if (!list) return;
    if (!items || items.length === 0) {
      list.innerHTML = '<li class="alert-list__empty">暂无告警</li>';
      return;
    }
    list.innerHTML = items.map(renderAlertItem).join("");
  }

  function renderAlertItem(alert) {
    const level = alert.level || alert.threat_level || "low";
    return (
      '<li class="alert-item alert-item--' +
      level +
      '">' +
      '<span class="alert-item__stripe" aria-hidden="true"></span>' +
      '<div class="alert-item__content">' +
      '<p class="alert-item__title">' +
      escapeHtml(alert.details || alert.message || "未知事件") +
      "</p>" +
      '<div class="alert-item__meta">' +
      '<span class="alert-item__time">' +
      escapeHtml(formatTime(alert.timestamp)) +
      "</span>" +
      (alert.source_ip
        ? '<span class="alert-item__ip">' +
          escapeHtml(alert.source_ip) +
          "</span>"
        : "") +
      (alert.threat_type
        ? '<span>' + escapeHtml(alert.threat_type) + "</span>"
        : "") +
      "</div>" +
      "</div>" +
      '<div class="alert-item__side">' +
      levelBadge(level) +
      "</div>" +
      "</li>"
    );
  }

  function prependAlert(alert) {
    const list = document.getElementById("alert-list");
    if (!list) return;
    // 清空占位
    const empty = list.querySelector(".alert-list__empty");
    if (empty) empty.remove();

    const tpl = document.createElement("template");
    tpl.innerHTML = renderAlertItem(alert).trim();
    const node = tpl.content.firstChild;
    list.prepend(node);

    // 只保留最近 20 条
    const items = list.querySelectorAll(".alert-item");
    for (let i = 20; i < items.length; i++) {
      items[i].remove();
    }

    prependTimeline(alert);
  }

  /* ----------------------------- 时间线 ------------------------------- */
  function renderTimeline(items) {
    const node = document.getElementById("event-timeline");
    if (!node) return;
    if (!items || items.length === 0) {
      node.innerHTML = '<li class="alert-list__empty">暂无事件</li>';
      return;
    }
    node.innerHTML = items.map(renderTimelineItem).join("");
  }

  function renderTimelineItem(alert) {
    const level = alert.level || alert.threat_level || "low";
    return (
      '<li class="timeline__item">' +
      '<span class="timeline__time">' +
      escapeHtml(formatTime(alert.timestamp)) +
      "</span>" +
      levelBadge(level) +
      "<span> " +
      escapeHtml(alert.details || alert.message || "未知事件") +
      "</span>" +
      "</li>"
    );
  }

  function prependTimeline(alert) {
    const node = document.getElementById("event-timeline");
    if (!node) return;
    const empty = node.querySelector(".alert-list__empty");
    if (empty) empty.remove();
    const tpl = document.createElement("template");
    tpl.innerHTML = renderTimelineItem(alert).trim();
    node.prepend(tpl.content.firstChild);
    const items = node.querySelectorAll(".timeline__item");
    for (let i = 20; i < items.length; i++) items[i].remove();
  }

  /* ----------------------------- WebSocket ---------------------------- */
  function connectWebSocket() {
    if (!window.io) return;

    const socket = window.io({
      transports: ["websocket", "polling"],
      reconnection: true,
      reconnectionAttempts: Infinity,
      reconnectionDelay: 2000,
    });

    socket.on("connect", () => {
      console.info("[ws] connected");
    });

    socket.on("metrics_update", (payload) => {
      applyMetrics(payload || {});
    });

    // 统一事件名（DESIGN §8.2 / Phase 7 Prompt 指定）
    socket.on("alert", (alert) => handleIncomingAlert(alert));

    socket.on("disconnect", () => console.info("[ws] disconnected"));
  }

  function handleIncomingAlert(alert) {
    if (!alert || typeof alert !== "object") return;
    prependAlert(alert);
    refreshAttackTypes();
    refreshTopAttackers();

    // 高危与严重等级自动弹 toast，替代旧 threat_detected 事件的行为
    const level = alert.level || alert.threat_level;
    if (level === "high" || level === "critical") {
      const title = alert.title || alert.summary || alert.details || alert.threat_type || "未分类威胁";
      toast(
        "检测到" + (level === "critical" ? "严重" : "高危") + "威胁：" + title,
        level === "critical" ? "error" : "warning"
      );
    }
  }

  /* ----------------------------- 交互绑定 ----------------------------- */
  function bindRangeTabs() {
    document.querySelectorAll("[data-range]").forEach((btn) => {
      btn.addEventListener("click", () => {
        currentRange = btn.dataset.range;
        document
          .querySelectorAll("[data-range]")
          .forEach((b) => b.classList.remove("is-active"));
        btn.classList.add("is-active");
        refreshTraffic();
      });
    });
  }

  function bindRefresh() {
    const btn = document.getElementById("btn-refresh");
    if (!btn) return;
    btn.addEventListener("click", () => {
      btn.disabled = true;
      loadInitial().finally(() => {
        btn.disabled = false;
      });
    });
  }
})();
