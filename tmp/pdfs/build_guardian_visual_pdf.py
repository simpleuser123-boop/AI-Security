from __future__ import annotations

import json
import os
import re
from datetime import datetime
from pathlib import Path

from PIL import Image
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm, mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    Flowable,
    Image as RLImage,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


_ENV_ROOT = os.environ.get("GUARDIAN_PROJECT_ROOT")
if _ENV_ROOT:
    ROOT = Path(_ENV_ROOT)
else:
    _BASE = Path(__file__).resolve().parents[2]
    ROOT = _BASE / "ai-security-guardian" if (_BASE / "ai-security-guardian").exists() else _BASE
ASSET_DIR = ROOT / "tmp" / "pdfs" / "guardian-visual-assets"
OUT_DIR = ROOT / "output" / "pdf"
OUT_DIR.mkdir(parents=True, exist_ok=True)
OUT_PDF = OUT_DIR / "AI安全守卫-v1.0-可视化运行过程报告.pdf"

SOURCE_DOC = ROOT / "docs" / "AI安全守卫-v1.0-原型评估与企业级演进方案.md"
GUARDIAN_LOG = ROOT / ".tmp" / "codex-run-guardian" / "guardian.err.log"


def register_fonts() -> tuple[str, str]:
    regular_candidates = [
        Path(r"C:\Windows\Fonts\NotoSansSC-VF.ttf"),
        Path(r"C:\Windows\Fonts\simhei.ttf"),
        Path(r"C:\Windows\Fonts\Deng.ttf"),
    ]
    bold_candidates = [
        Path(r"C:\Windows\Fonts\NotoSansSC-VF.ttf"),
        Path(r"C:\Windows\Fonts\simhei.ttf"),
        Path(r"C:\Windows\Fonts\Dengb.ttf"),
    ]
    regular = next(p for p in regular_candidates if p.exists())
    bold = next(p for p in bold_candidates if p.exists())
    pdfmetrics.registerFont(TTFont("GuardianCJK", str(regular)))
    pdfmetrics.registerFont(TTFont("GuardianCJKBold", str(bold)))
    return "GuardianCJK", "GuardianCJKBold"


FONT, BOLD = register_fonts()


def P(text: str, style: ParagraphStyle) -> Paragraph:
    return Paragraph(text.replace("\n", "<br/>"), style)


def safe(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


styles = getSampleStyleSheet()
styles.add(
    ParagraphStyle(
        name="CoverTitle",
        fontName=BOLD,
        fontSize=26,
        leading=34,
        textColor=colors.HexColor("#0f172a"),
        alignment=TA_LEFT,
        spaceAfter=12,
    )
)
styles.add(
    ParagraphStyle(
        name="CoverSub",
        fontName=FONT,
        fontSize=12,
        leading=20,
        textColor=colors.HexColor("#334155"),
        alignment=TA_LEFT,
    )
)
styles.add(
    ParagraphStyle(
        name="H1CJK",
        fontName=BOLD,
        fontSize=17,
        leading=24,
        textColor=colors.HexColor("#0f172a"),
        spaceBefore=8,
        spaceAfter=10,
    )
)
styles.add(
    ParagraphStyle(
        name="H2CJK",
        fontName=BOLD,
        fontSize=13,
        leading=19,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=8,
        spaceAfter=6,
    )
)
styles.add(
    ParagraphStyle(
        name="BodyCJK",
        fontName=FONT,
        fontSize=9.4,
        leading=15,
        textColor=colors.HexColor("#334155"),
        alignment=TA_LEFT,
    )
)
styles.add(
    ParagraphStyle(
        name="SmallCJK",
        fontName=FONT,
        fontSize=8.2,
        leading=12,
        textColor=colors.HexColor("#64748b"),
    )
)
styles.add(
    ParagraphStyle(
        name="Callout",
        fontName=BOLD,
        fontSize=10.5,
        leading=16,
        textColor=colors.HexColor("#075985"),
        backColor=colors.HexColor("#e0f2fe"),
        borderColor=colors.HexColor("#7dd3fc"),
        borderWidth=0.6,
        borderPadding=8,
        spaceAfter=10,
    )
)


class ProcessDiagram(Flowable):
    def __init__(self, width: float, height: float) -> None:
        super().__init__()
        self.width = width
        self.height = height

    def draw(self) -> None:
        c = self.canv
        boxes = [
            ("1. 访问日志", "GET /login?u=admin' OR 1=1--"),
            ("2. 采集入口", "LogCollector 读取 logs/access.log"),
            ("3. Web 检测", "WebAttackDetector 命中 SQLi 规则"),
            ("4. 决策响应", "HIGH 告警, notify, dry-run ban"),
            ("5. 审计展示", "security.log + 告警中心可视化"),
        ]
        x = 8 * mm
        y = self.height - 28 * mm
        w = self.width - 16 * mm
        h = 18 * mm
        gap = 8 * mm
        for idx, (title, desc) in enumerate(boxes):
            fill = colors.HexColor("#f8fafc") if idx % 2 == 0 else colors.HexColor("#eef6ff")
            c.setFillColor(fill)
            c.setStrokeColor(colors.HexColor("#38bdf8"))
            c.roundRect(x, y, w, h, 5, fill=1, stroke=1)
            c.setFillColor(colors.HexColor("#0f172a"))
            c.setFont(BOLD, 9.5)
            c.drawString(x + 6 * mm, y + 10.7 * mm, title)
            c.setFont(FONT, 8)
            c.setFillColor(colors.HexColor("#475569"))
            c.drawString(x + 6 * mm, y + 4.8 * mm, desc)
            if idx < len(boxes) - 1:
                c.setStrokeColor(colors.HexColor("#94a3b8"))
                cx = x + w / 2
                c.line(cx, y - 1 * mm, cx, y - gap + 2 * mm)
                c.line(cx, y - gap + 2 * mm, cx - 2 * mm, y - gap + 5 * mm)
                c.line(cx, y - gap + 2 * mm, cx + 2 * mm, y - gap + 5 * mm)
            y -= h + gap


def table(data, widths, header=True):
    t = Table(data, colWidths=widths, hAlign="LEFT")
    style = [
        ("FONTNAME", (0, 0), (-1, -1), FONT),
        ("FONTSIZE", (0, 0), (-1, -1), 8.2),
        ("LEADING", (0, 0), (-1, -1), 11),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#cbd5e1")),
        ("BACKGROUND", (0, 1 if header else 0), (-1, -1), colors.white),
        ("ROWBACKGROUNDS", (0, 1 if header else 0), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]
    if header:
        style.extend(
            [
                ("FONTNAME", (0, 0), (-1, 0), BOLD),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ]
        )
    t.setStyle(TableStyle(style))
    return t


def image_flowable(filename: str, max_w: float, max_h: float) -> RLImage:
    path = ASSET_DIR / filename
    with Image.open(path) as img:
        iw, ih = img.size
    scale = min(max_w / iw, max_h / ih)
    return RLImage(str(path), width=iw * scale, height=ih * scale)


def parse_latest_evidence() -> list[str]:
    if not GUARDIAN_LOG.exists():
        return []
    lines = GUARDIAN_LOG.read_text(encoding="utf-8", errors="ignore").splitlines()
    wanted = []
    for line in lines:
        if "20:18:35" in line and (
            "sql_injection" in line
            or '"action": "notify"' in line
            or '"action": "ban_ip"' in line
            or '"event_type": "web_attack"' in line
            or "WebAttackDetector" in line
        ):
            cleaned = re.sub(r"\s+", " ", line).strip()
            wanted.append(cleaned)
    return wanted[-6:]


def build_story() -> list:
    story = []
    doc_text = SOURCE_DOC.read_text(encoding="utf-8", errors="ignore")
    doc_lines = len(doc_text.splitlines())
    generated = datetime.now().strftime("%Y-%m-%d %H:%M")

    story.append(Spacer(1, 25 * mm))
    story.append(P("AI安全守卫 v1.0<br/>可视化运行过程报告", styles["CoverTitle"]))
    story.append(
        P(
            f"生成时间：{generated}<br/>依据文档：{safe(str(SOURCE_DOC))}<br/>"
            "依据实跑：本地 Web 控制台、Guardian 主链路、SQL 注入样例告警、审计日志与告警中心截图。",
            styles["CoverSub"],
        )
    )
    story.append(Spacer(1, 18 * mm))
    story.append(
        P(
            "结论摘要：当前系统适合 L0 演示与 L1 内部 PoC，并已接近 L2 预生产监控模式。"
            "本次运行证明了 Web 日志采集、Web 攻击检测、响应 dry-run、审计记录和告警可视化可以串成完整演示闭环。",
            styles["Callout"],
        )
    )
    story.append(
        table(
            [
                ["项目", "本次报告采用的事实"],
                ["源文档规模", f"{doc_lines} 行 Markdown，主题为原型评估与企业级演进方案"],
                ["Web 控制台", "http://127.0.0.1:5001，临时演示账号 admin / changeme"],
                ["主检测链路", "main.py --no-packet-capture，Web 日志采集开启，DRY_RUN=true"],
                ["演示事件", "GET /login?u=admin' OR 1=1--，命中 sql_injection，高危告警"],
            ],
            [36 * mm, 122 * mm],
        )
    )

    story.append(PageBreak())
    story.append(P("1. 文档评估结论", styles["H1CJK"]))
    story.append(
        P(
            "原型评估文档明确指出：AI安全守卫属于企业级安全平台方向，当前是 v1.0 原型 / MVP / 预生产试点基础，"
            "适合演示、答辩、内部 PoC、dry-run 监控和小范围试点，但尚不建议直接作为正式生产级自动阻断产品。",
            styles["BodyCJK"],
        )
    )
    story.append(
        table(
            [
                ["维度", "当前判断", "报告解读"],
                ["产品方向", "企业级方向", "覆盖采集、检测、决策、响应、审计和运营可视化。"],
                ["工程状态", "v1.0 原型 / MVP", "模块骨架完整，但仍需真实环境演练、测试治理和模型可信度提升。"],
                ["交付状态", "可 PoC / 可内部试点", "本次实跑已验证可完成一条可展示的检测闭环。"],
                ["生产状态", "尚未正式生产级", "真实封禁、隔离、SLA、审计责任和合规仍需企业级治理。"],
            ],
            [27 * mm, 35 * mm, 96 * mm],
        )
    )
    story.append(Spacer(1, 5 * mm))
    story.append(
        P(
            "推荐分级：当前建议评级为 L1 到 L2 之间。下一阶段宜进入 L2 预生产监控模式，"
            "接入真实日志或镜像流量，但继续保持 DRY_RUN=true，避免自动阻断误伤业务。",
            styles["Callout"],
        )
    )

    story.append(P("2. 本次全流程运行链路", styles["H1CJK"]))
    story.append(ProcessDiagram(158 * mm, 150 * mm))
    story.append(Spacer(1, 3 * mm))
    story.append(
        P(
            "本次运行没有启用真实抓包，原因是生产式抓包需要管理员权限和网卡/Npcap环境。"
            "为了可重复演示，采用 Web 访问日志作为采集入口，触发可控 SQL 注入样例，并保持响应处置为 dry-run。",
            styles["SmallCJK"],
        )
    )

    story.append(PageBreak())
    story.append(P("3. 可视化界面证据", styles["H1CJK"]))
    story.append(
        P(
            "仪表盘展示了安全评分、威胁总数、流量趋势、攻击类型分布和实时告警入口。"
            "这是面向 SOC 辅助运营的第一层视图。",
            styles["BodyCJK"],
        )
    )
    story.append(image_flowable("dashboard-view.png", 95 * mm, 145 * mm))
    story.append(Spacer(1, 4 * mm))
    story.append(
        P(
            "告警中心展示了本次链路生成的高危 Web 攻击告警：规则引擎命中 sql_injection，来源 127.0.0.1，类型 web_attack。",
            styles["BodyCJK"],
        )
    )
    story.append(image_flowable("alerts-list-view.png", 95 * mm, 145 * mm))

    story.append(PageBreak())
    story.append(P("4. 运行证据时间线", styles["H1CJK"]))
    evidence_rows = [
        ["时间", "阶段", "证据"],
        ["20:17:58", "登录与仪表盘", "进入安全态势感知控制台，仪表盘显示威胁总数、安全评分、实时告警等组件。"],
        ["20:18:17", "攻击样例", "请求 /login?u=admin%27%20OR%201%3D1-- 写入 logs/access.log。"],
        ["20:18:35", "检测命中", "WebAttackDetector 检出 sql_injection，source_ip=127.0.0.1，confidence=0.95。"],
        ["20:18:35", "响应动作", "触发 notify 与 ban_ip；因 DRY_RUN=true，仅模拟 iptables 封禁，不修改系统防火墙。"],
        ["20:18:35", "审计记录", "security.log 记录 web_attack、response、hash 链完整性字段。"],
        ["刷新后", "可视化展示", "告警中心显示 HIGH 级别的 sql_injection 告警，完成可视化闭环。"],
    ]
    story.append(table(evidence_rows, [24 * mm, 30 * mm, 104 * mm]))

    story.append(Spacer(1, 6 * mm))
    story.append(P("关键日志摘录", styles["H2CJK"]))
    logs = parse_latest_evidence()
    log_rows = [["序号", "日志片段"]]
    for i, line in enumerate(logs, 1):
        line = safe(line)
        if len(line) > 210:
            line = line[:207] + "..."
        log_rows.append([str(i), line])
    story.append(table(log_rows, [12 * mm, 146 * mm]))

    story.append(PageBreak())
    story.append(P("5. 与企业级演进方案的对应关系", styles["H1CJK"]))
    story.append(
        table(
            [
                ["路线", "文档目标", "本次实跑观察", "下一步"],
                ["R1", "生产配置与基线整理", "仍使用 development + DRY_RUN=true，适合演示。", "增加生产配置一键校验。"],
                ["R2", "测试稳定化与全量验收", "本次未重跑全量 pytest，仅验证演示链路。", "治理慢测、后台线程和 Redis 探测。"],
                ["R3", "模型可信度升级", "规则引擎 SQLi 检测可演示；模型指标仍需正式报告。", "补齐 Precision、Recall、FPR、FNR。"],
                ["R4", "真实环境部署演练", "本地 Web 日志链路已通；真实抓包未启用。", "预发环境验证网卡抓包、Redis Stream 和 WSS。"],
                ["R5", "响应闭环治理", "notify 与 ban_ip 已触发，但为 dry-run。", "上线前加入白名单、审批、回滚和误封处理。"],
                ["R6", "运维交付", "健康检查和日志可用，审计日志已有断链风险。", "归档测试日志，重建干净生产审计基线。"],
                ["R7", "产品化增强", "告警中心、规则、威胁情报等页面具备雏形。", "补 RBAC、SIEM/工单/企业 IM 集成。"],
            ],
            [14 * mm, 36 * mm, 55 * mm, 53 * mm],
        )
    )

    story.append(Spacer(1, 6 * mm))
    story.append(P("6. 结论", styles["H1CJK"]))
    story.append(
        P(
            "本次可视化运行证明：AI安全守卫 v1.0 已经具备从日志采集到告警展示的可演示闭环。"
            "它可以作为课程答辩、PoC 和内部试点材料，但若要进入企业级正式生产，仍需优先完成生产配置校验、"
            "全量测试稳定化、审计基线重建、模型评估报告、真实环境演练和响应治理。",
            styles["BodyCJK"],
        )
    )
    story.append(
        P(
            "建议下一阶段目标：L2 预生产监控模式。即接入真实日志和镜像流量，继续保持只告警不阻断，"
            "用真实环境数据验证误报、漏报、延迟、队列恢复和审计可靠性。",
            styles["Callout"],
        )
    )
    return story


def add_header_footer(canvas, doc):
    canvas.saveState()
    page_w, page_h = A4
    canvas.setFont(FONT, 7.5)
    canvas.setFillColor(colors.HexColor("#64748b"))
    canvas.drawString(18 * mm, page_h - 12 * mm, "AI安全守卫 v1.0 可视化运行过程报告")
    canvas.drawRightString(page_w - 18 * mm, 10 * mm, f"第 {doc.page} 页")
    canvas.setStrokeColor(colors.HexColor("#e2e8f0"))
    canvas.line(18 * mm, page_h - 15 * mm, page_w - 18 * mm, page_h - 15 * mm)
    canvas.restoreState()


def main() -> None:
    doc = SimpleDocTemplate(
        str(OUT_PDF),
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=20 * mm,
        bottomMargin=17 * mm,
        title="AI安全守卫 v1.0 可视化运行过程报告",
        author="Codex",
    )
    doc.build(build_story(), onFirstPage=add_header_footer, onLaterPages=add_header_footer)
    print(OUT_PDF)


if __name__ == "__main__":
    main()
