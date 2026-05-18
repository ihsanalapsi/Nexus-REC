import json
import re
from datetime import datetime
from pathlib import Path
from textwrap import wrap

from modules.core.summary import infer_stack


SENSITIVE_KEY_HINTS = (
    "secret", "token", "key", "password", "passwd", "credential",
    "cookie", "authorization", "jwt", "bearer", "client_secret",
    "service_role", "anon_key", "api_key",
)


def redact_results(value, parent_key=""):
    if isinstance(value, dict):
        return {k: redact_results(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_results(item, parent_key) for item in value]

    key = str(parent_key).lower()
    if any(hint in key for hint in SENSITIVE_KEY_HINTS):
        if value in (None, "", [], {}):
            return value
        text = str(value)
        if len(text) <= 10:
            return "[redacted]"
        return f"{text[:6]}...[redacted]"
    return value


def _safe_filename(value):
    safe = re.sub(r'[^A-Za-z0-9._-]+', '_', value).strip('_')
    return safe or 'target'


def _count_findings(value):
    if isinstance(value, list):
        return len(value)
    if isinstance(value, dict):
        return sum(
            _count_findings(v)
            for k, v in value.items()
            if not str(k).startswith('skipped_') and k != 'scan_mode'
        )
    return 0


def _markdown_table(headers, rows):
    out = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        out.append("| " + " | ".join(str(cell).replace("\n", " ") for cell in row) + " |")
    return "\n".join(out)


def _completed(metadata, name):
    completed = metadata.get('completed_result_sections', [])
    return name in completed


def _real_vulnerability_items(vulnerabilities):
    if not isinstance(vulnerabilities, dict):
        return {}
    return {
        finding_type: findings
        for finding_type, findings in vulnerabilities.items()
        if not finding_type.startswith('skipped_')
        and finding_type != 'scan_mode'
        and isinstance(findings, list)
        and findings
    }


def generate_markdown_report(results, domain):
    metadata = results.get('scan_metadata', {})
    basic = results.get('basic', {})
    headers = basic.get('headers', {})
    tech = basic.get('technologies', {})
    stack = infer_stack(results)
    waf = basic.get('waf', [])

    lines = [
        f"# Nexus-REC Security Report: {domain}",
        "",
        "## 1. Executive Summary",
        "",
        f"- Target: `{domain}`",
        f"- Scan mode: `{metadata.get('scan_mode', 'unknown')}`",
        f"- Started at: `{metadata.get('started_at', 'unknown')}`",
    ]
    if metadata.get('stealth'):
        lines.append("- Stealth mode: `enabled`")
    if stack:
        lines.append(f"- Detected stack: {', '.join(stack)}")
    if waf:
        lines.append(f"- WAF/CDN signal: {', '.join(waf)}")
    if tech:
        lines.append(f"- Technologies detected: {len(tech)}")
    lines.append("")

    requested = metadata.get('requested_modules', 'unknown')
    if isinstance(requested, list):
        requested_text = ', '.join(requested)
    else:
        requested_text = str(requested)
    completed = metadata.get('completed_result_sections', [])
    not_selected = metadata.get('not_selected_or_skipped_modules', [])
    coverage_rows = [
        ["Requested modules", requested_text],
        ["Completed result sections", ', '.join(completed) if completed else 'None recorded'],
        ["Not selected / skipped", ', '.join(not_selected) if not_selected else 'None'],
    ]
    lines += ["---", "", "## 2. Scan Coverage", "", _markdown_table(["Item", "Value"], coverage_rows), ""]

    section_num = 3
    smart_reasons = metadata.get('smart_plan_reasons', {})
    smart_skips = metadata.get('smart_skip_reasons', {})
    if smart_reasons or smart_skips:
        decision_rows = []
        for module, reason in smart_reasons.items():
            decision_rows.append([module, "Run", reason])
        for module, reason in smart_skips.items():
            decision_rows.append([module, "Skip", reason])
        if decision_rows:
            lines += [
                "---",
                "",
                f"## {section_num}. Smart Scan Decisions",
                "",
                _markdown_table(["Module", "Decision", "Reason"], decision_rows),
                "",
            ]
            section_num += 1

    if _completed(metadata, 'basic') and tech:
        rows = [[name, source] for name, source in sorted(tech.items())]
        lines += ["---", "", f"## {section_num}. Technologies", "", _markdown_table(["Technology", "Evidence"], rows), ""]
        section_num += 1

    if _completed(metadata, 'basic') and headers:
        rows = []
        for key, value in headers.items():
            if key.startswith('_') or key == 'infra_notes':
                continue
            rows.append([key, value])
        if rows:
            lines += ["---", "", f"## {section_num}. Security Headers", "", _markdown_table(["Header", "Value"], rows), ""]
            section_num += 1

    lines += ["---", "", f"## {section_num}. Findings Overview", ""]
    section_num += 1
    overview_rows = []
    for key, value in sorted(results.items()):
        if key in {'basic', 'scan_metadata', 'detected_stack'}:
            continue
        count = _count_findings(value)
        if count:
            overview_rows.append([key, count])
    if overview_rows:
        lines += [_markdown_table(["Section", "Finding Count"], overview_rows), ""]
    else:
        lines += ["No high-signal findings were recorded in the modules executed for this scan.", ""]

    vulnerabilities = results.get('vulnerabilities', {})
    vuln_items = _real_vulnerability_items(vulnerabilities)
    if _completed(metadata, 'vulnerabilities') and vuln_items:
        lines += ["---", "", f"## {section_num}. Vulnerability Details", ""]
        section_num += 1
        for finding_type, findings in vuln_items.items():
            lines += [f"### {finding_type}", ""]
            for item in findings[:10]:
                if isinstance(item, dict):
                    endpoint = item.get('endpoint', item.get('path', item.get('url', 'N/A')))
                    status = item.get('status', 'N/A')
                    preview = str(item.get('preview', item.get('response', item.get('type', ''))))[:300]
                    lines += [
                        f"- Endpoint: `{endpoint}`",
                        f"  Status: `{status}`",
                        f"  Evidence: {preview or 'N/A'}",
                    ]
                else:
                    lines.append(f"- {item}")
            lines.append("")

    lines += [
        "---",
        "",
        f"## {section_num}. Notes",
        "",
        "- Raw JSON evidence is saved alongside this report.",
        "- If a redacted export was requested, use it for sharing outside the authorized testing team.",
    ]
    return "\n".join(lines) + "\n"


def _pdf_escape(text):
    text = text.encode("latin-1", "replace").decode("latin-1")
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def write_simple_pdf(text, output_file):
    objects = []

    def add_object(content):
        objects.append(content)
        return len(objects)

    def clean_inline(value):
        value = re.sub(r'`([^`]*)`', r'\1', value)
        value = value.replace("**", "").replace("*", "")
        return value.strip()

    render_items = []
    table_header_seen = False
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if not line:
            render_items.append({"kind": "space"})
            table_header_seen = False
            continue
        if line == "---":
            render_items.append({"kind": "rule"})
            table_header_seen = False
            continue
        if line.startswith("# "):
            render_items.append({"kind": "title", "text": clean_inline(line[2:])})
            table_header_seen = False
            continue
        if line.startswith("## "):
            render_items.append({"kind": "section", "text": clean_inline(line[3:])})
            table_header_seen = False
            continue
        if line.startswith("### "):
            render_items.append({"kind": "subsection", "text": clean_inline(line[4:])})
            table_header_seen = False
            continue
        if line.startswith("|"):
            cells = [clean_inline(cell) for cell in line.strip("|").split("|")]
            if all(set(cell) <= {"-"} for cell in cells):
                continue
            text_line = "  |  ".join(cells)
            kind = "table_header" if not table_header_seen else "table_row"
            table_header_seen = True
            render_items.append({"kind": kind, "text": text_line})
            continue
        if line.startswith("- "):
            render_items.append({"kind": "bullet", "text": clean_inline(line[2:])})
            table_header_seen = False
            continue
        render_items.append({"kind": "body", "text": clean_inline(line)})
        table_header_seen = False

    pages = []
    current = []
    y = 760

    def item_height(kind):
        return {
            "title": 38,
            "section": 30,
            "subsection": 24,
            "table_header": 18,
            "table_row": 16,
            "bullet": 15,
            "rule": 18,
            "space": 10,
        }.get(kind, 15)

    for item in render_items:
        needed = item_height(item["kind"])
        if y - needed < 50:
            pages.append(current)
            current = []
            y = 760
        current.append(item)
        y -= needed
    if current or not pages:
        pages.append(current)

    page_refs = []
    for page in pages:
        stream_lines = []
        y = 760

        def emit(text_value, font="/F1", size=10, x=50, leading=13):
            nonlocal y
            for wrapped in wrap(text_value, width=max(32, int((560 - x) / (size * 0.52)))) or [""]:
                stream_lines.append("BT")
                stream_lines.append(f"{font} {size} Tf")
                stream_lines.append(f"{x} {y} Td")
                stream_lines.append(f"({_pdf_escape(wrapped)}) Tj")
                stream_lines.append("ET")
                y -= leading

        for item in page:
            kind = item["kind"]
            if kind == "space":
                y -= 7
            elif kind == "rule":
                emit("-" * 88, "/F1", 8, 50, 12)
            elif kind == "title":
                emit(item["text"], "/F2", 18, 50, 24)
                emit("=" * 70, "/F1", 8, 50, 14)
            elif kind == "section":
                y -= 4
                emit(item["text"], "/F2", 14, 50, 19)
            elif kind == "subsection":
                emit(item["text"], "/F2", 11, 58, 16)
            elif kind == "table_header":
                emit(item["text"], "/F2", 9, 58, 14)
            elif kind == "table_row":
                emit(item["text"], "/F1", 9, 58, 13)
            elif kind == "bullet":
                emit("- " + item["text"], "/F1", 10, 65, 14)
            else:
                emit(item["text"], "/F1", 10, 50, 14)

        stream = "\n".join(stream_lines).encode("latin-1", "replace")
        content_ref = add_object(
            f"<< /Length {len(stream)} >>\nstream\n".encode("latin-1") + stream + b"\nendstream"
        )
        page_refs.append((content_ref, None))

    font_ref = add_object(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    bold_font_ref = add_object(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")
    pages_ref = len(objects) + len(page_refs) + 1

    fixed_page_refs = []
    for content_ref, _ in page_refs:
        page_ref = add_object(
            f"<< /Type /Page /Parent {pages_ref} 0 R /MediaBox [0 0 612 792] "
            f"/Resources << /Font << /F1 {font_ref} 0 R /F2 {bold_font_ref} 0 R >> >> "
            f"/Contents {content_ref} 0 R >>"
        )
        fixed_page_refs.append(page_ref)

    kids = " ".join(f"{ref} 0 R" for ref in fixed_page_refs)
    pages_ref_actual = add_object(f"<< /Type /Pages /Kids [{kids}] /Count {len(fixed_page_refs)} >>")
    catalog_ref = add_object(f"<< /Type /Catalog /Pages {pages_ref_actual} 0 R >>")

    pdf = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for idx, obj in enumerate(objects, start=1):
        offsets.append(len(pdf))
        pdf.extend(f"{idx} 0 obj\n".encode("utf-8"))
        if isinstance(obj, str):
            obj = obj.encode("utf-8")
        pdf.extend(obj)
        pdf.extend(b"\nendobj\n")
    xref_pos = len(pdf)
    pdf.extend(f"xref\n0 {len(objects) + 1}\n".encode("utf-8"))
    pdf.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        pdf.extend(f"{offset:010d} 00000 n \n".encode("utf-8"))
    pdf.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root {catalog_ref} 0 R >>\n"
        f"startxref\n{xref_pos}\n%%EOF\n".encode("utf-8")
    )
    output_file.write_bytes(pdf)


def save_scan_results(results, domain, redact_report=False, console=None):
    project_root = Path(__file__).resolve().parents[2]
    output_dir = project_root / 'results'
    output_dir.mkdir(exist_ok=True)

    sanitized_domain = domain.replace(':', '_').replace('/', '_')
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    scan_dir = output_dir / f"{timestamp}-{_safe_filename(sanitized_domain)}"
    scan_dir.mkdir(exist_ok=True)
    output_file = scan_dir / "raw_report.json"

    with output_file.open('w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, default=str, ensure_ascii=False)

    markdown_file = scan_dir / "security_report.md"
    markdown = generate_markdown_report(results, domain)
    markdown_file.write_text(markdown, encoding='utf-8')

    pdf_file = scan_dir / "security_report.pdf"
    write_simple_pdf(markdown, pdf_file)

    if console:
        console.print(f"\n[bold green]✓ Report folder: [/bold green]{scan_dir}")
        console.print(f"[bold green]✓ Raw JSON: [/bold green]{output_file}")
        console.print(f"[bold green]✓ Markdown: [/bold green]{markdown_file}")
        console.print(f"[bold green]✓ PDF: [/bold green]{pdf_file}")

    if redact_report:
        redacted_file = scan_dir / "redacted_report.json"
        redacted = redact_results(results)
        redacted.setdefault("scan_metadata", {})["redacted_export"] = True
        with redacted_file.open('w', encoding='utf-8') as f:
            json.dump(redacted, f, indent=2, default=str, ensure_ascii=False)
        if console:
            console.print(f"[bold green]✓ Redacted JSON: [/bold green]{redacted_file}")

    return str(output_file)
