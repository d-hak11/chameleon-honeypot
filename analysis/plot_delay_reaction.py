#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import statistics
import sys
from typing import Dict, List, Optional

import yaml

# Fixed class order and colour across all charts (colourblind-safe).
CLASS_ORDER = ["broad_scanning", "active_backend_testing", "indexing"]
CLASS_COLOR = {
    "broad_scanning": "#0072B2",
    "active_backend_testing": "#D55E00",
    "indexing": "#009E73",
}
CLASS_LABEL = {
    "broad_scanning": "broad scanning",
    "active_backend_testing": "active backend testing",
    "indexing": "indexing",
}

INK = "#1b1f24"
MUTED = "#6b7280"
GRID = "#e5e7eb"
SURFACE = "#ffffff"


def parse_pipe_floats(s: Optional[str]) -> List[float]:
    if not s:
        return []
    out = []
    for part in s.split("|"):
        part = part.strip()
        if part and part.lower() != "none":
            try:
                out.append(float(part))
            except ValueError:
                pass
    return out


def load_rows(path: str) -> List[Dict[str, str]]:
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def load_profile_order(path: str) -> List[tuple]:
    """Profiles ordered by induced delay_ms."""
    with open(path, "r", encoding="utf-8") as f:
        profiles = yaml.safe_load(f)["profiles"]
    return sorted(((name, p["delay_ms"]) for name, p in profiles.items()),
                  key=lambda t: t[1])


def svg_header(width: int, height: int) -> str:
    return (f'<svg viewBox="0 0 {width} {height}" width="100%" '
           f'style="max-width:{width}px;font-family:ui-sans-serif,system-ui,'
           f'sans-serif" role="img">')


def legend(x: int, y: int, classes: List[str]) -> str:
    parts = [f'<g transform="translate({x},{y})">']
    for i, cls in enumerate(classes):
        cy = i * 20
        parts.append(f'<rect x="0" y="{cy}" width="12" height="12" rx="2" '
                     f'fill="{CLASS_COLOR[cls]}"/>')
        parts.append(f'<text x="18" y="{cy + 10}" font-size="12" '
                     f'fill="{INK}">{CLASS_LABEL[cls]}</text>')
    parts.append("</g>")
    return "".join(parts)


def chart_abandonment_vs_delay(rows: List[Dict[str, str]],
                              profile_order: List[tuple]) -> str:
    # (class, profile) -> [abandoned_count_sum, known_outcome_count_sum]
    agg: Dict[tuple, List[int]] = {}
    for row in rows:
        cls = row.get("behaviour_class", "")
        profile = row.get("network_profile", "")
        if cls not in CLASS_ORDER:
            continue
        completed = parse_pipe_floats(row.get("probe_delay_ms_values"))
        abandoned = parse_pipe_floats(row.get("abandon_after_ms_values"))
        known = len(completed) + len(abandoned)
        if known == 0:
            continue
        key = (cls, profile)
        agg.setdefault(key, [0, 0])
        agg[key][0] += len(abandoned)
        agg[key][1] += known

    width, height = 640, 380
    margin = {"top": 30, "right": 20, "bottom": 70, "left": 50}
    plot_w = width - margin["left"] - margin["right"]
    plot_h = height - margin["top"] - margin["bottom"]

    rates = []
    for profile, _ in profile_order:
        for cls in CLASS_ORDER:
            ab, known = agg.get((cls, profile), [0, 0])
            rates.append(ab / known if known else 0.0)
    y_max = max(0.1, max(rates) * 1.2) if rates else 0.1

    n_groups = len(profile_order)
    group_w = plot_w / n_groups
    bar_w = group_w / (len(CLASS_ORDER) + 1)

    svg = [svg_header(width, height)]
    svg.append(f'<rect width="{width}" height="{height}" fill="{SURFACE}"/>')
    svg.append(f'<text x="{margin["left"]}" y="18" font-size="14" '
               f'font-weight="600" fill="{INK}">Client abandonment rate vs. '
               f'induced delay magnitude</text>')

    # y gridlines + axis labels (0%, 25%, ... of y_max, rounded to 5 ticks)
    n_ticks = 5
    for i in range(n_ticks + 1):
        frac = i / n_ticks
        y = margin["top"] + plot_h * (1 - frac)
        val = frac * y_max * 100
        svg.append(f'<line x1="{margin["left"]}" y1="{y:.1f}" '
                   f'x2="{width - margin["right"]}" y2="{y:.1f}" '
                   f'stroke="{GRID}" stroke-width="1"/>')
        svg.append(f'<text x="{margin["left"] - 8}" y="{y + 4:.1f}" '
                   f'font-size="10" fill="{MUTED}" text-anchor="end">'
                   f'{val:.0f}%</text>')

    for gi, (profile, delay_ms) in enumerate(profile_order):
        gx = margin["left"] + gi * group_w
        for ci, cls in enumerate(CLASS_ORDER):
            ab, known = agg.get((cls, profile), [0, 0])
            rate = ab / known if known else 0.0
            bar_h = plot_h * (rate / y_max) if y_max else 0
            bx = gx + bar_w * (ci + 0.5)
            by = margin["top"] + plot_h - bar_h
            tooltip = (f"{CLASS_LABEL[cls]}, {profile} ({delay_ms}ms delay): "
                      f"{rate*100:.1f}% abandoned ({ab}/{known} probed "
                      f"requests with a known outcome)")
            svg.append(f'<rect x="{bx:.1f}" y="{by:.1f}" width="{bar_w*0.85:.1f}" '
                       f'height="{max(bar_h,0):.1f}" rx="3" '
                       f'fill="{CLASS_COLOR[cls]}"><title>{tooltip}</title></rect>')
        svg.append(f'<text x="{gx + group_w/2:.1f}" '
                   f'y="{margin["top"] + plot_h + 20}" font-size="12" '
                   f'fill="{INK}" text-anchor="middle">{profile}</text>')
        svg.append(f'<text x="{gx + group_w/2:.1f}" '
                   f'y="{margin["top"] + plot_h + 36}" font-size="10" '
                   f'fill="{MUTED}" text-anchor="middle">({delay_ms}ms)</text>')

    svg.append(f'<line x1="{margin["left"]}" y1="{margin["top"]+plot_h}" '
               f'x2="{width-margin["right"]}" y2="{margin["top"]+plot_h}" '
               f'stroke="{INK}" stroke-width="1"/>')
    svg.append(legend(width - 190, margin["top"], CLASS_ORDER))
    svg.append("</svg>")
    return "".join(svg)


def _box_plot_svg(values: Dict[str, List[float]], title: str, unit: str,
                  empty_label: str) -> str:
    width, height = 640, 340
    margin = {"top": 30, "right": 20, "bottom": 50, "left": 60}
    plot_w = width - margin["left"] - margin["right"]
    plot_h = height - margin["top"] - margin["bottom"]

    all_vals = [v for vs in values.values() for v in vs]
    if all_vals:
        data_lo, data_hi = min(all_vals), max(all_vals)
        span = (data_hi - data_lo) or abs(data_hi) or 1.0
        y_lo = min(0.0, data_lo - span * 0.1)
        y_hi = max(0.0, data_hi + span * 0.1)
    else:
        y_lo, y_hi = 0.0, 100.0
    y_span = y_hi - y_lo

    svg = [svg_header(width, height)]
    svg.append(f'<rect width="{width}" height="{height}" fill="{SURFACE}"/>')
    svg.append(f'<text x="{margin["left"]}" y="18" font-size="14" '
               f'font-weight="600" fill="{INK}">{title}</text>')

    def y_of(v: float) -> float:
        return margin["top"] + plot_h * (1 - (v - y_lo) / y_span) if y_span else margin["top"] + plot_h

    n_ticks = 5
    for i in range(n_ticks + 1):
        frac = i / n_ticks
        y = margin["top"] + plot_h * (1 - frac)
        val = y_lo + frac * y_span
        svg.append(f'<line x1="{margin["left"]}" y1="{y:.1f}" '
                   f'x2="{width - margin["right"]}" y2="{y:.1f}" '
                   f'stroke="{GRID}" stroke-width="1"/>')
        svg.append(f'<text x="{margin["left"] - 8}" y="{y + 4:.1f}" '
                   f'font-size="10" fill="{MUTED}" text-anchor="end">'
                   f'{val:.0f}{unit}</text>')

    if y_lo < 0 < y_hi:
        zy = y_of(0.0)
        svg.append(f'<line x1="{margin["left"]}" y1="{zy:.1f}" '
                   f'x2="{width - margin["right"]}" y2="{zy:.1f}" '
                   f'stroke="{MUTED}" stroke-width="1.5" stroke-dasharray="4,3"/>')

    n = len(CLASS_ORDER)
    slot_w = plot_w / n
    for i, cls in enumerate(CLASS_ORDER):
        cx = margin["left"] + slot_w * (i + 0.5)
        vals = sorted(values[cls])
        color = CLASS_COLOR[cls]
        if not vals:
            svg.append(f'<text x="{cx:.1f}" '
                       f'y="{margin["top"] + plot_h/2:.1f}" font-size="11" '
                       f'fill="{MUTED}" text-anchor="middle">{empty_label}</text>')
        else:
            lo, hi = vals[0], vals[-1]
            if len(vals) >= 2:
                q1, med, q3 = statistics.quantiles(vals, n=4, method="inclusive")
            else:
                q1 = med = q3 = vals[0]

            box_w = slot_w * 0.4
            svg.append(f'<line x1="{cx:.1f}" y1="{y_of(lo):.1f}" '
                       f'x2="{cx:.1f}" y2="{y_of(hi):.1f}" '
                       f'stroke="{color}" stroke-width="2"/>')
            svg.append(f'<rect x="{cx-box_w/2:.1f}" y="{y_of(q3):.1f}" '
                       f'width="{box_w:.1f}" height="{max(y_of(q1)-y_of(q3),1):.1f}" '
                       f'rx="3" fill="{color}" fill-opacity="0.35" '
                       f'stroke="{color}" stroke-width="1.5">'
                       f'<title>{CLASS_LABEL[cls]}: n={len(vals)}, '
                       f'median={med:.0f}{unit}, IQR=[{q1:.0f}, {q3:.0f}]{unit}, '
                       f'range=[{lo:.0f}, {hi:.0f}]{unit}</title></rect>')
            svg.append(f'<line x1="{cx-box_w/2:.1f}" y1="{y_of(med):.1f}" '
                       f'x2="{cx+box_w/2:.1f}" y2="{y_of(med):.1f}" '
                       f'stroke="{color}" stroke-width="2"/>')
            svg.append(f'<text x="{cx:.1f}" y="{margin["top"]+plot_h+16}" '
                       f'font-size="10" fill="{MUTED}" text-anchor="middle">'
                       f'n={len(vals)}</text>')
        svg.append(f'<text x="{cx:.1f}" y="{margin["top"]+plot_h+34}" '
                   f'font-size="12" fill="{INK}" text-anchor="middle">'
                   f'{CLASS_LABEL[cls]}</text>')

    svg.append(f'<line x1="{margin["left"]}" y1="{margin["top"]+plot_h}" '
               f'x2="{width-margin["right"]}" y2="{margin["top"]+plot_h}" '
               f'stroke="{INK}" stroke-width="1"/>')
    svg.append("</svg>")
    return "".join(svg)


def chart_abandon_after_ms_box(rows: List[Dict[str, str]]) -> str:
    values: Dict[str, List[float]] = {c: [] for c in CLASS_ORDER}
    for row in rows:
        cls = row.get("behaviour_class", "")
        if cls not in CLASS_ORDER:
            continue
        values[cls].extend(parse_pipe_floats(row.get("abandon_after_ms_values")))
    return _box_plot_svg(values, "abandon_after_ms distribution per class",
                         "ms", "no abandonments recorded")


def chart_interval_delta_box(rows: List[Dict[str, str]]) -> str:
    values: Dict[str, List[float]] = {c: [] for c in CLASS_ORDER}
    for row in rows:
        cls = row.get("behaviour_class", "")
        if cls not in CLASS_ORDER:
            continue
        v = row.get("timing_probe_interval_delta_ms")
        if v not in (None, "", "None"):
            values[cls].append(float(v))
    return _box_plot_svg(
        values, "Inter-request interval delta across the timing-probe hold",
        "ms", "no probed session with both a pre- and post-hold interval")


def chart_rate_before_after(rows: List[Dict[str, str]]) -> str:
    before: Dict[str, List[float]] = {c: [] for c in CLASS_ORDER}
    after: Dict[str, List[float]] = {c: [] for c in CLASS_ORDER}
    for row in rows:
        cls = row.get("behaviour_class", "")
        if cls not in CLASS_ORDER:
            continue
        pre = row.get("pre_timing_probe_interval_mean")
        post = row.get("post_timing_probe_interval_mean")
        if pre not in (None, "", "None"):
            pre_f = float(pre)
            if pre_f > 0:
                before[cls].append(1.0 / pre_f)
        if post not in (None, "", "None"):
            post_f = float(post)
            if post_f > 0:
                after[cls].append(1.0 / post_f)

    width, height = 640, 340
    margin = {"top": 30, "right": 20, "bottom": 60, "left": 60}
    plot_w = width - margin["left"] - margin["right"]
    plot_h = height - margin["top"] - margin["bottom"]

    means = {}
    for cls in CLASS_ORDER:
        means[cls] = (
            statistics.mean(before[cls]) if before[cls] else 0.0,
            statistics.mean(after[cls]) if after[cls] else 0.0,
        )
    y_max = max((v for pair in means.values() for v in pair), default=0.0)
    y_max = max(y_max * 1.2, 0.1)

    n = len(CLASS_ORDER)
    slot_w = plot_w / n
    bar_w = slot_w * 0.3

    svg = [svg_header(width, height)]
    svg.append(f'<rect width="{width}" height="{height}" fill="{SURFACE}"/>')
    svg.append(f'<text x="{margin["left"]}" y="18" font-size="14" '
               f'font-weight="600" fill="{INK}">Request rate before vs. '
               f'after first probe hit</text>')

    n_ticks = 5
    for i in range(n_ticks + 1):
        frac = i / n_ticks
        y = margin["top"] + plot_h * (1 - frac)
        val = frac * y_max
        svg.append(f'<line x1="{margin["left"]}" y1="{y:.1f}" '
                   f'x2="{width - margin["right"]}" y2="{y:.1f}" '
                   f'stroke="{GRID}" stroke-width="1"/>')
        svg.append(f'<text x="{margin["left"] - 8}" y="{y + 4:.1f}" '
                   f'font-size="10" fill="{MUTED}" text-anchor="end">'
                   f'{val:.1f}/s</text>')

    for i, cls in enumerate(CLASS_ORDER):
        cx = margin["left"] + slot_w * (i + 0.5)
        color = CLASS_COLOR[cls]
        b_mean, a_mean = means[cls]
        for label, val, opacity, dx in (("before", b_mean, 1.0, -bar_w * 0.6),
                                        ("after", a_mean, 0.5, bar_w * 0.6)):
            bx = cx + dx - bar_w / 2
            bar_h = plot_h * (val / y_max) if y_max else 0
            by = margin["top"] + plot_h - bar_h
            n_samples = len(before[cls]) if label == "before" else len(after[cls])
            svg.append(f'<rect x="{bx:.1f}" y="{by:.1f}" width="{bar_w:.1f}" '
                       f'height="{max(bar_h,0):.1f}" rx="3" fill="{color}" '
                       f'fill-opacity="{opacity}"><title>{CLASS_LABEL[cls]}, '
                       f'{label} first probe: {val:.2f} req/s (n={n_samples} '
                       f'sessions)</title></rect>')
        svg.append(f'<text x="{cx:.1f}" y="{margin["top"]+plot_h+34}" '
                   f'font-size="12" fill="{INK}" text-anchor="middle">'
                   f'{CLASS_LABEL[cls]}</text>')

    svg.append(f'<line x1="{margin["left"]}" y1="{margin["top"]+plot_h}" '
               f'x2="{width-margin["right"]}" y2="{margin["top"]+plot_h}" '
               f'stroke="{INK}" stroke-width="1"/>')
    # before/after legend (opacity, not hue -- one swatch pair)
    lx, ly = width - 150, margin["top"]
    svg.append(f'<rect x="{lx}" y="{ly}" width="12" height="12" rx="2" '
               f'fill="{INK}" fill-opacity="1.0"/>')
    svg.append(f'<text x="{lx+18}" y="{ly+10}" font-size="12" fill="{INK}">'
               f'before probe</text>')
    svg.append(f'<rect x="{lx}" y="{ly+20}" width="12" height="12" rx="2" '
               f'fill="{INK}" fill-opacity="0.5"/>')
    svg.append(f'<text x="{lx+18}" y="{ly+30}" font-size="12" fill="{INK}">'
               f'after probe</text>')
    svg.append("</svg>")
    return "".join(svg)


PAGE_TEMPLATE = """<title>Delay-Reaction Distributions</title>
<style>
  :root {{
    color-scheme: light dark;
  }}
  body {{ background: #f8f9fb; }}
  h1 {{ font-size: 18px; margin: 0 0 4px; }}
  p.meta {{ color: #6b7280; font-size: 13px; margin: 0 0 24px; }}
  .card {{
    background: #ffffff; border: 1px solid #e5e7eb; border-radius: 10px;
    padding: 16px; margin-bottom: 20px; max-width: 680px;
  }}
  @media (prefers-color-scheme: dark) {{
    body {{ background: #0f1115; }}
    .card {{ background: #171a21; border-color: #2a2f3a; }}
    h1, p.meta {{ color: #e5e7eb; }}
  }}
</style>
<div style="padding:20px">
  <h1>Delay-reaction distributions -- Phase 8 pre-classifier check</h1>
  <p class="meta">{n_sessions} labelled sessions, {n_probed} with at least
    one probed request. Generated from {source}. No classifier has been
    trained on this data.</p>
  <div class="card">{chart1}</div>
  <div class="card">{chart2}</div>
  <div class="card">{chart3}</div>
  <div class="card">{chart4}</div>
</div>
"""


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("labelled_csv", help="output of generation/label_sessions.py")
    p.add_argument("network_profiles_yml")
    p.add_argument("--out", required=True)
    args = p.parse_args(argv)

    rows = load_rows(args.labelled_csv)
    profile_order = load_profile_order(args.network_profiles_yml)

    n_probed = sum(1 for r in rows
                  if parse_pipe_floats(r.get("probe_delay_ms_values"))
                  or parse_pipe_floats(r.get("abandon_after_ms_values")))

    html = PAGE_TEMPLATE.format(
        n_sessions=len(rows),
        n_probed=n_probed,
        source=args.labelled_csv,
        chart1=chart_abandonment_vs_delay(rows, profile_order),
        chart2=chart_abandon_after_ms_box(rows),
        chart3=chart_rate_before_after(rows),
        chart4=chart_interval_delta_box(rows),
    )
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"plot_delay_reaction: {len(rows)} sessions ({n_probed} probed) "
         f"-> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
