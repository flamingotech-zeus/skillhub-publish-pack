#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
批量体检：扫描 skills 目录下所有技能的可上架性。
输出：每个技能的高/中风险命中数 + 结论（可直发 / 需脱敏 / 无价值）。

用法：python audit_all.py [skills目录]
"""
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from skill_pack import scan_sensitive, read_text, parse_frontmatter  # noqa: E402

ROOT = sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser("~/.workbuddy/skills")

rows = []
for name in sorted(os.listdir(ROOT)):
    d = os.path.join(ROOT, name)
    md = os.path.join(d, "SKILL.md")
    if not os.path.isdir(d) or not os.path.isfile(md):
        continue
    meta, _ = parse_frontmatter(read_text(md))
    hits = scan_sensitive(d)
    c = Counter(h[0] for h in hits)
    nfiles = sum(len(fs) for _, _, fs in os.walk(d))
    size_k = sum(os.path.getsize(os.path.join(dp, f))
                 for dp, _, fs in os.walk(d) for f in fs) // 1024
    rows.append({
        "name": name,
        "selfmade": "agent_created: true" in read_text(md),
        "high": c.get("高", 0),
        "mid": c.get("中", 0),
        "files": nfiles,
        "kb": size_k,
        "highs": [h for h in hits if h[0] == "高"],
    })

W = 96
print("=" * W)
print("  技能可上架性批量体检")
print("=" * W)
print("  扫描目录：%s" % ROOT)
print()
print("  %-38s %5s %5s %6s %7s  %s" % ("技能名", "高风", "中风", "文件", "KB", "结论"))
print("  " + "-" * (W - 4))

selfmade = [r for r in rows if r["selfmade"]]
other = [r for r in rows if not r["selfmade"]]

for r in sorted(selfmade, key=lambda x: (-x["high"], -x["mid"])):
    if r["high"] > 0:
        verdict = "× 必须先脱敏"
    elif r["mid"] > 3:
        verdict = "△ 建议检查来源标识"
    else:
        verdict = "√ 可直接上架"
    print("  %-38s %5d %5d %6d %7d  %s"
          % (r["name"], r["high"], r["mid"], r["files"], r["kb"], verdict))

print()
print("  ── 以上为你自建（agent_created）技能，共 %d 个 %s ──"
      % (len(selfmade), "（只列这些，市场下载的技能不建议再转发）"))
print()

need_fix = [r for r in selfmade if r["high"] > 0]
if need_fix:
    print("=" * W)
    print("  阻断项明细（这些技能上架前必须处理）")
    print("=" * W)
    for r in need_fix:
        print()
        print("  【%s】高风险 %d 处：" % (r["name"], r["high"]))
        seen = set()
        for lv, kind, rel, ln, frag in r["highs"]:
            key = (kind, frag)
            if key in seen:
                continue
            seen.add(key)
            print("    · %s  →  %s" % (kind, frag))
            print("      %s:%d" % (rel, ln))
print()
print("=" * W)
print("  汇总：可直接上架 %d 个 / 需先脱敏 %d 个 / 建议检查 %d 个"
      % (len([r for r in selfmade if r["high"] == 0 and r["mid"] <= 3]),
         len(need_fix),
         len([r for r in selfmade if r["high"] == 0 and r["mid"] > 3])))
print("=" * W)
