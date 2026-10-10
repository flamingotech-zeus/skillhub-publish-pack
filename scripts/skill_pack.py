#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
公司技能上架打包器 —— 把本地技能目录整理成可上传 SkillHub 的合规压缩包。

用法：
    python skill_pack.py "C:/Users/book/.workbuddy/skills/local-wanghong-audit"
    python skill_pack.py <技能目录> --slug my-skill --display "我的技能" --version 1.0.0

做四件事：
  1. 敏感信息扫描   —— 揪出真实 IP / 凭据 / 内部路径 / 企业域名（上架前必须过这一关）
  2. 元数据合规校验 —— 补齐 SkillHub 要求的 slug / displayName / version / tags / license
  3. 结构校验       —— 检查 SKILL.md 与目录规范、文件数与体积限制
  4. 打包           —— 输出上架版 SKILL.md 与 .zip（含 SHA256）
"""

import argparse
import hashlib
import os
import re
import shutil
import sys
import tempfile
import zipfile
from datetime import datetime

# ---------------- 平台限额（SkillHub 官方口径） ----------------
MAX_FILES = 300          # 官方口径：腾讯云《Skills 文件规范》ZIP 内文件总数 ≤300（错误码 450034）
MAX_DESC = 1024          # 官方口径：description 1～1024 字符，超出会被平台截断
MAX_BYTES = 10 * 1024 * 1024
# 官方硬校验：包内任意位置不允许二进制文件，命中即拒（错误码 450033）
# 依据：腾讯云《Skills 文件规范》2026-07-20 更新版
BINARY_EXT = {
    # 可执行文件
    ".exe", ".dll", ".so", ".dylib", ".bin", ".msi", ".com", ".bat", ".cmd",
    # 图片 / 媒体
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".ico",
    ".mp4", ".mov", ".avi", ".mp3", ".wav", ".ttf", ".woff", ".woff2",
    # 压缩 / 归档
    ".zip", ".tar", ".gz", ".rar", ".7z", ".bz2", ".xz",
    # 办公 / 其他二进制
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".pyc", ".pyo", ".pyd", ".class", ".jar", ".db", ".sqlite",
}

# ---------------- 敏感信息规则 ----------------
# 每条：(类型, 正则, 风险等级, 说明)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# 允许出现的"安全"IP（回环、通配、文档示例）
SAFE_IPS = {"127.0.0.1", "0.0.0.0", "255.255.255.255", "192.168.1.1", "10.0.0.1"}

CRED_PATTERNS = [
    ("疑似真实密钥", re.compile(r"\b(sk-[A-Za-z0-9]{16,}|skh_[A-Za-z0-9]{10,}|sk-ent-[A-Za-z0-9]{6,}|AKID[A-Za-z0-9]{10,})\b"), "高"),
    ("疑似密码赋值", re.compile(r"(密码|口令|password|passwd|pwd)\s*[:=：]\s*[\"']?([^\s\"',，。]{4,})", re.I), "高"),
    ("疑似 Token", re.compile(r"(token|secret[_-]?key|access[_-]?key)\s*[:=：]\s*[\"']([A-Za-z0-9_\-]{12,})[\"']", re.I), "高"),
    ("企业/个人域名", re.compile(r"\b(?:[a-z0-9-]+\.)+(?:com|cn|cc|net|org)\b", re.I), "中"),
    ("手机号", re.compile(r"\b1[3-9]\d{9}\b"), "中"),
    ("Windows 绝对路径", re.compile(r"[A-Za-z]:\\\\?(?:Users|www|项目|跨境电商|官网)[^\s\)\]]*"), "中"),
    ("订单/流水号", re.compile(r"\b(?:ORDER|SN|IMEI)[-_]?\d{8,}\b"), "低"),
]

# 可安全出现的通用示例值（命中后不算风险）
WHITELIST_VALUES = {
    "你的密钥", "xxx", "your_password", "...", "待填", "待确认", "同上", "略",
    "示例", "password", "123456", "******", "sk-api-你的密钥",
}

# Windows 绝对路径中，含用户名的需要关注；这些目录名属通用词，忽略
PATH_OK_SEGMENTS = ("Users", "www", "项目", "跨境电商", "官网")


def read_text(path):
    """尽量稳健地读文本"""
    for enc in ("utf-8", "utf-8-sig", "gbk", "latin-1"):
        try:
            with open(path, "r", encoding=enc) as f:
                return f.read()
        except (UnicodeDecodeError, LookupError):
            continue
    return ""


def parse_frontmatter(text):
    """解析 SKILL.md 的 YAML frontmatter（只做浅解析，够用）"""
    if not text.startswith("---"):
        return {}, text
    end = text.find("\n---", 3)
    if end < 0:
        return {}, text
    raw = text[3:end].strip("\n")
    body = text[end + 4:]
    meta = {}
    key = None
    for line in raw.split("\n"):
        if not line.strip():
            continue
        if re.match(r"^\s+\S", line) and key:      # 缩进行：可能是嵌套映射，也可能是续行
            stripped = line.strip()
            sub = re.match(r"^([A-Za-z_][\w-]*)\s*:\s*(.*)$", stripped)
            if isinstance(meta.get(key), dict) and sub:
                meta[key][sub.group(1)] = sub.group(2).strip().strip('"').strip("'")
            elif isinstance(meta.get(key), dict):
                pass                                # 嵌套映射内的非 k:v 行，忽略
            else:
                meta[key] = ((meta.get(key) or "") + " " + stripped).strip()
            continue
        m = re.match(r"^([A-Za-z_][\w-]*)\s*:\s*(.*)$", line)
        if m:
            key = m.group(1)
            val = m.group(2).strip().strip('"').strip("'")
            # 冒号后为空 → 可能是嵌套映射（如 pricing:），先占位，收尾时无子项则回退为空串
            meta[key] = {} if val == "" else val
    for k, v in list(meta.items()):
        if isinstance(v, dict) and not v:
            meta[k] = ""
    return meta, body


def scan_sensitive(root):
    """扫描敏感信息，返回 [(等级, 类型, 相对路径, 行号, 片段)]"""
    hits = []
    secret_like = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in (".git", "__pycache__", "_bm")]
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root).replace("\\", "/")
            if fn.endswith((".zip", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".lock")):
                continue
            if os.path.getsize(full) > 2 * 1024 * 1024:
                continue
            text = read_text(full)
            if not text:
                continue

            for lineno, line in enumerate(text.split("\n"), 1):
                if not line.strip() or len(line) > 800:
                    continue

                # 公网 IP
                for ip in IP_RE.findall(line):
                    if ip in SAFE_IPS:
                        continue
                    parts = ip.split(".")
                    if len(parts) != 4:
                        continue
                    try:
                        a, b = int(parts[0]), int(parts[1])
                    except ValueError:
                        continue
                    # 跳过内网与保留段
                    if a in (10, 127, 0) or (a == 192 and b == 168) or (a == 172 and 16 <= b <= 31) or a >= 224:
                        continue
                    hits.append(("高", "公网 IP", rel, lineno, ip))

                # 凭据类
                for label, rx, level in CRED_PATTERNS:
                    for m in rx.finditer(line):
                        frag = m.group(0)
                        val = m.group(m.lastindex) if m.lastindex else frag
                        if val in WHITELIST_VALUES:
                            continue
                        if label == "企业/个人域名":
                            # 域名只作提示，且过滤常见地址与技术标准命名空间
                            if any(k in val.lower() for k in (
                                    "github.com", "example.com", "qq.com", "163.com",
                                    "baidu.com", "google.com", "w3.org", "schema.org",
                                    "127.0.0.1", "openxmlformats.org", "python.org",
                                    "pypi.org", "microsoft.com", "office.com",
                                    # 平台官方域名：Pay Skill 改造指南要求 SKILL.md 写明
                                    # https://skillhub.cn/install/skillhub.md（属平台自身，非企业域名）
                                    "skillhub.cn", "weixin.qq.com", "pay.weixin.qq.com",
                                    "tencent.com", "tencent-cloud.com")):
                                continue
                            hits.append(("中", "域名/来源标识", rel, lineno, val))
                            continue
                        if label == "Windows 绝对路径":
                            if os.sep not in frag and "/" not in frag:
                                continue
                            hits.append(("中", "本机绝对路径", rel, lineno, frag[:60]))
                            continue
                        hits.append((level, label, rel, lineno, frag[:60]))
                        secret_like.append((rel, lineno, frag[:60]))
    return hits


def check_meta(meta, root):
    """校验 SkillHub 必需元数据，返回 (问题列表, 建议补全字典)"""
    problems, suggest = [], {}

    slug = meta.get("slug") or meta.get("name", "")
    if not slug:
        problems.append("缺少 slug（全网唯一标识符）")
    else:
        s = re.sub(r"[^a-z0-9-]", "-", slug.lower()).strip("-")
        s = re.sub(r"-{2,}", "-", s)
        if not s:
            s = os.path.basename(root).lower()
            s = re.sub(r"[^a-z0-9-]", "-", s)
        suggest["slug"] = s
        if not re.fullmatch(r"[a-z0-9-]+", slug):
            problems.append("slug 含非法字符（只允许小写字母、数字、连字符）：%s" % slug)
        if not (2 <= len(slug) <= 128):
            problems.append("slug 长度 %d 超出官方区间 2~128：%s" % (len(slug), slug))
        if os.path.basename(root).lower() == slug and "-" not in slug:
            problems.append("slug 建议带公司前缀（如 flamingotech-xxx / takelemon-xxx），"
                            "且 slug 全网唯一、提交后不可修改")

    if not meta.get("displayName"):
        suggest["displayName"] = meta.get("name", os.path.basename(root))
        problems.append("建议补 displayName（商店里显示的正式名称）")

    if not meta.get("version"):
        suggest["version"] = "1.0.0"
        problems.append("缺少 version，建议从 1.0.0 起")

    if not meta.get("license"):
        suggest["license"] = "Internal"
        problems.append("缺少 license（企业内部分发建议写 Internal）")

    if not meta.get("tags"):
        suggest["tags"] = ""
        problems.append("建议补 tags（检索关键词，影响被搜到的概率）")

    desc = meta.get("description", "")
    if not desc:
        problems.append("缺少 description —— 这是触发技能的唯一依据，必须写")
    elif len(desc) < 40:
        problems.append("description 偏短（%d 字），建议写清「做什么 + 什么时候用」" % len(desc))
    elif len(desc) > MAX_DESC:
        problems.append("description 超长（%d 字），官方上限 %d 字符，超出会被截断" % (len(desc), MAX_DESC))

    # Pay Skill 定价字段：官方要求 pricing.model / pricing.amount_fen
    if "pricing" in meta:
        pr = meta["pricing"]
        if not isinstance(pr, dict):
            problems.append("pricing 不是合法映射（当前值：%s）—— 必须写成 "
                            "`pricing: {model: per_call, amount_fen: 10}` 或两行缩进块，"
                            "否则平台解析定价失败" % pr)
        else:
            model = str(pr.get("model", ""))
            if model not in ("per_call", "per_use", "free"):
                problems.append("pricing.model 值异常：%s（官方示例 per_call）" % (model or "缺失"))
            fen = str(pr.get("amount_fen", ""))
            if not fen.isdigit() or int(fen) <= 0:
                problems.append("pricing.amount_fen 必须为正整数（单位：分）：当前 %s" % (fen or "缺失"))
            elif model == "per_call":
                print("  [√] 定价字段：%s 分 / 次（%.2f 元），与发布页需一致" % (fen, int(fen) / 100.0))

    return problems, suggest


def _fmt_val(v):
    """写出 frontmatter 值：字典用 YAML 流式写法（单行、合法），其余原样。
    注意：绝不能用 "%s" % dict —— 会生成非法 YAML，平台解析 pricing 会失败。"""
    if isinstance(v, dict):
        return "{" + ", ".join("%s: %s" % (k, _fmt_val(x)) for k, x in v.items()) + "}"
    return str(v)


def build_pack_md(meta, body, suggest):
    """生成上架版 SKILL.md：补齐 SkillHub 必需字段，保留本机兼容字段"""
    out = dict(meta)
    for k in ("slug", "displayName", "version", "license", "tags"):
        if not out.get(k) and suggest.get(k):
            out[k] = suggest[k]

    order = ["name", "slug", "displayName", "description", "version", "tags",
             "license", "agent_created", "allowed-tools", "disable"]
    lines = ["---"]
    for k in order:
        if k in out and out[k]:
            lines.append("%s: %s" % (k, _fmt_val(out[k])))
    for k, v in out.items():
        if k not in order and v:
            lines.append("%s: %s" % (k, _fmt_val(v)))
    lines.append("---")
    return "\n".join(lines) + "\n" + body


def pack(root, out_dir, suggest, meta, md_override=None):
    """打包为 zip，返回 (zip路径, 文件数, 字节数, sha256)

    做法：先把技能复制到临时目录，用 md_override 覆盖 SKILL.md，再打包，
    保证 zip 内只含该技能自身的文件，且元数据是补齐后的上架版。
    """
    os.makedirs(out_dir, exist_ok=True)
    slug = suggest.get("slug") or os.path.basename(root)
    ver = meta.get("version") or suggest.get("version") or "1.0.0"
    zip_path = os.path.join(out_dir, "%s-v%s.zip" % (slug, ver))

    skip_dirs = {".git", "__pycache__", ".idea", ".vscode", "_bm"}

    tmp_root = tempfile.mkdtemp(prefix="skillpack_")
    work = os.path.join(tmp_root, slug)
    try:
        shutil.copytree(root, work, dirs_exist_ok=True,
                        ignore=shutil.ignore_patterns(*skip_dirs))
        if md_override:
            with open(os.path.join(work, "SKILL.md"), "w",
                      encoding="utf-8", newline="\n") as f:
                f.write(md_override)

        count = 0
        total = 0
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
            for dirpath, dirnames, filenames in os.walk(work):
                dirnames[:] = [d for d in dirnames if d not in skip_dirs]
                for fn in sorted(filenames):
                    if fn.endswith((".zip", ".bak", ".tmp", ".pyc")) or fn.startswith("."):
                        continue
                    full = os.path.join(dirpath, fn)
                    rel = os.path.relpath(full, work).replace("\\", "/")
                    z.write(full, rel)
                    count += 1
                    total += os.path.getsize(full)
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)

    h = hashlib.sha256()
    with open(zip_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return zip_path, count, total, h.hexdigest()


def main():
    ap = argparse.ArgumentParser(description="公司技能上架打包器")
    ap.add_argument("skill_dir", help="本地技能目录")
    ap.add_argument("--out", default=None, help="zip 输出目录")
    ap.add_argument("--slug")
    ap.add_argument("--display")
    ap.add_argument("--version")
    ap.add_argument("--tags")
    ap.add_argument("--license", dest="lic")
    ap.add_argument("--allow-sensitive", action="store_true",
                    help="忽略敏感信息阻断，仍生成压缩包（不建议）")
    ap.add_argument("--allow-binary", action="store_true",
                    help="忽略二进制文件阻断，仍生成压缩包（仅限自用，不要上传）")
    args = ap.parse_args()

    root = os.path.abspath(args.skill_dir)
    skill_md = os.path.join(root, "SKILL.md")
    W = 68
    print("=" * W)
    print("  公司技能上架打包器")
    print("=" * W)
    print("  技能目录：%s" % root)
    print("  检查时间：%s" % datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print()

    if not os.path.isfile(skill_md):
        print("  [×] 致命：目录内没有 SKILL.md，无法上架。")
        sys.exit(1)

    text = read_text(skill_md)
    meta, body = parse_frontmatter(text)

    # ---- 1. 敏感信息 ----
    print("-" * W)
    print("  [1/4] 敏感信息扫描")
    print("-" * W)
    hits = scan_sensitive(root)
    if not hits:
        print("  [√] 未发现敏感信息，可以安全上架。")
    else:
        order = {"高": 0, "中": 1, "低": 2}
        hits.sort(key=lambda x: (order[x[0]], x[2], x[3]))
        high = [h for h in hits if h[0] == "高"]
        mid = [h for h in hits if h[0] == "中"]
        low = [h for h in hits if h[0] == "低"]
        print("  [!] 命中 %d 处（高 %d / 中 %d / 低 %d）" % (len(hits), len(high), len(mid), len(low)))
        print()
        shown = [h for h in hits if h[0] in ("高", "中")][:25]
        for lv, kind, rel, ln, frag in shown:
            print("   %s %-14s %s:%d" % (lv, kind, rel, ln))
            print("       %s" % frag)
        if len([h for h in hits if h[0] in ("高", "中")]) > 25:
            print("   ... 其余 %d 处略" % (len([h for h in hits if h[0] in ("高", "中")]) - 25))
        print()
        if high:
            print("  [×] 存在【高】风险项：公开发布等于把这些信息交给所有人。")
            print("      处理办法：把真实值替换为占位符（<服务器IP> / <密码> / <你的域名>），")
            print("      真实值另存到本地不发布的配置文件里。")
    print()

    # ---- 2. 元数据 ----
    print("-" * W)
    print("  [2/4] 元数据合规校验")
    print("-" * W)
    if args.slug:
        meta["slug"] = args.slug
    if args.display:
        meta["displayName"] = args.display
    if args.version:
        meta["version"] = args.version
    if args.tags:
        meta["tags"] = args.tags
    if args.lic:
        meta["license"] = args.lic

    problems, suggest = check_meta(meta, root)
    if problems:
        for p in problems:
            print("  [!] %s" % p)
    else:
        print("  [√] 元数据完整。")
    if suggest:
        print()
        print("  将自动补全：")
        for k, v in suggest.items():
            if v:
                print("    %s = %s" % (k, v))
    for k, v in suggest.items():
        if v and not meta.get(k):
            meta[k] = v
    print()

    # ---- 3. 结构 ----
    print("-" * W)
    print("  [3/4] 结构与限额校验")
    print("-" * W)
    nfiles, nbytes = 0, 0
    binaries = []
    for dp, dn, fs in os.walk(root):
        dn[:] = [d for d in dn if d not in (".git", "__pycache__")]
        for f in fs:
            full = os.path.join(dp, f)
            nfiles += 1
            nbytes += os.path.getsize(full)
            if os.path.splitext(f)[1].lower() in BINARY_EXT:
                binaries.append(os.path.relpath(full, root).replace("\\", "/"))
    print("  文件数：%d / %d  %s" % (nfiles, MAX_FILES, "√" if nfiles <= MAX_FILES else "× 超限"))
    print("  体积：%.2f MB / 10.00 MB  %s" % (nbytes / 1048576.0,
                                        "√" if nbytes <= MAX_BYTES else "× 超限"))
    print("  SKILL.md：√ 存在")
    # 官方硬校验：包内任意位置不允许二进制文件（上传报 450033）
    if binaries:
        print("  二进制文件：× 发现 %d 个 —— 上传将报 450033" % len(binaries))
        for b in binaries[:10]:
            print("      %s" % b)
        if len(binaries) > 10:
            print("      …… 另有 %d 个" % (len(binaries) - 10))
    else:
        print("  二进制文件：√ 无（纯文本，符合硬校验）")
    print()

    # ---- 4. 打包 ----
    print("-" * W)
    print("  [4/4] 打包")
    print("-" * W)

    if binaries and not args.allow_binary:
        print("  [!] 技能包含二进制文件，官方硬校验会拒绝（错误码 450033）。")
        print("      图片/图标等资源请改为文本格式，或从技能包中移除。")
        print("      确需打包时加 --allow-binary 强制继续（仅限自用，不要上传）。")
        print()
        return

    if any(h[0] == "高" for h in hits) and not args.allow_sensitive:
        print("  [!] 因存在【高】风险项，已中止打包。")
        print("      确认这些信息可公开后，加 --allow-sensitive 强制打包。")
        print()
        return

    out_dir = args.out or os.path.join(os.path.dirname(root), "_publish")
    os.makedirs(out_dir, exist_ok=True)

    pack_md = build_pack_md(meta, body, suggest)
    slug = suggest.get("slug") or os.path.basename(root)
    ver = meta.get("version") or "1.0.0"
    md_out = os.path.join(out_dir, "%s-v%s.SKILL.md" % (slug, ver))
    with open(md_out, "w", encoding="utf-8", newline="\n") as f:
        f.write(pack_md)
    print("  上架版元数据：%s" % md_out)

    zip_path, cnt, sz, sha = pack(root, out_dir, suggest, meta, md_override=pack_md)

    print("  压缩包：%s" % zip_path)
    print("  内含 %d 个文件，%.2f MB" % (cnt, sz / 1048576.0))
    print("  SHA256：%s" % sha)
    print()
    print("=" * W)
    print("  下一步")
    print("=" * W)
    print("  1) 本地预检（不发请求）：")
    print("     skillhub publish \"%s\" --dry-run" % zip_path)
    print("  2) 登录（实名认证后在 skillhub.cn 生成 Token）：")
    print("     skillhub login --key skh_你的Token")
    print("  3) 正式发布：")
    print("     skillhub publish \"%s\" --version %s --changelog \"首个版本\""
          % (zip_path, ver))
    print()


if __name__ == "__main__":
    main()
