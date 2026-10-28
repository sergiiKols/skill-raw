#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
skill-raw: просмотр сырого чужого скилла до установки.

Только читает файлы как текст, ничего не запускает и не ходит в сеть.
Ловит приёмы из разбора VirusTotal (октябрь 2026): блоки пустых строк, HTML-комментарии,
невидимые символы, `curl | sh`, «не говори пользователю», обращение к сканеру,
запись в память и конфиг агента, отправка секретов по адресу. Чистый результат
не означает безопасность: смысл инструкций скрипт не оценивает.

Коды выхода: 0 · 1 ошибка · 2 стоп-находки · 10 нет SKILL.md.
Код 20 не используется: скрипт ничего не меняет.
"""
import argparse
import hashlib
import json
import os
import re
import sys
from collections import Counter, OrderedDict

MAX_FILE = 2 * 1024 * 1024
MAX_FILES = 2000
AGGREGATE = {"R9.1", "R5.1", "R6"}
SEV_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
TEXT_NAMES = {"SKILL.md", "Makefile", "Dockerfile", "LICENSE"}
SCRIPT_EXT = {".py", ".js", ".mjs", ".cjs", ".ts", ".sh", ".bash", ".zsh", ".ps1", ".bat", ".rb", ".pl", ".php"}
PROSE_EXT = {".md", ".txt", ".markdown", ".rst", ""}

TAG_RANGE = range(0xE0000, 0xE0080)
BIDI = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A))
ZERO_WIDTH = {0x200B, 0x200C, 0x200D, 0x2060, 0x180E, 0x00AD, 0x2062, 0x2063, 0x2064}
VARIATION = set(range(0xFE00, 0xFE0F)) | set(range(0xE0100, 0xE01F0))

I = re.IGNORECASE
PIPE_SHELL = [
    re.compile(r"\b(curl|wget|fetch|iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n|]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b", I),
    re.compile(r"\b(ba|z)?sh\s+<\(\s*(curl|wget)", I),
    re.compile(r"\beval\b[^\n]{0,20}\b(curl|wget)\b", I),
    re.compile(r"base64\s+(-d|--decode)[^\n|]*\|\s*(ba|z)?sh\b", I),
    re.compile(r"\b(iex|invoke-expression)\b[^\n]{0,80}(downloadstring|iwr|irm|invoke-webrequest)", I),
    re.compile(r"powershell[^\n]{0,40}\s-e(nc|ncodedcommand)?\s", I),
]
HIDE_FROM_USER = [
    re.compile(r"\b(do not|don't|never|must not)\s+(tell|inform|mention|notify|alert|reveal|show|disclose)[^\n.]{0,30}\b(user|human|owner|operator)", I),
    re.compile(r"\bwithout\s+(telling|informing|notifying|alerting|mentioning)\b", I),
    re.compile(r"\bkeep\s+(this|it|that)\s+(secret|hidden|quiet|confidential)\b", I),
    re.compile(r"не\s+(сообщай|говори|показывай|уведомляй|упоминай|раскрывай)[^\n.]{0,40}пользовател", I),
    re.compile(r"(скрой|утаи)\s+(это\s+)?от\s+пользовател", I),
]
ADDRESS_SCANNER = [
    re.compile(r"\b(ignore|disregard|forget)\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|earlier)\s+(instructions|rules|prompts?)", I),
    re.compile(r"\b(mark|rate|label|classify|approve)\s+(this|it)(\s+skill)?\s+(as\s+)?(safe|benign|clean|harmless)\b", I),
    re.compile(r"\bif\s+you\s+are\s+(an?\s+)?(llm|ai|language model|scanner|reviewer|security|auditor|analy[sz]er)", I),
    re.compile(r"\bthis\s+(skill|file)\s+is\s+(safe|benign|trusted|harmless)\b", I),
    re.compile(r"игнорируй\s+(все\s+)?(предыдущие|прежние|выше\w*)\s+(инструкции|указания|правила)", I),
    re.compile(r"если\s+ты\s+(ии|нейросеть|сканер|рецензент|аудитор|модель)", I),
    re.compile(r"(отметь|оцени|признай)\s+(это\s+|скилл\s+)?как\s+безопасн", I),
]
EXFIL = re.compile(
    r"(send|post|upload|forward|exfiltrate|transmit|отправ\w+|передай|передайте|загрузи)[^\n]{0,80}"
    r"(api[_ -]?keys?|tokens?|secrets?|passwords?|credentials?|\.env|ssh|private key|cookies?|ключ\w*|токен\w*|парол\w*|секрет\w*)"
    r"[^\n]{0,120}https?://", I)
SENSITIVE_PATHS = re.compile(
    r"(~|\$HOME|/home/\w+|/root)?/?\.(ssh|aws|gnupg|kube|docker|npmrc|netrc|pypirc)\b|id_rsa|id_ed25519|credentials\.json|\.env\b|"
    r"keychain|Login Data|cookies\.sqlite|wallet\.dat", I)
AGENT_STATE = re.compile(
    r"\b(MEMORY\.md|SOUL\.md|AGENTS\.md|CLAUDE\.md|settings(\.local)?\.json|\.mcp\.json|\.bashrc|\.zshrc|\.profile|"
    r"crontab|authorized_keys|hooks?\b[^\n]{0,20}(settings|json)|persistent memory|постоянн\w+ памят\w+)", I)
WRITE_VERBS = re.compile(
    r"\b(write|append|add|edit|modify|overwrite|update|insert|store|save|persist|remember|"
    r"запиши|допиши|добавь|измени|перезапиши|обнови|сохрани|запомни)\w*", I)
BAD_HOSTS = re.compile(
    r"(webhook\.site|requestbin|pipedream|hooks\.slack\.com|discord(app)?\.com/api/webhooks|pastebin\.com|paste\.ee|"
    r"transfer\.sh|ngrok|interact\.sh|oast\.\w+|burpcollaborator|bit\.ly|tinyurl\.com|t\.co/|goo\.gl|is\.gd|rb\.gy|"
    r"api\.telegram\.org/bot|\b\d{1,3}(\.\d{1,3}){3}\b)", I)
URL_RE = re.compile(r"https?://([A-Za-z0-9._\-]+)(?::\d+)?[^\s)\]>\"']*")
SUSP_COMMENT = re.compile(
    r"(api[_ -]?key|token|secret|password|credential|curl|wget|bash|\bsh\b|exfil|send|post|upload|ignore|system prompt|"
    r"do not tell|don't tell|never tell|не\s+сообщ|не\s+говор|скрой|ключ|токен|парол|http)", I)
SCRIPT_PATTERNS = OrderedDict([
    ("сеть", re.compile(r"\b(requests\.(get|post|put)|urllib|http\.client|fetch\(|XMLHttpRequest|axios|socket\.|net\.connect|curl\s|wget\s)", I)),
    ("запуск процессов", re.compile(r"\b(subprocess|os\.system|child_process|exec\(|execSync|spawn\(|popen|Runtime\.getRuntime)", I)),
    ("динамический код", re.compile(r"\b(eval\(|exec\(|new Function|compile\(|__import__)", I)),
    ("раскодирование", re.compile(r"(base64\.b64decode|atob\(|Buffer\.from\([^)]*base64|fromCharCode|codecs\.decode|bytes\.fromhex)", I)),
])


def san(s, limit=140):
    """Безопасная печать: управляющие и невидимые символы заменяются на <U+XXXX>."""
    out = []
    for ch in s:
        o = ord(ch)
        if ch == "\t":
            out.append(" ")
        elif o < 32 or o == 127 or 0x80 <= o < 0xA0 or o in ZERO_WIDTH or o in BIDI or o in VARIATION \
                or o in TAG_RANGE or o == 0xFEFF or o in (0x2028, 0x2029):
            out.append("<U+%04X>" % o)
        else:
            out.append(ch)
    t = "".join(out)
    return t if len(t) <= limit else t[:limit] + "…"


class Report:
    def __init__(self):
        self.findings = []
        self.domains = Counter()
        self.files = 0
        self.skipped = []
        self.manifest = []
        self.tail = None
        self.binary = []
        self.scripts = []
        self._agg = {}

    def add(self, code, sev, path, line, msg, ev=""):
        if code in AGGREGATE:  # шумные признаки: одна находка на файл, со счётом
            key = (code, path)
            if key in self._agg:
                self._agg[key]["count"] += 1
                return
        f = {"code": code, "severity": sev, "path": path, "line": line,
             "message": msg, "evidence": san(ev) if ev else "", "count": 1}
        if code in AGGREGATE:
            self._agg[(code, path)] = f
        self.findings.append(f)


def is_text(data):
    return b"\x00" not in data[:8192]


def scan_text(rep, rel, text, ext, is_skill_md):
    lines = text.split("\n")
    prose = ext in PROSE_EXT
    is_script = ext in SCRIPT_EXT

    # P3 невидимые символы
    inv = {"tag": [], "bidi": [], "zw": [], "var": []}
    for ln, line in enumerate(lines, 1):
        for pos, ch in enumerate(line):
            o = ord(ch)
            if o == 0xFEFF and ln == 1 and pos == 0:
                continue
            if o in TAG_RANGE:
                inv["tag"].append(ln)
            elif o in BIDI:
                inv["bidi"].append(ln)
            elif o in ZERO_WIDTH or o == 0xFEFF:
                inv["zw"].append(ln)
            elif o in VARIATION:
                inv["var"].append(ln)
    if inv["tag"]:
        rep.add("R3.1", "HIGH", rel, inv["tag"][0], "теговые символы Unicode (U+E0000–E007F): скрытый текст, невидим в рендере", "%d шт." % len(inv["tag"]))
    if inv["bidi"]:
        rep.add("R3.2", "HIGH", rel, inv["bidi"][0], "символы смены направления письма: текст читается не в том порядке, в каком показан", "%d шт." % len(inv["bidi"]))
    if inv["zw"]:
        n = len(inv["zw"])
        if prose:
            rep.add("R3.3", "HIGH" if n >= 3 else "MEDIUM", rel, inv["zw"][0],
                    "символы нулевой ширины в тексте: прячут слова от поиска по ключам или кодируют сообщение", "%d шт." % n)
        else:
            rep.add("R3.3", "MEDIUM", rel, inv["zw"][0],
                    "символы нулевой ширины в коде: допустимо в строке-данных, но запишите их через \\u200b", "%d шт." % n)
    if len(inv["var"]) >= 5:
        rep.add("R3.4", "MEDIUM", rel, inv["var"][0], "селекторы вариантов Unicode: возможно кодирование данных", "%d шт." % len(inv["var"]))

    # P1 блоки пустых строк (проза)
    if prose:
        run = 0
        start = 0
        for ln, line in enumerate(lines + ["§конец§"], 1):
            if line.strip() == "" or all(ord(c) in ZERO_WIDTH or ord(c) in TAG_RANGE or c.isspace() for c in line):
                if run == 0:
                    start = ln
                run += 1
            else:
                if run >= 20:
                    follows = line != "§конец§"
                    if run >= 40 and follows:
                        sev, why = "HIGH", "после блока есть текст"
                    elif run >= 40:
                        sev, why = "LOW", "блок в конце файла"
                    else:
                        sev, why = "MEDIUM", "после блока есть текст" if follows else "блок в конце файла"
                    rep.add("R1", sev, rel, start, "%d пустых строк подряд (%s): так прячут инструкцию ниже видимого конца файла" % (run, why))
                run = 0

    # P2 HTML-комментарии (проза)
    if prose:
        for m in re.finditer(r"<!--(.*?)-->", text, re.S):
            ln = text.count("\n", 0, m.start()) + 1
            body = m.group(1).strip()
            sev = "HIGH" if SUSP_COMMENT.search(body) else "MEDIUM"
            rep.add("R2", sev, rel, ln, "HTML-комментарий: рендер его скрывает, агент читает", body.replace("\n", " "))

    # поиск по строкам
    for ln, line in enumerate(lines, 1):
        if len(line) > 4000:
            line_check = line[:4000]
        else:
            line_check = line
        for rx in PIPE_SHELL:
            if rx.search(line_check):
                rep.add("R4", "HIGH", rel, ln, "загрузка и запуск чужого кода одной строкой (curl | sh и подобное)", line_check.strip())
                break
        for rx in HIDE_FROM_USER:
            if rx.search(line_check):
                rep.add("R7", "HIGH", rel, ln, "инструкция не сообщать пользователю", line_check.strip())
                break
        for rx in ADDRESS_SCANNER:
            if rx.search(line_check):
                rep.add("R8", "HIGH", rel, ln, "обращение к модели или сканеру: игнорировать правила или признать безопасным", line_check.strip())
                break
        if EXFIL.search(line_check):
            rep.add("R9", "HIGH", rel, ln, "отправка ключей, токенов или секретов по адресу", line_check.strip())
        elif SENSITIVE_PATHS.search(line_check) and not is_script:
            rep.add("R9.1", "MEDIUM", rel, ln, "упомянуты чувствительные пути (ключи, облачные данные, куки)", line_check.strip())
        mm = AGENT_STATE.search(line_check)
        if mm and WRITE_VERBS.search(line_check):
            rep.add("R6", "MEDIUM", rel, ln, "запись в память или конфиг агента: переживёт удаление скилла", line_check.strip())
        if BAD_HOSTS.search(line_check):
            rep.add("R5.1", "MEDIUM", rel, ln, "адрес из группы риска: вебхук, пастебин, сократитель ссылок, голый IP, бот-API", line_check.strip())
        for u in URL_RE.finditer(line_check):
            rep.domains[u.group(1).lower()] += 1

    # скрипты: возможности
    if is_script:
        found = [name for name, rx in SCRIPT_PATTERNS.items() if rx.search(text)]
        if found:
            rep.scripts.append((rel, found))


def collect(root):
    """Список файлов относительно root; симлинки не раскрываются."""
    if os.path.isfile(root):
        return [(os.path.basename(root), root)], []
    out, links = [], []
    for d, dirs, fs in os.walk(root, followlinks=False):
        dirs[:] = sorted(x for x in dirs if x != ".git")
        for f in sorted(fs):
            p = os.path.join(d, f)
            out.append((os.path.relpath(p, root), p))
        for x in list(dirs):
            if os.path.islink(os.path.join(d, x)):
                links.append((os.path.relpath(os.path.join(d, x), root), os.path.join(d, x)))
    return out, links


def run(target, tail_n):
    rep = Report()
    root = os.path.abspath(target)
    if not os.path.exists(root):
        raise FileNotFoundError(target)
    files, dirlinks = collect(root)
    for rel, p in dirlinks:
        _link(rep, rel, p, root)
    if len(files) > MAX_FILES:
        rep.skipped.append("файлов больше %d, просмотрены первые %d" % (MAX_FILES, MAX_FILES))
        files = files[:MAX_FILES]
    skill_md = None
    h = hashlib.sha256()
    for rel, p in files:
        if os.path.islink(p):
            _link(rep, rel, p, root)
            continue
        try:
            size = os.path.getsize(p)
            if size > MAX_FILE:
                rep.add("R10", "MEDIUM", rel, 0, "файл больше 2 МБ не просмотрен (там прячут нагрузку)", "%d байт" % size)
                continue
            with open(p, "rb") as fh:
                data = fh.read()
        except OSError as e:
            rep.skipped.append("%s: %s" % (rel, e.strerror))
            continue
        fh_ = hashlib.sha256(data).hexdigest()
        rep.manifest.append((rel, fh_))
        h.update(rel.encode("utf-8", "replace") + b"\0" + fh_.encode() + b"\n")
        rep.files += 1
        if not is_text(data):
            rep.binary.append(rel)
            continue
        text = data.decode("utf-8", "replace")
        ext = os.path.splitext(rel)[1].lower()
        name = os.path.basename(rel)
        is_md = name == "SKILL.md"
        scan_text(rep, rel, text, ext, is_md)
        if is_md and (skill_md is None or rel.count(os.sep) < skill_md[0].count(os.sep)):
            skill_md = (rel, text)
    if rep.binary:
        rep.add("R11", "MEDIUM", ", ".join(rep.binary[:5]) + ("…" if len(rep.binary) > 5 else ""), 0,
                "бинарные файлы в скилле (%d): содержимое не просматривалось" % len(rep.binary))
    for rel, caps in rep.scripts:
        rep.add("R12", "LOW", rel, 0, "скрипт может: " + ", ".join(caps))
    if skill_md:
        ls = skill_md[1].split("\n")
        lines_tail = ls[-tail_n:] if tail_n > 0 else []
        start = len(ls) - len(lines_tail) + 1
        rep.tail = {"path": skill_md[0], "total_lines": len(ls),
                    "lines": [(start + i, san(x, 200)) for i, x in enumerate(lines_tail)]}
    rep.pin = "sha256:" + h.hexdigest()
    rep.has_skill = skill_md is not None
    return rep


def _link(rep, rel, p, root):
    try:
        dest = os.path.realpath(p)
    except OSError:
        dest = "?"
    inside = dest == root or dest.startswith(root + os.sep)
    rep.add("R13", "LOW" if inside else "HIGH", rel, 0,
            "символическая ссылка " + ("внутри скилла" if inside else "наружу: скилл читает или пишет чужие файлы"),
            "→ " + dest)


def emit(rep, fmt, fail_on, target):
    thr = SEV_ORDER[fail_on]
    blocking = [f for f in rep.findings if SEV_ORDER[f["severity"]] >= thr]
    cnt = Counter(f["severity"] for f in rep.findings)
    if fmt == "json":
        print(json.dumps({
            "target": target, "pin": rep.pin, "files": rep.files,
            "findings": rep.findings, "domains": dict(rep.domains),
            "tail": rep.tail, "skipped": rep.skipped}, ensure_ascii=False, indent=2))
    else:
        print("skill-raw: %s" % san(target, 200))
        print("файлов просмотрено: %d · находок: HIGH %d, MEDIUM %d, LOW %d" % (
            rep.files, cnt["HIGH"], cnt["MEDIUM"], cnt["LOW"]))
        print("отпечаток: %s" % rep.pin)
        for s in ("HIGH", "MEDIUM", "LOW"):
            for f in [x for x in rep.findings if x["severity"] == s]:
                loc = "%s:%d" % (f["path"], f["line"]) if f["line"] else f["path"]
                more = " (всего в файле: %d)" % f["count"] if f.get("count", 1) > 1 else ""
                print("[%s] %s %s — %s%s" % (s, f["code"], san(loc, 120), f["message"], more))
                if f["evidence"]:
                    print("      " + f["evidence"])
        if rep.domains:
            print("внешние адреса (%d): %s" % (len(rep.domains), ", ".join(
                "%s×%d" % (d, n) for d, n in sorted(rep.domains.items(), key=lambda x: (-x[1], x[0]))[:20])))
        if rep.tail:
            print("конец %s (последние %d из %d строк, невидимые символы раскрыты):" % (
                rep.tail["path"], len(rep.tail["lines"]), rep.tail["total_lines"]))
            for n, t in rep.tail["lines"]:
                print("  %4d| %s" % (n, t))
        for s in rep.skipped:
            print("пропущено: %s" % san(s))
        print("Чистый результат не значит безопасно: смысл инструкций не оценивался.")
    return blocking


def main(argv):
    ap = argparse.ArgumentParser(description="Просмотр сырого чужого скилла до установки")
    ap.add_argument("target", help="папка скилла, репозиторий или SKILL.md")
    ap.add_argument("--format", choices=["text", "json"], default="text")
    ap.add_argument("--fail-on", choices=["high", "medium"], default="high")
    ap.add_argument("--tail", type=int, default=12, help="сколько последних строк SKILL.md показать")

    def err(msg):
        print("SKILL_ERROR\nSTAGE=аргументы\nERROR=%s" % msg)
        sys.exit(1)
    ap.error = err
    a = ap.parse_args(argv)
    try:
        rep = run(a.target, a.tail)
    except FileNotFoundError:
        print("SKILL_ERROR\nSTAGE=чтение\nERROR=путь не найден: %s" % san(a.target, 200))
        return 1
    except OSError as e:
        print("SKILL_ERROR\nSTAGE=чтение\nERROR=%s" % san(str(e), 200))
        return 1
    blocking = emit(rep, a.format, a.fail_on.upper(), a.target)
    quiet = a.format == "json"  # чистый JSON в stdout, маркер не печатается
    if not rep.has_skill:
        if not quiet:
            print("\nSKILL_NEEDS_INPUT\nMISSING=SKILL.md\nWHERE=укажите папку скилла; SKIPPED не значит PASS")
        return 10
    if blocking:
        if not quiet:
            print("\nSKILL_STOP\nBLOCKING=%d\nTHRESHOLD=%s\nPIN=%s" % (len(blocking), a.fail_on.upper(), rep.pin))
        return 2
    if not quiet:
        print("\nSKILL_RESULT\nSUMMARY=стоп-находок нет; файлов %d; безопасность не доказана\nPIN=%s" % (rep.files, rep.pin))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
