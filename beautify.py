#!/usr/bin/env python3
"""Post-process Ghidra bodies: rename param_N -> real IL2CPP parameter names.

Reads csharp/part*/*.cs, writes csharp_pretty/ (same layout).
Only textual, no semantics changes.
"""
import glob
import json
import os
import re
import sys

SRC = sys.argv[1] if len(sys.argv) > 1 else "csharp"
DST = sys.argv[2] if len(sys.argv) > 2 else "csharp_pretty"
IMG_BASE = 0x100000

PARAM_RE = re.compile(r"\bparam_(\d+)\b")
CALL_RE = re.compile(r"\b(?:thunk_FUN|func|FUN|SUB)_0x([0-9a-fA-F]{4,})\b")


def load_names(path="dump/script.json"):
    if not os.path.exists(path):
        return {}
    d = json.load(open(path))
    out = {}
    for x in d.get("ScriptMethod", []):
        a = x.get("Address") or 0
        if a:
            out[a] = x["Name"].replace("$$", ".")
    return out


NAMES = load_names()

TYPE_RE = re.compile(
    r"^(?:\[.*?\]\s*)?(?:public|internal|private|protected)?\s*"
    r"(?:sealed\s+|abstract\s+|static\s+|readonly\s+|ref\s+)*"
    r"(?:class|struct)\s+([A-Za-z_][\w]*)"
)
FIELD_RE = re.compile(r"^\s*(?:public|private|protected|internal)\s+.*?\s([A-Za-z_]\w*)\s*;\s*//\s*(0x[0-9a-fA-F]+)\s*$")


def load_fields(path="dump/dump.cs"):
    """type name -> {offset: field name} from Il2CppDumper dump.cs"""
    if not os.path.exists(path):
        return {}
    out = {}
    cur = None
    for line in open(path, encoding="utf-8", errors="replace"):
        m = TYPE_RE.match(line)
        if m:
            cur = m.group(1)
            out.setdefault(cur, {})
            continue
        if cur and line.startswith(("\t", " ")):
            fm = FIELD_RE.match(line)
            if fm:
                out[cur][int(fm.group(2), 16)] = fm.group(1)
        elif line.strip() == "}":
            cur = None
    return out


FIELDS = load_fields()
OFF_RE = re.compile(r"\(__this\s*\+\s*(0x[0-9a-fA-F]+)\)")


def annotate_fields(text, type_name):
    if not type_name or type_name not in FIELDS:
        return text
    fmap = FIELDS[type_name]
    if not fmap:
        return text

    def repl(m):
        off = int(m.group(1), 16)
        name = fmap.get(off)
        if name:
            return f"(__this + {m.group(1)} /* .{name} */)"
        return m.group(0)

    return OFF_RE.sub(repl, text)


def resolve_calls(text):
    if not NAMES:
        return text

    def repl(m):
        addr = int(m.group(1), 16)
        name = NAMES.get(addr - IMG_BASE)
        return name if name else m.group(0)

    return CALL_RE.sub(repl, text)


def parse_il2cpp_params(sig):
    """void Foo__bar (Type* __this, int x, const MethodInfo* method) -> ['__this','x','method']"""
    m = re.search(r"\((.*)\)\s*;?\s*$", sig.strip())
    if not m:
        return []
    inner = m.group(1).strip()
    if not inner:
        return []
    parts, depth, cur = [], 0, ""
    for ch in inner:
        if ch == "<":
            depth += 1
        elif ch == ">":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    parts.append(cur)
    names = []
    for p in parts:
        p = p.strip()
        if not p:
            continue
        name = p.split()[-1].lstrip("*")
        names.append(name)
    return names


def process_block(block):
    head, sep, body = block.partition("\n")
    if not sep:
        return block
    m = re.search(r"^// il2cpp: (.*)$", block, re.M)
    if not m:
        return block
    names = parse_il2cpp_params(m.group(1))
    if not names:
        return block

    def repl(mm):
        i = int(mm.group(1)) - 1
        return names[i] if 0 <= i < len(names) else mm.group(0)

    block = PARAM_RE.sub(repl, block)

    tm = re.search(r"\(\s*([A-Za-z_]\w*)_o\s*\*\s*__this", m.group(1))
    if tm:
        block = annotate_fields(block, tm.group(1))
    return block


def main():
    n_files = 0
    n_blocks = 0
    for src in glob.glob(os.path.join(SRC, "part*", "**", "*.cs"), recursive=True):
        rel = os.path.relpath(src, SRC)
        dst = os.path.join(DST, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        text = open(src, encoding="utf-8", errors="replace").read()
        if not text.strip():
            continue
        chunks = re.split(r"(?=^// RVA: )", text, flags=re.M)
        out = []
        for c in chunks:
            if c.startswith("// RVA: "):
                c = process_block(c)
                n_blocks += 1
            out.append(resolve_calls(c))
        open(dst, "w", encoding="utf-8").write("".join(out))
        n_files += 1
    print(f"files={n_files} blocks={n_blocks}")


if __name__ == "__main__":
    main()
