#!/usr/bin/env python3
""

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path




# Override this portable default by setting BAC_DATASET_ROOT to your dataset directory.
DATASET_ROOT = Path(os.environ.get("BAC_DATASET_ROOT", Path(__file__).resolve().parents[1])).expanduser().resolve()
REPOS = ["usememos", "openemr", "inlong", "xwiki", "bookwyrm", "nextcloud"]
CVE_APP_SOURCE = DATASET_ROOT / "cve-app-source"

REPO_MAP = {
    "usememos":   {"default": "memos-v0.8.3"},
    "bookwyrm":   {"default": "bookwyrm-v0.4.3"},
    "inlong":     {"default": "inlong-1.6.0-RC0"},
    "openemr":    {"default": "openemr-v7_0_0",
                   "exceptions": {"cve-2022-1177": "openemr-v6_0_0"}},
    "xwiki":      {"default": "xwiki-platform-12.10.1",
                   "exceptions": {"cve-2021-32731": "xwiki-platform-13.1"}},
    "nextcloud":  {"per_vuln": True},
}

DESC_FILE = "vul_information_base.txt"
POC_FILE = "poc_natural_language.txt"
PATCH_DIR = "patch-file-all"
ADDR_FILE = "source_code_address_info.txt"


MODEL_ID = "deepseek-v4-pro"
DEEPSEEK_BASE_URL = "https://api.deepseek.com"
DEEPSEEK_ENV = "DEEPSEEK_API_KEY"
MODE_LABEL = "Think Max"
REASONING_KWARGS = {"reasoning_effort": "max", "extra_body": {"thinking": {"type": "enabled"}}}


MAX_READ_ROUNDS = 10          
SUGGEST_FILES = 8            
HARD_FILES = 12              
READ_FILE_MAX_LINES = 1500   
TREE_FULL_MAX = 2000         
TREE_DEPTH = 2               
TREE_MAX_LINES = 1500        
LS_MAX_ENTRIES = 400         

SYSTEM_PROMPT = (
    "You are a security expert specializing in fixing web application access-control vulnerabilities (broken access control).\n"
    "This task has two phases. In phase 1, inspect source code on demand. In phase 2, generate the fix. "
    "I will first provide vulnerability information and the repository file tree, without source contents. "
    "Request source files or directory listings over multiple rounds. When you understand the vulnerability and its access-control mechanism, output a unified diff patch. "
    "Preserve real file paths, match unchanged context exactly, use numbered hunk headers, separate multiple files with independent diff --git headers, "
    "and put the final fix in exactly one ```diff code block."
)

SUCCESS_STATUS = ("check_passed", "applied")





_DIFF_LINE = re.compile(r"^(diff --git |--- |\+\+\+ |@@ |index )")


def _looks_like_diff(text: str) -> bool:
    return bool(re.search(r"^@@", text, re.M)) or "diff --git " in text or\
        (re.search(r"^--- ", text, re.M) and re.search(r"^\+\+\+ ", text, re.M))


def extract_diff_blocks(content: str) -> str:
    def _join(blocks):
        return "".join(b if b.endswith("\n") else b + "\n" for b in blocks)
    for tag in ("diff", "patch"):
        blocks = re.findall(rf"```{tag}[ \t]*\n(.*?)```", content, re.DOTALL)
        if blocks:
            return _join(blocks)
    generic = re.findall(r"```[a-zA-Z]*[ \t]*\n(.*?)```", content, re.DOTALL)
    diffish = [b for b in generic if _looks_like_diff(b)]
    if diffish:
        return _join(diffish)
    if _looks_like_diff(content):
        m = re.search(r"^(diff --git |--- a/)", content, re.M)
        if m:
            lines = content[m.start():].splitlines()
            while lines and not (lines[-1][:1] in (" ", "+", "-", "@", "\\")
                                 or _DIFF_LINE.match(lines[-1])):
                lines.pop()
            if lines:
                return "\n".join(lines) + "\n"
    return ""


def normalize_patch(text: str) -> str:
    if "```" in text or not re.match(r"^(diff --git |--- a/)", text):
        extracted = extract_diff_blocks(text)
        if extracted.strip():
            text = extracted
    if text and not text.endswith("\n"):
        text += "\n"
    return text


def precheck_format(patch: str) -> list[str]:
    issues = []
    if not patch.strip():
        return ["Could not extract any diff (the model may not have produced a ```diff code block)."]
    if not re.search(r"^--- ", patch, re.M) or not re.search(r"^\+\+\+ ", patch, re.M):
        issues.append("Missing the '--- a/file' or '+++ b/file' file header.")
    hunks = re.findall(r"^@@.*$", patch, re.M)
    if not hunks:
        issues.append("No '@@' hunk header.")
    bare = [h for h in hunks if not re.match(r"^@@ -\d", h)]
    if bare:
        issues.append(f"{len(bare)} hunk header(s) lack line-number ranges (bare '@@'); git will report "
                      "'unrecognized input'. Use the form '@@ -start,count +start,count @@'.")
    return issues





def discover_vul_names(project: str) -> list[str]:
    base = DATASET_ROOT / project
    if not base.is_dir():
        return []
    return sorted(p.name for p in base.iterdir()
                  if p.is_dir() and (p / PATCH_DIR).is_dir())


def _git_repo_in(base: Path) -> Path:
    if (base / ".git").is_dir():
        return base
    if base.is_dir():
        repos = sorted(d for d in base.iterdir() if d.is_dir() and (d / ".git").is_dir())
        if repos:
            return repos[0]
    raise FileNotFoundError(f"{base}  does not contain a repository with .git  repository directory")


def resolve_repo(project: str, vul_name: str) -> Path:
    cfg = REPO_MAP.get(project)
    if cfg is None:
        raise KeyError(f"REPO_MAP does not configure project {project}  repository mapping")
    proj_root = CVE_APP_SOURCE / project
    if cfg.get("per_vuln"):
        return _git_repo_in(proj_root / vul_name)
    version = cfg.get("exceptions", {}).get(vul_name, cfg["default"])
    matches = sorted(d for d in proj_root.glob(f"*/{version}") if (d / ".git").is_dir())
    if not matches:
        raise FileNotFoundError(f"Could not find {project}  version repository directory: */{version}(under {proj_root} text)")
    return matches[0]


def load_vul_meta(project: str, vul_name: str) -> tuple[str, str, str]:
    ""
    vul_dir = DATASET_ROOT / project / vul_name
    desc = (vul_dir / DESC_FILE).read_text(encoding="utf-8").strip()
    poc = (vul_dir / POC_FILE).read_text(encoding="utf-8").strip()
    addr = (vul_dir / PATCH_DIR / ADDR_FILE).read_text(encoding="utf-8").strip()
    return desc, poc, addr


def _all_files(repo: Path) -> list[str]:
    ""
    out = []
    for p in repo.rglob("*"):
        if not p.is_file():
            continue
        rel = p.relative_to(repo)
        if rel.parts and rel.parts[0] == ".git":
            continue
        out.append(rel.as_posix())
    return sorted(out)


def _nested(files: list[str]) -> dict:
    root: dict = {}
    for f in files:
        parts = f.split("/")
        d = root
        for p in parts[:-1]:
            d = d.setdefault(p, {})
        d.setdefault("__files__", []).append(parts[-1])
    return root


def _count_files(node: dict) -> int:
    n = len(node.get("__files__", []))
    for k, v in node.items():
        if k != "__files__":
            n += _count_files(v)
    return n


def _render_tree(node: dict, prefix: str, depth: int, maxdepth: int, lines: list, cap: int):
    if len(lines) >= cap:
        return
    for fn in sorted(node.get("__files__", [])):
        lines.append(prefix + fn)
        if len(lines) >= cap:
            return
    for name in sorted(k for k in node if k != "__files__"):
        sub = node[name]
        if depth >= maxdepth:
            lines.append(f"{prefix}{name}/   ({_count_files(sub)}  files, use ```ls expand)")
        else:
            lines.append(prefix + name + "/")
            _render_tree(sub, prefix + "  ", depth + 1, maxdepth, lines, cap)


def build_tree_view(repo: Path) -> tuple[str, int, bool]:
    ""
    files = _all_files(repo)
    if len(files) <= TREE_FULL_MAX:
        return "\n".join(files), len(files), False
    node = _nested(files)
    for md in (TREE_DEPTH, 1):
        lines: list = []
        _render_tree(node, "", 0, md, lines, TREE_MAX_LINES)
        if len(lines) < TREE_MAX_LINES:
            break
    return "\n".join(lines), len(files), True


def _norm_rel(p: str) -> str:
    s = p.strip().strip("`").strip().lstrip("-* ").strip().strip('"').strip("'")
    while s.startswith("./"):
        s = s[2:]
    s = s.lstrip("/")
    return s


def list_dir(repo: Path, d: str) -> tuple[str, bool]:
    base = repo / _norm_rel(d) if _norm_rel(d) else repo
    if not base.is_dir():
        return "", False
    entries = []
    for c in sorted(base.iterdir()):
        if c.name == ".git":
            continue
        entries.append(c.name + ("/" if c.is_dir() else ""))
    extra = ""
    if len(entries) > LS_MAX_ENTRIES:
        extra = f"\n... (Total {len(entries)} entries, showing only the first {LS_MAX_ENTRIES})"
        entries = entries[:LS_MAX_ENTRIES]
    return "\n".join(entries) + extra, True


_RANGE_RE = re.compile(r"^(.*?):(\d+)\s*-\s*(\d+)\s*$")


def _split_range(p: str) -> tuple[str, int | None, int | None]:
    ""
    m = _RANGE_RE.match(p.strip())
    if m:
        return m.group(1).strip(), int(m.group(2)), int(m.group(3))
    return p, None, None


def read_one(repo: Path, p: str) -> tuple[str, str, int, str, bool]:
    ""
    raw, lo, hi = _split_range(p)
    rel = _norm_rel(raw)
    fp = repo / rel
    if not fp.is_file():
        cand = [q for q in repo.rglob(Path(rel).name)
                if q.is_file() and ".git" not in q.parts]
        if len(cand) == 1:
            fp = cand[0]; rel = fp.relative_to(repo).as_posix()
        else:
            return rel, "", 0, "", False
    lines = fp.read_text(encoding="utf-8", errors="replace").splitlines()
    n = len(lines)

    if lo is not None:                                  
        lo = max(1, lo); hi = min(n, hi)
        if lo > n:
            return rel, "", n, f"(Total {n} , requested start line {lo} is outside the file)", True
        seg = "\n".join(f"{i:>5}\t{lines[i-1]}" for i in range(lo, hi + 1))
        note = f"(Total {n} , showingLines  {lo}~{hi} )"
        return rel, seg, n, note, True

    if n <= READ_FILE_MAX_LINES:                        
        body = "\n".join(f"{i+1:>5}\t{ln}" for i, ln in enumerate(lines))
        return rel, body, n, f"(Total {n} , full text)", True

    
    body = "\n".join(f"{i+1:>5}\t{lines[i]}" for i in range(READ_FILE_MAX_LINES))
    note = (f"(Total {n} , The file is long, showing the first {READ_FILE_MAX_LINES} ; "
            f"To inspect a later range, under ```read text `{rel}:start line-end line`, text "
            f"`{rel}:{READ_FILE_MAX_LINES+1}-{min(n, READ_FILE_MAX_LINES+800)}`)")
    return rel, body, n, note, True





def _paths_from_blocks(reply: str, tag: str) -> list[str]:
    ""
    out = []
    for b in re.findall(rf"```{tag}[ \t]*\n(.*?)```", reply, re.DOTALL):
        for line in b.splitlines():
            raw = line.strip()
            if not raw or raw.startswith("#"):
                continue
            m = _RANGE_RE.match(raw) if tag == "read" else None
            if m:
                s = _norm_rel(m.group(1)) + f":{m.group(2)}-{m.group(3)}"
            else:
                s = _norm_rel(raw)
            if not s or s.startswith("#"):
                continue
            out.append(s)
    seen = set()
    return [p for p in out if not (p in seen or seen.add(p))]


def parse_read_request(reply: str) -> tuple[list[str], list[str], bool]:
    ""
    reads = _paths_from_blocks(reply, "read")
    ls = _paths_from_blocks(reply, "ls")
    done = bool(re.search(r"READ_DONE", reply))
    return reads, ls, done





def build_explore_intro(desc: str, poc: str, addr: str,
                        tree: str, total: int, partial: bool) -> str:
    nav = (
        "- To inspect files, output one ```read code block with one repository-relative path per line "
        f"(up to {SUGGEST_FILES} suggested files, with a hard limit of {HARD_FILES} per round). "
        f"Long files return only the first {READ_FILE_MAX_LINES} lines; to read a later range, use `path:start-end`, "
        "for example `src/Foo.java:1600-2400`.\n"
    )
    if partial:
        nav += (
            "- The tree is large, so deep directories are collapsed as `dir/ (N files; use ```ls to expand)`. "
            "To inspect a directory, output one ```ls code block with one directory-relative path per line.\n"
        )
    nav += "- When you have enough information to generate the fix, output one line: READ_DONE (do not output more read/ls blocks).\n"
    return (
        "[Vulnerability description]\n" + desc + "\n\n"
        "[Vulnerability PoC description]\n" + poc + "\n\n"
        "[Source locations in the project file]\n" + addr + "\n\n"
        f"[Repository file tree (total {total} files{' ; deep directories collapsed' if partial else ''})]\n"
        + tree + "\n\n---\n"
        "You cannot see source contents yet; only the tree above is available. Read files as needed:\n" + nav +
        f"You may use at most {MAX_READ_ROUNDS} rounds. After each round, briefly summarize your findings and decide what to inspect next. "
        f"After {MAX_READ_ROUNDS} rounds, you will be asked to generate the patch directly.\n"
        "Provide the first files to inspect in a ```read block, use ```ls for navigation if needed, or output READ_DONE directly."
    )


def build_read_result(repo: Path, reads: list[str], ls: list[str], round_no: int):
    parts, found, missing = [], [], []
    for d in ls[:HARD_FILES]:
        listing, ok = list_dir(repo, d)
        if ok:
            parts.append(f"# ===== Directory listing: {d} =====\n{listing}")
        else:
            parts.append(f"# Directory does not exist(choose from the provided tree): {d}")
            missing.append(d + "/(dir)")
    to_read, skipped = reads[:HARD_FILES], reads[HARD_FILES:]
    for p in to_read:
        rel, body, n, note, ok = read_one(repo, p)
        if ok:
            found.append(rel)
            parts.append(f"# ===== File: {rel} {note} =====\n```\n{body}\n```")
        else:
            missing.append(p)
            parts.append(f"# File not found(choose a valid relative path from the provided tree): {p}")
    head = f"[Lines  {round_no}/{MAX_READ_ROUNDS}  roundreading result]"
    if skipped:
        head += f"(Too many files were requested, only the first {HARD_FILES} ; request the rest next round: {', '.join(skipped)})"
    tail = (f"\n--—\nThis is round  {round_no}/{MAX_READ_ROUNDS}  round, remaining {MAX_READ_ROUNDS - round_no}  round."
            "To continue: text ```read(File)text ```ls(directory)text; If sufficient: text READ_DONE.")
    return head + "\n" + "\n\n".join(parts) + tail, found, missing


def build_generate_msg() -> str:
    return (
        "You have finished reading source code. Use the gathered information to analyze the access-control vulnerability root cause "
        "and provide a remediation as a unified diff patch that follows all formatting requirements. "
        "Output only one ```diff code block."
    )


def build_repair_user_msg(patch: str, git_err: str, rej: str, file_ctx: str,
                          fmt_issues: list[str]) -> str:
    parts = ["Your previous patch could not be applied. Use the following information to generate a correct unified diff.\n"]
    if fmt_issues:
        parts.append("[Format precheck errors]\n- " + "\n- ".join(fmt_issues) + "\n")
    parts.append("[git apply --check error output]\n" + (git_err or "(No stderr)") + "\n")
    if rej:
        parts.append("[Failed hunk(.rej, this context did not match the real file)]\n" + rej + "\n")
    parts.append("[Current target file contents--align context to this content]\n" + file_ctx + "\n")
    parts.append("[Your previous rejected patch]\n```diff\n" + (patch or "(empty)") + "\n```\n")
    parts.append("Output only one corrected ```diff code block.")
    return "\n".join(parts)





def _git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True)


def apply_check(repo: Path, patch_path: Path) -> tuple[bool, str, str | None]:
    cp1 = _git(repo, "apply", "-p1", "--check", str(patch_path))
    if cp1.returncode == 0:
        return True, "", "git apply --check"
    cp2 = _git(repo, "apply", "--recount", "-p1", "--check", str(patch_path))
    if cp2.returncode == 0:
        return True, "", "git apply --recount --check"
    return False, (cp1.stderr or cp1.stdout).strip(), None


def do_apply(repo: Path, patch_path: Path) -> tuple[bool, str]:
    cp = _git(repo, "apply", "-p1", str(patch_path))
    if cp.returncode == 0:
        return True, ""
    cp = _git(repo, "apply", "--recount", "-p1", str(patch_path))
    return cp.returncode == 0, (cp.stderr or cp.stdout).strip()


def patched_files(patch: str) -> list[str]:
    files = re.findall(r"^\+\+\+ b/(\S+)", patch, re.M) or re.findall(r"^--- a/(\S+)", patch, re.M)
    seen, out = set(), []
    for f in files:
        if f not in seen:
            seen.add(f); out.append(f)
    return out


def collect_rejects(repo: Path, patch_path: Path, patch: str) -> str:
    _git(repo, "apply", "--reject", "-p1", str(patch_path))
    rej_text = []
    for f in patched_files(patch):
        rej = repo / (f + ".rej")
        if rej.exists():
            rej_text.append(f"# ===== {f}.rej =====\n" + rej.read_text(encoding="utf-8", errors="replace"))
    _git(repo, "checkout", "--", ".")
    for f in patched_files(patch):
        rej = repo / (f + ".rej")
        if rej.exists():
            rej.unlink()
    return "\n\n".join(rej_text)


def _hunk_starts(patch: str) -> dict[str, list[tuple[int, int]]]:
    out: dict[str, list[tuple[int, int]]] = {}
    cur = None
    for ln in patch.splitlines():
        m = re.match(r"^\+\+\+ b/(\S+)", ln)
        if m:
            cur = m.group(1); out.setdefault(cur, []); continue
        m = re.match(r"^@@ -(\d+)(?:,(\d+))?", ln)
        if m and cur:
            out[cur].append((int(m.group(1)), int(m.group(2) or 1)))
    return out


def real_file_context(repo: Path, patch: str, window: int = 60, whole_if_le: int = 400) -> str:
    starts = _hunk_starts(patch)
    chunks = []
    for f in patched_files(patch):
        fp = repo / f
        if not fp.exists():
            chunks.append(f"# File does not exist in the target repository(the path or version may be wrong?): {f}")
            continue
        lines = fp.read_text(encoding="utf-8", errors="replace").splitlines()
        n = len(lines)
        if n <= whole_if_le or not starts.get(f):
            body = "\n".join(f"{i+1:>5}\t{ln}" for i, ln in enumerate(lines))
            chunks.append(f"# ===== Real file {f}(Total {n} , full text with line numbers)=====\n{body}")
            continue
        ranges = sorted((max(1, st - window), min(n, st + ln_ + window)) for st, ln_ in starts[f])
        merged = []
        for lo, hi in ranges:
            if merged and lo <= merged[-1][1] + 1:
                merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
            else:
                merged.append((lo, hi))
        segs = []
        for lo, hi in merged:
            seg = "\n".join(f"{i:>5}\t{lines[i-1]}" for i in range(lo, hi + 1))
            segs.append(f"# Lines  {lo}~{hi} : \n{seg}")
        chunks.append(f"# ===== Real file {f}(Total {n} , windowed around failed hunk hunk)=====\n"
                      + "\n   ...\n".join(segs))
    return "\n\n".join(chunks)





def make_client():
    from openai import OpenAI
    key = os.environ.get(DEEPSEEK_ENV)
    if not key:
        sys.exit(f"Error: Set the environment variable first {DEEPSEEK_ENV}")
    return OpenAI(api_key=key, base_url=DEEPSEEK_BASE_URL, timeout=600)


def llm_complete(client, messages: list[dict], reasoning_kwargs: dict):
    import time
    t0 = time.time()
    raw = client.with_raw_response.chat.completions.create(
        model=MODEL_ID, messages=messages, **reasoning_kwargs)
    elapsed = time.time() - t0
    raw_json_text = raw.text
    resp = raw.parse()
    if not resp.choices:
        raise RuntimeError(f"API response contains no choices(possible rate limiting/network/error object): {raw_json_text[:300]}")
    return (resp.choices[0].message.content or ""), raw_json_text, resp.usage, elapsed


def _cost_part(usage) -> str:
    ""
    if not usage:
        return "costN-A"
    cost = getattr(usage, "cost", None)
    if cost is None and getattr(usage, "model_extra", None):
        cost = usage.model_extra.get("cost")
    return f"cost{cost:.6f}" if cost is not None else "costN-A"


def save_round_json(raw_json_text: str, elapsed: float, usage, vul_name: str, workdir: Path) -> str:
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    tok = (f"p{usage.prompt_tokens}-c{usage.completion_tokens}-t{usage.total_tokens}"
           if usage else "tokenN-A")
    fname = f"{vul_name}-patch_{MODEL_ID}_{timestamp}_dur{elapsed:.1f}s_{tok}_{_cost_part(usage)}.json"
    (workdir / fname).write_text(raw_json_text, encoding="utf-8")
    return fname





def solve_vul(project: str, vul_name: str, repo: Path, max_retries: int,
              apply_final: bool, logs_root: Path) -> dict:
    workdir = logs_root / project / vul_name
    workdir.mkdir(parents=True, exist_ok=True)
    log = {"vul": vul_name, "project": project, "repo": str(repo), "model": MODEL_ID,
           "mode": MODE_LABEL, "read_rounds": [], "rounds": [], "status": None}

    desc, poc, addr = load_vul_meta(project, vul_name)
    tree, total, partial = build_tree_view(repo)
    print(f"  Target repository: {repo}({total}  files, directory{'depth-collapsed+ls for navigation if needed' if partial else 'fully expanded'})")
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": build_explore_intro(desc, poc, addr, tree, total, partial)},
    ]
    log["messages"] = messages
    client = make_client()

    
    pending_patch_reply = None
    for ex in range(MAX_READ_ROUNDS):
        print(f"  [{vul_name}] Read round  {ex}/{MAX_READ_ROUNDS-1}  round, requesting {MODEL_ID} ...")
        reply, raw_json, usage, elapsed = llm_complete(client, messages, REASONING_KWARGS)
        messages.append({"role": "assistant", "content": reply})
        saved = save_round_json(raw_json, elapsed, usage, vul_name, workdir)
        rr = {"round": ex, "llm_raw_json": saved, "llm_seconds": round(elapsed, 1)}

        if extract_diff_blocks(reply).strip():     
            pending_patch_reply = reply
            rr["note"] = "A patch, reuse it"
            log["read_rounds"].append(rr)
            print("           Model returned a patch during the reading phase patch")
            break

        reads, ls, done = parse_read_request(reply)
        rr.update({"requested_read": reads, "requested_ls": ls, "read_done": done})
        if not reads and not ls:
            rr["note"] = "READ_DONE no read/ls request -> Finish reading"
            log["read_rounds"].append(rr)
            print(f"           Finish reading(done={done}), start generation")
            break

        feedback, found, missing = build_read_result(repo, reads, ls, ex + 1)
        rr.update({"found": found, "missing": missing})
        log["read_rounds"].append(rr)
        print(f"           Read files {len(found)}  | List directories {len(ls)}  | Could not find {len(missing)} ")
        messages.append({"role": "user", "content": feedback})
    else:
        print(f"           Used all {MAX_READ_ROUNDS}  reading rounds, forcing generation")

    
    prev_patch = None
    for rnd in range(max_retries + 1):
        if rnd == 0 and pending_patch_reply is not None:
            reply = pending_patch_reply              
            saved = "(patch returned during a read round)"
            elapsed = 0.0
        else:
            if rnd == 0:
                messages.append({"role": "user", "content": build_generate_msg()})
            phase = "Generation" if rnd == 0 else f"Repair round {rnd} round"
            print(f"  [{vul_name}] {phase}, requesting {MODEL_ID}({MODE_LABEL})...")
            reply, raw_json, usage, elapsed = llm_complete(client, messages, REASONING_KWARGS)
            messages.append({"role": "assistant", "content": reply})
            saved = save_round_json(raw_json, elapsed, usage, vul_name, workdir)

        cur_patch = normalize_patch(reply)
        patch_path = workdir / f"attempt_{rnd}.patch"
        patch_path.write_text(cur_patch, encoding="utf-8")

        fmt_issues = precheck_format(cur_patch)
        ok, git_err, gate = ((False, "No diff", None) if not cur_patch.strip()
                             else apply_check(repo, patch_path))
        round_log = {"round": rnd, "phase": "Generation" if rnd == 0 else f"Repair round {rnd} round",
                     "llm_raw_json": saved, "llm_seconds": round(elapsed, 1),
                     "patch_file": str(patch_path), "format_issues": fmt_issues,
                     "apply_check_ok": ok, "passed_by": gate, "git_error": git_err}
        print(f"           apply --check -> {'OK ✅' if ok else 'FAIL ❌'}"
              + (f" | {git_err.splitlines()[0]}" if (not ok and git_err) else ""))

        if ok:
            log["status"] = "applied" if apply_final else "check_passed"
            log["gate"] = gate
            final_patch = workdir / f"{vul_name}.patch"
            final_patch.write_text(cur_patch, encoding="utf-8")
            log["winning_patch"] = str(patch_path)
            log["final_patch"] = str(final_patch)
            print(f"           ✅ passed, Saved final patch: {final_patch.name}")
            if apply_final:
                applied, err = do_apply(repo, patch_path)
                round_log["real_apply_ok"] = applied
                round_log["real_apply_error"] = err
                log["status"] = "applied" if applied else "apply_failed_after_check"
                print(f"           Apply changes -> {'OK ✅' if applied else 'FAIL ❌ ' + err}")
            log["rounds"].append(round_log)
            break

        rej = collect_rejects(repo, patch_path, cur_patch) if cur_patch.strip() else ""
        file_ctx = real_file_context(repo, cur_patch) if cur_patch.strip() else "(No diff, cannot locate files)"
        round_log["rej_present"] = bool(rej)
        log["rounds"].append(round_log)

        if rnd == max_retries:
            log["status"] = "exhausted"
            print(f"           Reached retry limit {max_retries}, giving up.")
            break
        if cur_patch.strip() and cur_patch.strip() == (prev_patch or "").strip():
            log["status"] = "no_progress"
            print("           New  patch matches the previous version, stopping.")
            break
        prev_patch = cur_patch
        messages.append({"role": "user",
                         "content": build_repair_user_msg(cur_patch, git_err, rej, file_ctx, fmt_issues)})

    (workdir / "run_log.json").write_text(json.dumps(log, ensure_ascii=False, indent=2), encoding="utf-8")
    return log


def is_done(project: str, vul_name: str, logs_root: Path) -> bool:
    ""
    return any((logs_root / project / vul_name).glob(f"{vul_name}-patch_*.json"))


def read_info_from_log(log: dict) -> tuple[int, list[str]]:
    ""
    rounds = log.get("read_rounds", [])
    files, seen = [], set()
    for rr in rounds:
        for f in rr.get("found", []):
            if f not in seen:
                seen.add(f); files.append(f)
    return len(rounds), files


def load_read_info(project: str, vul_name: str, logs_root: Path) -> tuple[int, list[str]]:
    ""
    p = logs_root / project / vul_name / "run_log.json"
    if not p.exists():
        return 0, []
    try:
        return read_info_from_log(json.loads(p.read_text(encoding="utf-8")))
    except Exception:
        return 0, []



def main():
    global MAX_READ_ROUNDS
    ap = argparse.ArgumentParser(
        description="text + Generation->apply->text text Agent(DeepSeek V4-Pro, read rounds 6 Project)")
    ap.add_argument("project", nargs="?", help=f"process only the specified project({'/'.join(REPOS)}); omit to process all")
    ap.add_argument("vul", nargs="?", help="with project, process one vulnerability in the project")
    ap.add_argument("--max-retries", type=int, default=5, help="maximum repair retries(default 5)")
    ap.add_argument("--max-read-rounds", type=int, default=MAX_READ_ROUNDS,
                    help=f"maximum source-reading rounds(default {MAX_READ_ROUNDS})")
    ap.add_argument("--apply", action="store_true", help="dry-run after a successful check, actually git apply(defaultonly --check)")
    ap.add_argument("--force", action="store_true", help="ignore previous-attempt records, force rerun")
    args = ap.parse_args()
    MAX_READ_ROUNDS = args.max_read_rounds

    repos = [args.project] if args.project else REPOS
    logs_root = Path(__file__).parent / "logs"

    print("=" * 70)
    print(f"Project: {', '.join(repos)}")
    print(f"Model: {MODEL_ID} ({MODE_LABEL}) | Read rounds: {MAX_READ_ROUNDS} | "
          f"text: {args.max_retries} | apply: {'yes' if args.apply else 'no'} | output: {logs_root}/<Project>/")
    print("=" * 70)

    
    results, skipped, api_failed = [], [], []
    for repo in repos:
        vuls = [args.vul] if args.vul else discover_vul_names(repo)
        print("\n" + "@" * 70)
        if not vuls:
            print(f"Project {repo}: No data(dataset/{repo}/ is missing or has no vulnerabilities), Skip")
            print("@" * 70)
            continue
        print(f"Project {repo}: Total {len(vuls)}  vulnerabilities")
        print("@" * 70)
        for idx, vul in enumerate(vuls, 1):
            print(f"\n#### [{repo}] [{idx}/{len(vuls)}] {vul} ####")
            if not args.force and is_done(repo, vul, logs_root):
                print(f"  ⏭️  already attempted(response json), Skip(--force text)")
                skipped.append(f"{repo}/{vul}")
                rr_n, files = load_read_info(repo, vul, logs_root)
                results.append({"project": repo, "vul": vul, "status": "skipped(done)",
                                "heal": 0, "read_rounds": rr_n, "files": files})
                continue
            try:
                repo_path = resolve_repo(repo, vul)
                log = solve_vul(repo, vul, repo_path, args.max_retries, args.apply, logs_root)
                rr_n, files = read_info_from_log(log)
                results.append({"project": repo, "vul": vul, "status": log["status"],
                                "heal": len(log["rounds"]), "read_rounds": rr_n, "files": files})
            except Exception as e:
                print(f"  ⚠️  response/Processing failed(will retry next time): {repo}/{vul} -> {type(e).__name__}: {e}")
                api_failed.append(f"{repo}/{vul}({type(e).__name__})")
                results.append({"project": repo, "vul": vul, "status": f"error:{type(e).__name__}",
                                "heal": 0, "read_rounds": 0, "files": []})

    ran = [r for r in results if r["status"] != "skipped(done)" and not r["status"].startswith("error:")]
    ok = sum(1 for r in results if r["status"] in SUCCESS_STATUS)

    
    lines = []
    lines.append("=" * 96)
    lines.append(f"{'Project/Vulnerability':30} {'Status':22} {'Read rounds':>6} {'Files read':>6} {'Repair rounds':>6}")
    lines.append("-" * 96)
    for r in results:
        lines.append(f"{r['project'] + '/' + r['vul']:30} {r['status']:22} "
                     f"{r['read_rounds']:>6} {len(r['files']):>6} {r['heal']:>6}")
    lines.append("=" * 96)
    lines.append("Reading details (files read for each vulnerability):")
    for r in results:
        if r["files"]:
            lines.append(f"  {r['project']}/{r['vul']}(text {r['read_rounds']}  round, Total {len(r['files'])}  files): ")
            lines.append("      " + ", ".join(r["files"]))
        elif r["status"] != "skipped(done)":
            lines.append(f"  {r['project']}/{r['vul']}(text {r['read_rounds']}  round, no files read)")
    lines.append("=" * 96)
    lines.append(f"All tasks completed | Processed this run {len(ran)}(including git apply passed {ok}) | "
                 f"Skip(already attempted) {len(skipped)} | requires retry(APIFailed) {len(api_failed)}")
    if api_failed:
        lines.append("Requires retry: " + ", ".join(api_failed))

    text = "\n".join(lines)
    print("\n" + text)

    logs_root.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    summary_path = logs_root / f"summary_{ts}.txt"
    summary_path.write_text(text + "\n", encoding="utf-8")
    print(f"\nSummary saved: {summary_path}")


if __name__ == "__main__":
    main()
