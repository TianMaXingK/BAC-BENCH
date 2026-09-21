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



REASONING_KWARGS = {"reasoning_effort": "max", "extra_body": {"thinking": {"type": "enabled"}}}



SYSTEM_PROMPT = (
    "You are a security expert specializing in fixing web application access-control vulnerabilities (broken access control). "
    "When proposing a fix, output a unified diff patch and follow these requirements: "
    "(1) preserve real file paths and use a/ and b/ prefixes for git apply -p1; "
    "(2) unchanged context lines, indentation, and whitespace must match the supplied source exactly; "
    "(3) use numbered hunk headers such as `@@ -start,count +start,count @@`; "
    "(4) separate multiple files with independent diff --git headers and file headers; "
    "(5) put the final fix in exactly one ```diff code block."
)


SUCCESS_STATUS = ("check_passed", "applied")





_DIFF_LINE = re.compile(r"^(diff --git |--- |\+\+\+ |@@ |index )")


def _looks_like_diff(text: str) -> bool:
    return bool(re.search(r"^@@", text, re.M)) or "diff --git " in text or\
        (re.search(r"^--- ", text, re.M) and re.search(r"^\+\+\+ ", text, re.M))


def extract_diff_blocks(content: str) -> str:
    ""
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
    ""
    issues = []
    if not patch.strip():
        return ["Could not extract any diff(the model may not have produced a ```diff text)."]
    if not re.search(r"^--- ", patch, re.M) or not re.search(r"^\+\+\+ ", patch, re.M):
        issues.append("Missing '--- a/file' text '+++ b/file' file header.")
    hunks = re.findall(r"^@@.*$", patch, re.M)
    if not hunks:
        issues.append("No '@@' hunk header.")
    bare = [h for h in hunks if not re.match(r"^@@ -\d", h)]
    if bare:
        issues.append(f" {len(bare)}  hunk headerlack line-number ranges(bare '@@'), git will report "
                      f"'unrecognized input', must be written as '@@ -text,text +text,text @@'.")
    return issues





def discover_vul_names(project: str) -> list[str]:
    ""
    base = DATASET_ROOT / project
    if not base.is_dir():
        return []
    return sorted(p.name for p in base.iterdir()
                  if p.is_dir() and (p / PATCH_DIR).is_dir())


def _git_repo_in(base: Path) -> Path:
    ""
    if (base / ".git").is_dir():
        return base
    if base.is_dir():
        repos = sorted(d for d in base.iterdir() if d.is_dir() and (d / ".git").is_dir())
        if repos:
            return repos[0]
    raise FileNotFoundError(f"{base}  does not contain a repository with .git  repository directory")


def resolve_repo(project: str, vul_name: str) -> Path:
    ""
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


def load_vul_information(project: str, vul_name: str) -> str:
    ""
    vul_dir = DATASET_ROOT / project / vul_name
    vul_desc = (vul_dir / DESC_FILE).read_text(encoding="utf-8").strip()
    vul_poc = (vul_dir / POC_FILE).read_text(encoding="utf-8").strip()
    patch_dir = vul_dir / PATCH_DIR
    if not patch_dir.is_dir():
        raise FileNotFoundError(f"{vul_dir}  does not contain source directory: {PATCH_DIR}")
    addr_info = (patch_dir / ADDR_FILE).read_text(encoding="utf-8").strip()
    
    
    
    
    src_blocks = []
    for f in sorted(patch_dir.rglob("*")):
        if not f.is_file() or f.name == ADDR_FILE:
            continue
        rel = f.relative_to(patch_dir).as_posix()
        src_blocks.append(f"--- File: {rel} ---\n```\n{f.read_text(encoding='utf-8')}\n```")
    src_text = "\n\n".join(src_blocks) if src_blocks else "(No source files found)"
    return ("[Vulnerability description]\n" + vul_desc + "\n\n"
            "[Vulnerability PoC description]\n" + vul_poc + "\n\n"
            "[Source locations in the project]\n" + addr_info + "\n\n"
            "[Vulnerability-related source code]\n" + src_text + "\n")


def build_gen_question(vul_context: str) -> str:
    return (
        "Read the vulnerability information and related source code below and complete two tasks:\n"
        "1. Analyze the root cause of the access-control vulnerability (broken access control).\n"
        "2. Provide a remediation and output the concrete source changes as a unified diff patch "
        "that preserves the original file paths and can be applied directly with git apply.\n\n"
        + vul_context
    )


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True)


def apply_check(repo: Path, patch_path: Path) -> tuple[bool, str, str | None]:
    ""
    cp1 = _git(repo, "apply", "-p1", "--check", str(patch_path))
    if cp1.returncode == 0:
        return True, "", "git apply --check"
    cp2 = _git(repo, "apply", "--recount", "-p1", "--check", str(patch_path))
    if cp2.returncode == 0:
        return True, "", "git apply --recount --check"
    return False, (cp1.stderr or cp1.stdout).strip(), None


def do_apply(repo: Path, patch_path: Path) -> tuple[bool, str]:
    ""
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
    ""
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
    ""
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
    ""
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
    ""
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


def save_round_json(raw_json_text: str, elapsed: float, usage, vul_name: str,
                    workdir: Path) -> str:
    ""
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    tok = (f"p{usage.prompt_tokens}-c{usage.completion_tokens}-t{usage.total_tokens}"
           if usage else "tokenN-A")
    fname = f"{vul_name}-patch_{MODEL_ID}_{timestamp}_dur{elapsed:.1f}s_{tok}.json"
    (workdir / fname).write_text(raw_json_text, encoding="utf-8")
    return fname


def build_repair_user_msg(patch: str, git_err: str, rej: str, file_ctx: str,
                          fmt_issues: list[str]) -> str:
    parts = ["Your previous patch could not be applied, Use the following information to generate a correct unified diff.\n"]
    if fmt_issues:
        parts.append("[Format precheck errors]\n- " + "\n- ".join(fmt_issues) + "\n")
    parts.append("[git apply --recount --check error output]\n" + (git_err or "(No stderr)") + "\n")
    if rej:
        parts.append("[Failed hunk(.rej, this context did not match the real file)]\n" + rej + "\n")
    parts.append("[Current target file contents--align context to this content]\n" + file_ctx + "\n")
    parts.append("[Your previous rejected patch]\n```diff\n" + (patch or "(empty)") + "\n```\n")
    parts.append("Output only one corrected ```diff code block.")
    return "\n".join(parts)





def solve_vul(project: str, vul_name: str, repo: Path, max_retries: int,
              apply_final: bool, logs_root: Path) -> dict:
    workdir = logs_root / project / vul_name
    workdir.mkdir(parents=True, exist_ok=True)         
    log = {"vul": vul_name, "project": project, "repo": str(repo),
           "model": MODEL_ID, "mode": "Think Max", "rounds": [], "status": None}

    vul_context = load_vul_information(project, vul_name)
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": build_gen_question(vul_context)},  
    ]
    log["messages"] = messages
    client = make_client()

    prev_patch = None
    for rnd in range(max_retries + 1):
        phase = "Generation" if rnd == 0 else f"Repair round {rnd} round"
        print(f"  [{vul_name}] round {rnd}({phase})requesting {MODEL_ID}(Think Max)...")
        reply, raw_json, usage, elapsed = llm_complete(client, messages, REASONING_KWARGS)
        
        
        
        
        
        messages.append({"role": "assistant", "content": reply})
        saved = save_round_json(raw_json, elapsed, usage, vul_name, workdir)

        cur_patch = normalize_patch(reply)
        patch_path = workdir / f"attempt_{rnd}.patch"
        patch_path.write_text(cur_patch, encoding="utf-8")

        fmt_issues = precheck_format(cur_patch)
        ok, git_err, gate = ((False, "No diff", None) if not cur_patch.strip()
                             else apply_check(repo, patch_path))
        round_log = {"round": rnd, "phase": phase, "llm_raw_json": saved,
                     "llm_seconds": round(elapsed, 1), "patch_file": str(patch_path),
                     "format_issues": fmt_issues, "apply_check_ok": ok,
                     "passed_by": gate, "git_error": git_err}
        print(f"           apply --recount --check -> {'OK ✅' if ok else 'FAIL ❌'}"
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

    (workdir / "run_log.json").write_text(json.dumps(log, ensure_ascii=False, indent=2),
                                          encoding="utf-8")
    return log


def is_done(project: str, vul_name: str, logs_root: Path) -> bool:
    ""
    return any((logs_root / project / vul_name).glob(f"{vul_name}-patch_*.json"))



def main():
    ap = argparse.ArgumentParser(
        description="Generation->apply->text Agent(read rounds 6 Project)")
    ap.add_argument("project", nargs="?",
                    help=f"process only the specified project({'/'.join(REPOS)}); read rounds 6 ")
    ap.add_argument("vul", nargs="?", help="with project, process one vulnerability in the project")
    ap.add_argument("--max-retries", type=int, default=5, help="maximum repair retries(default 5)")
    ap.add_argument("--apply", action="store_true", help="dry-run after a successful check, actually git apply(defaultonly --check)")
    ap.add_argument("--force", action="store_true", help="text, force rerun")
    args = ap.parse_args()

    repos = [args.project] if args.project else REPOS
    logs_root = Path(__file__).parent / "logs"

    print("=" * 70)
    print(f"Project: {', '.join(repos)}")
    print(f"Model: {MODEL_ID}(Think Max) | max_retries: {args.max_retries} | "
          f"apply: {'yes' if args.apply else 'no(text --check)'} | output: {logs_root}/<Project>/")
    print("=" * 70)

    
    
    results = []                       
    skipped, api_failed = [], []       
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
                print(f"  ⏭️  already attempted( run_log), Skip(--force text)")
                skipped.append(f"{repo}/{vul}")
                results.append((repo, vul, "skipped(done)", 0))
                continue
            try:
                repo_path = resolve_repo(repo, vul)        
                print(f"  Target repository: {repo_path}")
                log = solve_vul(repo, vul, repo_path, args.max_retries, args.apply, logs_root)
                
                results.append((repo, vul, log["status"], len(log["rounds"])))
            except Exception as e:
                
                print(f"  ⚠️  response/Processing failed(will retry next time): {repo}/{vul} -> {type(e).__name__}: {e}")
                api_failed.append(f"{repo}/{vul}({type(e).__name__})")
                results.append((repo, vul, f"error:{type(e).__name__}", 0))

    
    ran = [r for r in results if r[2] != "skipped(done)" and not r[2].startswith("error:")]
    ok = sum(1 for _, _, st, _ in results if st in SUCCESS_STATUS)
    print("\n" + "=" * 70)
    print(f"{'Project/Vulnerability':34} {'Status':24} {'Repair rounds':>13}")
    print("-" * 70)
    for repo, vul, st, n in results:
        print(f"{repo + '/' + vul:34} {st:24} {n}")
    print("=" * 70)
    print(f"All tasks completed | Processed this run {len(ran)}(including git apply passed {ok}) | "
          f"Skip(already attempted) {len(skipped)} | requires retry(APIFailed) {len(api_failed)}")
    if api_failed:
        print("Requires retry (API failure; already attempted items are skipped): " + ", ".join(api_failed))
    print("=" * 70)


if __name__ == "__main__":
    main()
