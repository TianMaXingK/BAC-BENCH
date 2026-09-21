""

import os
import sys
import time
from datetime import datetime
from pathlib import Path

from openai import OpenAI



MODEL_ID = "deepseek-v4-pro"


# Override this portable default by setting BAC_DATASET_ROOT to your dataset directory.
DATASET_ROOT = Path(os.environ.get("BAC_DATASET_ROOT", Path(__file__).resolve().parents[1])).expanduser().resolve()
LOGS_DIR = Path(__file__).parent / "logs"


REPOS = ["usememos", "openemr", "inlong", "xwiki", "bookwyrm", "nextcloud"]

RGLOB_REPOS = {"usememos", "xwiki"}


DESC_FILE = "vul_information_base.txt"          
POC_FILE = "poc_natural_language.txt"           
PATCH_DIR = "patch-file-all"                    
ADDR_FILE = "source_code_address_info.txt"      

SYSTEM_PROMPT = (
    "You are a security expert specializing in fixing web application access-control vulnerabilities (broken access control)."
)


def load_vul_information(repo: str, vul_name: str) -> str:
    ""
    vul_dir = DATASET_ROOT / repo / vul_name
    vul_desc = (vul_dir / DESC_FILE).read_text(encoding="utf-8").strip()
    vul_poc = (vul_dir / POC_FILE).read_text(encoding="utf-8").strip()

    patch_dir = vul_dir / PATCH_DIR
    if not patch_dir.is_dir():
        raise FileNotFoundError(f"{vul_dir}  does not contain source directory: {PATCH_DIR}")

    addr_info = (patch_dir / ADDR_FILE).read_text(encoding="utf-8").strip()

    use_rglob = repo in RGLOB_REPOS
    files = sorted(patch_dir.rglob("*")) if use_rglob else sorted(patch_dir.iterdir())
    src_blocks = []
    for f in files:
        if not f.is_file() or f.name == ADDR_FILE:
            continue
        
        label = f.relative_to(patch_dir) if use_rglob else f.name
        code = f.read_text(encoding="utf-8")
        src_blocks.append(f"--- File: {label} ---\n```\n{code}\n```")
    src_text = "\n\n".join(src_blocks) if src_blocks else "(No source files found)"

    return (
        "[Vulnerability description]\n"
        f"{vul_desc}\n\n"
        "[Vulnerability PoC description]\n"
        f"{vul_poc}\n\n"
        "[Source locations in the project]\n"
        f"{addr_info}\n\n"
        "[Vulnerability-related source code]\n"
        f"{src_text}\n"
    )


def build_question(vul_context: str) -> str:
    ""
    return (
        "Read the vulnerability information and related source code below and complete two tasks:\n"
        "1. Analyze the root cause of the access-control vulnerability (broken access control).\n"
        "2. Provide a remediation and output the concrete source changes as a unified diff (patch)\n"
        "that preserves the original file paths and can be applied directly with git apply.\n\n"
        f"{vul_context}"
    )


def discover_vul_names(repo: str) -> list[str]:
    ""
    base = DATASET_ROOT / repo
    if not base.is_dir():
        return []
    return sorted(
        p.name for p in base.iterdir()
        if p.is_dir() and (p / PATCH_DIR).is_dir()
    )


def out_dir_of(repo: str) -> Path:
    ""
    return LOGS_DIR / repo


def already_done(repo: str, vul_name: str) -> bool:
    ""
    return any(out_dir_of(repo).glob(f"{vul_name}-patch_*.json"))


def main() -> None:
    api_key = os.environ.get("DEEPSEEK_API_KEY")
    if not api_key:
        sys.exit("Error: Set the environment variable first DEEPSEEK_API_KEY")

    
    repos = [sys.argv[1]] if len(sys.argv) > 1 else REPOS

    client = OpenAI(
        api_key=api_key,
        base_url="https://api.deepseek.com",
        timeout=600,   
    )

    
    skipped, failed = [], []
    for repo in repos:
        vuls = discover_vul_names(repo)
        print("\n" + "@" * 70)
        if not vuls:
            print(f"Repository {repo}: No data(directory is missing or contains no vulnerabilities), Skip")
            print("@" * 70)
            continue
        print(f"Repository {repo}: Total {len(vuls)}  vulnerabilities")
        print("@" * 70)
        for idx, vul_name in enumerate(vuls, start=1):
            print("\n" + "#" * 60)
            print(f"[{repo}] [{idx}/{len(vuls)}] Vulnerability: {vul_name}")
            print("#" * 60)
            if already_done(repo, vul_name):
                print(f"⏭️  result already exists, Skip: {repo}/{vul_name}")
                skipped.append(f"{repo}/{vul_name}")
                continue
            try:
                process_vul(client, repo, vul_name)
            except Exception as e:
                print(f"⚠️  Processing failed, Skip: {repo}/{vul_name} -> {type(e).__name__}: {e}")
                failed.append(f"{repo}/{vul_name}")
                continue

    print("\n" + "=" * 60)
    print(f"All tasks completed | Skipped (already completed) {len(skipped)} | Failed {len(failed)}")
    if failed:
        print("Failure list: " + ", ".join(failed))
    print("=" * 60)


def process_vul(client: OpenAI, repo: str, vul_name: str) -> None:
    ""
    vul_context = load_vul_information(repo, vul_name)
    question = build_question(vul_context)

    print("=" * 60)
    print(f"Model: {MODEL_ID}(Think Max: thinking enabled + reasoning_effort=max) | Repository: {repo}")
    print("=" * 60)
    print(f"\n[Question]\n{question}\n")

    t0 = time.time()
    raw = client.with_raw_response.chat.completions.create(
        model=MODEL_ID,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": question},
        ],
        reasoning_effort="max",
        extra_body={"thinking": {"type": "enabled"}},
    )
    elapsed = time.time() - t0

    raw_json_text = raw.text          
    response = raw.parse()

    
    
    if not response.choices:
        print("⚠️  Response does not contain choices, raw response follows(usually contains error information): ")
        print(raw_json_text)
        save_raw_json(raw_json_text, repo, vul_name, elapsed, getattr(response, "usage", None))
        return

    message = response.choices[0].message
    reasoning = getattr(message, "reasoning_content", None)
    answer = message.content

    if reasoning:
        print("-" * 60)
        print("[Reasoning reasoning_content]")
        print("-" * 60)
        print(reasoning)

    print("\n" + "-" * 60)
    print("[Final answer content]")
    print("-" * 60)
    print(answer)

    usage = response.usage
    print("\n" + "=" * 60)
    print(f"Elapsed: {elapsed:.1f}s")
    if usage:
        print(
            f"Token usage: prompt={usage.prompt_tokens}, "
            f"completion={usage.completion_tokens}, "
            f"total={usage.total_tokens}"
        )
    print("=" * 60)

    save_raw_json(raw_json_text, repo, vul_name, elapsed, usage)


def save_raw_json(raw_json_text: str, repo: str, vul_name: str, elapsed: float, usage) -> None:
    ""
    out_dir = out_dir_of(repo)
    out_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")

    if usage:
        tok_part = (
            f"p{usage.prompt_tokens}-c{usage.completion_tokens}-t{usage.total_tokens}"
        )
    else:
        tok_part = "tokenN-A"

    fname = f"{vul_name}-patch_{MODEL_ID}_{timestamp}_dur{elapsed:.1f}s_{tok_part}.json"
    out_path = out_dir / fname
    out_path.write_text(raw_json_text, encoding="utf-8")
    print(f"\nSaved raw JSON to: {out_path}")


if __name__ == "__main__":
    main()
