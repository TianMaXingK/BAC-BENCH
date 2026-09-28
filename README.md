# BAC-BENCH
We build \textsc{BAC-Bench}, a benchmark of 46 real-world BAC vulnerabilities drawn from six widely used web applications spanning four programming languages (Java, PHP, Go, and Python). Each vulnerability is equipped with a vulnerability description, a textual PoC description, the official patch, a sandboxed runtime environment, a PoC validation program, and a targeted functional test. We open-source it to facilitate research on BAC repair in web applications.


## Repository Structure

| Directory | Contents |
| --- | --- |
| [`benchmark/`](benchmark/) | Vulnerability artifacts, organized as `<application>/<vulnerability-id>/`. |
| [`scripts/`](scripts/) | Three example scripts for LLM-based repair, with and without lightweight scaffolds. |

## Benchmark Artifacts

Each benchmark case is organized around six artifacts. Five artifact types are hosted in this repository; the Docker sandbox environments are distributed separately because of their size.

| Artifact | File or location | Purpose |
| --- | --- | --- |
| Vulnerability description | `vul_information_base.txt` | Describes the vulnerability and its context. |
| Textual PoC description | `poc_natural_language.txt` | Describes the proof of concept in natural language. |
| Reference patch | `official.patch` | Provides the official patch for reference. |
| PoC validation program | `poc.py` | Checks the vulnerable behavior. |
| Functional test | `functional_test.py` | Checks relevant application functionality. |
| Docker sandbox | Google Drive, linked below | Provides the application environment and accompanying restoration assets. |


### Docker Sandboxes

**[Download the Docker sandbox environments from Google Drive](https://drive.google.com/drive/folders/1wiBH8wRQAf_eD08_lKLDJUADu4UBaJSF?usp=sharing).**

Download the environment corresponding to the selected benchmark case, together with its accompanying files. A sandbox may include multiple Docker images, database dumps, volume backups, configuration files, and a restoration script. Keep these files together and follow the instructions supplied with that environment; image files alone may not contain the database or volume data required by the application.

## Repair Scripts

**The scripts in the `/scripts` directory take DeepSeek as an example.** The model identifier and API configuration are defined in the scripts and can be adapted to the model being evaluated.

| Script | Setting |
| --- | --- |
| `base_llm_no_scaffold_deepseek.py` | Single-turn patch generation using vulnerability descriptions and supplied source files. |
| `base_llm_scaffold_1_deepseek.py` | Apply-Feedback: iteratively refines patches using patch-application feedback. |
| `base_llm_scaffold_2_deepseek.py` | Navigate-and-Locate with Apply-Feedback: allows repository browsing before patch generation and subsequent refinement. |

### Prerequisites

Use Python 3.10 or later and Git. From the repository root, install the Python dependency and configure your API key:

```bash
python3 -m pip install openai
export DEEPSEEK_API_KEY="YOUR_DEEPSEEK_API_KEY"
export BAC_DATASET_ROOT="$PWD/benchmark"
```

`BAC_DATASET_ROOT` must point to the directory containing `bookwyrm/`, `inlong/`, `nextcloud/`, `openemr/`, `usememos/`, and `xwiki/`. For this repository layout, explicitly set it to `benchmark/`: the scripts' built-in default points to the repository root.

### Prepare the Source Code

The current GitHub release contains the benchmark artifacts but **does not include the local source inputs required by the repair scripts**. Prepare these before running the examples:

1. For each case, create `patch-file-all/` inside its benchmark directory. Add `source_code_address_info.txt`, describing the source locations in the application. The no-scaffold and scaffold-1 scripts also read the vulnerable source files placed in this directory. Use the original vulnerable source, not the reference patch.
2. For scaffold-1 and scaffold-2, prepare full application source checkouts containing `.git` under `$BAC_DATASET_ROOT/cve-app-source/`. The paths must match `CVE_APP_SOURCE` and `REPO_MAP` near the top of each scaffold script, or these settings and the path-resolution logic must be adjusted to your local layout.

For example, the BookWyrm inputs are located at:

```text
$BAC_DATASET_ROOT/bookwyrm/BW-1/patch-file-all/source_code_address_info.txt
$BAC_DATASET_ROOT/bookwyrm/BW-1/patch-file-all/<vulnerable-source-files>
$BAC_DATASET_ROOT/cve-app-source/bookwyrm/<group>/bookwyrm-v0.4.3/.git/
```

`<group>` represents one intermediate directory chosen for your local source organization. The current resolver expects the following paths relative to `$BAC_DATASET_ROOT/cve-app-source/`:

| Application | Source checkout path |
| --- | --- |
| BookWyrm | `bookwyrm/<group>/bookwyrm-v0.4.3/` |
| InLong | `inlong/<group>/inlong-1.6.0-RC0/` |
| Memos | `usememos/<group>/memos-v0.8.3/` |
| OpenEMR | `openemr/<group>/openemr-v7_0_0/`; `openemr-v6_0_0/` for `cve-2022-1177` |
| XWiki | `xwiki/<group>/xwiki-platform-12.10.1/`; `xwiki-platform-13.1/` for `cve-2021-32731` |
| Nextcloud | `nextcloud/<vulnerability-id>/`, or a Git checkout immediately inside that directory |

Use dedicated, clean source checkouts. The scaffold scripts may temporarily apply rejected patches and run `git checkout -- .` while collecting feedback, even without `--apply`.

### Basic Usage

Run the following commands from the repository root **after preparing the source inputs above**. These are alternative evaluation settings; run them separately and archive the shared `scripts/logs/` directory between settings to avoid output collisions or unintended skips.

**Single-turn generation for BookWyrm:**

```bash
python3 scripts/base_llm_no_scaffold_deepseek.py bookwyrm
```

**Apply-Feedback for one BookWyrm case:**

```bash
python3 scripts/base_llm_scaffold_1_deepseek.py bookwyrm BW-1
```

**Navigate-and-Locate with Apply-Feedback for the same case:**

```bash
python3 scripts/base_llm_scaffold_2_deepseek.py bookwyrm BW-1
```

The no-scaffold script accepts an optional application name. Both scaffold scripts accept an optional application name followed by a vulnerability ID; omitting the vulnerability ID processes all discoverable cases for that application. Omitting all positional arguments processes all configured applications.

Outputs are written to `scripts/logs/`. The scaffold scripts check patch applicability by default; add `--apply` to apply the final patch after a successful check. Use `--help` with either scaffold script for additional options. A successful applicability check does not establish repair correctness: the case-specific PoC validation program and functional test provide separate dynamic checks.
