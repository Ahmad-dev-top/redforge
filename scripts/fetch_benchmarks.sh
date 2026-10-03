#!/usr/bin/env bash
# Clone the three corpora registered in src/redforge/eval/datasets.py into
# benchmarks/<name>/. Shallow and idempotent: a repo that already has .git
# is left untouched. Re-run after deleting a directory to refresh it.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST_ROOT="${ROOT}/benchmarks"
mkdir -p "${DEST_ROOT}"

clone_dataset() {
  local name="$1"
  local url="$2"
  local dest="${DEST_ROOT}/${name}"

  if [[ -d "${dest}/.git" ]]; then
    echo "skip ${name}: already cloned at ${dest}"
    return 0
  fi
  if [[ -e "${dest}" ]]; then
    echo "error: ${dest} exists but is not a git clone" >&2
    exit 1
  fi
  echo "cloning ${name} -> ${dest}"
  git clone --depth 1 --no-recurse-submodules "${url}" "${dest}"
}

# Names and URLs match DATASETS in eval/datasets.py. Subdirs are read by the
# loader; this script only clones the repo roots.
clone_dataset "smartbugs-curated" "https://github.com/smartbugs/smartbugs-curated"
clone_dataset "damn-vulnerable-defi" "https://github.com/theredguild/damn-vulnerable-defi"
clone_dataset "ethernaut" "https://github.com/OpenZeppelin/ethernaut"

echo "benchmarks ready in ${DEST_ROOT}"
