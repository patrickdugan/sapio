#!/usr/bin/env bash
# Validate one genuine-regtest capture and publish its public proof:
# the JSON file, its SHA-256, ::notice annotations (served by the REST API
# without authentication) and the job step summary. Only public regtest
# facts leave the private capture directory.
set -euo pipefail
SCENARIO="$1" CAPTURE="$2" OUTPUT="$3"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

WRITER="$SCRIPT_DIR/write_public_proof.py"
if [[ "$SCENARIO" == "stale-race" ]]; then
    WRITER="$SCRIPT_DIR/write_stale_race_public_proof.py"
fi
python3 "$WRITER" "$CAPTURE" "$OUTPUT" \
    --scenario "$SCENARIO" \
    --revision sdk_revision=b45e5ef7b9c151cfc18f0efd9f4fee9327e1a29d \
    --revision tee_revision=f083bdbd2343aad22fab861f1565c0f2c2e6b0af \
    --revision bark_revision=626c9b241dd25d73212915d8fca959ab5e3b8f1f \
    --revision source_commit="$GITHUB_SHA" \
    --revision head_commit="${HEAD_COMMIT:-$GITHUB_SHA}" \
    --revision workflow_run="$GITHUB_SERVER_URL/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID"
sha256sum "$OUTPUT"
python3 - "$SCENARIO" "$OUTPUT" <<'PY'
import json, os, sys
scenario, path = sys.argv[1:]
text = open(path, encoding="utf-8").read()
compact = json.dumps(json.loads(text), sort_keys=True, separators=(",", ":"))
parts = [compact[i:i + 3500] for i in range(0, len(compact), 3500)]
for n, part in enumerate(parts, 1):
    print(f"::notice title=public-regtest-proof {scenario} {n}/{len(parts)}::"
          + part.replace("%", "%25"))
with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as out:
    out.write(f"## Public regtest proof: {scenario}\n\n```json\n{text}```\n")
PY
