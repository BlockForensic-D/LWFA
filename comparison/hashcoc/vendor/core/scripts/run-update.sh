#!/usr/bin/env bash
# Deploy a new chaincode namespace on the existing network and run correction gates.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FABRIC="${LWFA_FABRIC_ROOT:-$HOME/2labforensic/fabric-samples}"
PREVIOUS="${LWFA_PREVIOUS_ROOT:-$FABRIC/lwfa-v0.5.0}"
TN="$FABRIC/test-network"
NAME=lwfaContractV051
export LWFA_FABRIC_ROOT="$FABRIC" LWFA_PREVIOUS_ROOT="$PREVIOUS" PATH="$FABRIC/bin:$PATH" FABRIC_LOGGING_SPEC=error
[[ "$ROOT" != "$PREVIOUS" && -d "$PREVIOUS/chaincode" && -x "$TN/network.sh" ]]
cd "$ROOT"
mkdir -p results/environment
LOG="$ROOT/results/update-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee "$LOG") 2>&1
trap 'rc=$?; printf "\nSTOP stage=%s line=%s exit=%s; retain %s\n" "${STAGE:-preflight}" "$LINENO" "$rc" "$ROOT/results" >&2; exit "$rc"' ERR
for cmd in node npm docker jq peer sha256sum tar; do command -v "$cmd" >/dev/null; done
STAGE=preserve-old-source-and-cases
capture_previous() {
 node - "$1" <<'NODE'
const {fs,path,sha,readJson,writeJson,same,ensure}=require('./client/io'),{FabricClient}=require('./client/fabric');
const old=process.env.LWFA_PREVIOUS_ROOT,files=['index.js','model.js','issues.js','state.js','LWFAContract.js','profiles.json','package.json','package-lock.json'];
const value={source:Object.fromEntries(files.map(f=>[f,sha(fs.readFileSync(path.join(old,'chaincode',f)))])),journals:{}};
for(const caseID of ['LWFA-RERUN-REGRESSION-005','LWFA-M3-001'])
 value.journals[caseID]=new FabricClient('IndependentReviewer',{name:'lwfaContractV05'}).query('ListCaseJournal',{caseID,afterSequence:0,limit:50});
const file='results/previous.before.json';
if(process.argv[2]==='before'&&!fs.existsSync(file))writeJson(file,value);
else ensure(same(readJson(file),value),'PREVIOUS_SOURCE_OR_CASES_CHANGED');
if(process.argv[2]==='after')writeJson('results/previous.after.json',value);
NODE
}
capture_previous before
STAGE=environment-and-local-tests
node release-check.js > results/release-before.json
IMAGE_ID="$(docker image inspect --format '{{.Id}}' "${LWFA_RUNNER_IMAGE:-hyperledger/fabric-nodeenv:2.5}")"
[[ "$IMAGE_ID" =~ ^sha256:[0-9a-f]{64}$ ]]
export LWFA_RUNNER_IMAGE="$IMAGE_ID"
printf '%s\n' "$IMAGE_ID" > results/environment/runner-image-id.txt
{ date -u +'%Y-%m-%dT%H:%M:%SZ'; node -v; npm -v; peer version; } > results/environment/host-versions.txt
docker ps --format '{{.Names}}\t{{.Image}}\t{{.Status}}' > results/environment/containers.tsv
docker run --rm --user "$(id -u):$(id -g)" --env HOME=/tmp --env npm_config_cache=/tmp/npm-cache --mount "type=bind,source=$ROOT,target=$ROOT" --workdir "$ROOT" --entrypoint /bin/sh "$IMAGE_ID" -ec '
 node -e '\''if(Number(process.versions.node.split(".")[0])!==22)process.exit(1)'\''
 npm ci --prefix chaincode --no-audit --no-fund > results/native-install.log 2>&1
 npm test > results/native-tests.tap 2>&1 || { tail -90 results/native-tests.tap; exit 1; }
 npm run metadata > results/native-metadata.log 2>&1
'
STAGE=parallel-chaincode-deployment
cd "$TN"
set +u; source scripts/envVar.sh; setGlobals 1; set -u
peer lifecycle chaincode querycommitted -C forensic-channel --output json > "$ROOT/results/channel-definitions.json"
FOUND="$(jq --arg name "$NAME" '[.chaincode_definitions[]? | select(.name==$name)] | length' "$ROOT/results/channel-definitions.json")"
SOURCE_ID="$(cd "$ROOT/chaincode"; sha256sum index.js model.js issues.js state.js LWFAContract.js profiles.json package.json package-lock.json | sha256sum | awk '{print $1}')"
MARKER="$ROOT/results/deployed-source.sha256"
if [[ "$FOUND" == 0 ]]; then
 ./network.sh deployCC -ccn "$NAME" -ccp "$ROOT/chaincode" -ccl javascript -ccv 0.5.1 -ccs 1 -c forensic-channel
 printf '%s\n' "$SOURCE_ID" > "$MARKER"
else
 [[ "$FOUND" == 1 && -s "$MARKER" && "$(cat "$MARKER")" == "$SOURCE_ID" ]] || { echo 'Existing V051 has no matching local source receipt; deployment stopped.' >&2; exit 1; }
fi
for org in 1 2 3; do
 set +u; setGlobals "$org"; set -u
 peer lifecycle chaincode querycommitted -C forensic-channel --name "$NAME" --output json > "$ROOT/results/definition-org$org.json"
 jq -e '.version=="0.5.1" and (.sequence|tonumber)==1' "$ROOT/results/definition-org$org.json" >/dev/null
done
STAGE=runtime-acceptance
cd "$ROOT"
node client/smoke.js
node client/m3-smoke.js
node client/audit-smoke.js
capture_previous after
node - <<'NODE'
const {readJson,writeJson,ensure}=require('./client/io');
const checks={m2:readJson('results/runtime-m2-regression-v0.5.1/summary.json'),
 m3:readJson('results/runtime-m3-v0.5.1/summary.json'),audit:readJson('results/runtime-audit-v0.5.1/summary.json')};
ensure(Object.values(checks).every(x=>x.result==='PASS'),'RUNTIME_ACCEPTANCE_FAILED');
writeJson('results/runtime-acceptance.json',{release:'0.5.1',chaincode:'lwfaContractV051',result:'PASS',
 classification:'CONTROLLED_RUNTIME_NOT_FINAL_RESEARCH',previousV05:'UNCHANGED',checks});
NODE
node release-check.js manifest
ARCHIVE="$ROOT/results/runtime-v0.5.1-$(date +%Y%m%d-%H%M%S).tar.gz"
tar -C "$ROOT/results" -czf "$ARCHIVE" runtime-m2-regression-v0.5.1 runtime-m3-v0.5.1 runtime-audit-v0.5.1 runtime-acceptance.json environment source-manifest.json previous.before.json previous.after.json native-tests.tap definition-org1.json definition-org2.json definition-org3.json
sha256sum "$ARCHIVE" > "$ARCHIVE.sha256"
printf '\nControlled update checks PASS. Archive: %s\n' "$ARCHIVE"
