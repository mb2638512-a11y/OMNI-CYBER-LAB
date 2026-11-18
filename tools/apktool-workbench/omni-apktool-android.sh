#!/data/data/com.termux/files/usr/bin/bash
set -Eeuo pipefail
ROOT="/sdcard/Download/OMNI-APK-Workbench"
usage(){ cat <<'EOF'
OMNI CYBER LAB • On-device APK resource workbench (Termux)
  ./omni-apktool-android.sh setup
  ./omni-apktool-android.sh decode /sdcard/Download/OMNI-APK-Workbench/input.apk
  ./omni-apktool-android.sh build /sdcard/Download/OMNI-APK-Workbench/input-work
  ./omni-apktool-android.sh sign /path/rebuilt-aligned-unsigned.apk /path/owner-key.jks alias
Only use APKs you own or have written permission to modify.
EOF
}
need_cmd(){ command -v "$1" >/dev/null 2>&1 || { echo "MISSING: $1"; exit 2; }; }
check_arch(){ case "$(uname -m)" in aarch64|arm64) ;; *) echo "Requires Android ARM64 (aarch64)."; exit 2;; esac; }
setup(){
 check_arch
 pkg update
 pkg install -y openjdk-21 apktool aapt2 zipalign apksigner python
 termux-setup-storage
 mkdir -p "$ROOT"
 echo "SETUP COMPLETE • java/apktool/aapt2/zipalign/apksigner installed"
}
hash_file(){ sha256sum "$1"|awk '{print $1}'; }
decode(){
 local input="$1"
 [ -f "$input" ]||{ echo "Source APK not found: $input";exit 2; }
 need_cmd apktool;need_cmd aapt2
 local work="${input%.apk}-work"
 [ ! -e "$work" ]||{ echo "Workspace exists; choose another path.";exit 2; }
 local source_hash;source_hash="$(hash_file "$input")"
 apktool d -f --no-src -o "$work" "$input"
 mkdir -p "$work/.omni"
 printf '%s\n' "$input" > "$work/.omni/source-path.txt"
 printf '%s\n' "$source_hash" > "$work/.omni/source-sha256.txt"
 (cd "$work"&&find res assets -type f -print0 2>/dev/null|sort -z|xargs -0 -r sha256sum) > "$work/.omni/baseline-resources.sha256"
 apktool --version > "$work/.omni/apktool-version.txt"
 echo "DECODE PASS • $work"
 echo "Edit res/ and assets/. DEX is intentionally not disassembled or rebuilt."
}
build(){
 local work="$1"
 [ -f "$work/apktool.yml" ]||{ echo "Not an Apktool workspace.";exit 2; }
 [ -f "$work/.omni/source-path.txt" ]||{ echo "OMNI metadata missing.";exit 2; }
 local source;source="$(cat "$work/.omni/source-path.txt")"
 [ -f "$source" ]||{ echo "Original source APK missing.";exit 2; }
 local expected actual;expected="$(cat "$work/.omni/source-sha256.txt")";actual="$(hash_file "$source")"
 [ "$actual" = "$expected" ]||{ echo "FAIL • source APK hash changed since decode.";exit 3; }
 need_cmd apktool;need_cmd aapt2;need_cmd zipalign;need_cmd python
 local out="${work}-rebuilt-unsigned.apk";local aligned="${work}-rebuilt-aligned-unsigned.apk"
 [ ! -e "$out" ]&&[ ! -e "$aligned" ]||{ echo "Output exists; refusing overwrite.";exit 2; }
 apktool b --use-aapt2 -a "$(command -v aapt2)" "$work" -o "$out"
 zipalign -p -f 4 "$out" "$aligned"
 local out_hash;out_hash="$(hash_file "$aligned")"
 local added changed removed
 added="$(comm -13 <(awk '{print $2}' "$work/.omni/baseline-resources.sha256"|sort) <(cd "$work"&&find res assets -type f -print 2>/dev/null|sort))"
 changed="$( (cd "$work"&&find res assets -type f -print0 2>/dev/null|xargs -0 -r sha256sum)|while read -r hash path;do old="$(awk -v p="$path" '$2==p{print $1}' "$work/.omni/baseline-resources.sha256")";[ -n "$old" ]&&[ "$old" != "$hash" ]&&echo "$path";done )"
 removed="$(comm -23 <(awk '{print $2}' "$work/.omni/baseline-resources.sha256"|sort) <(cd "$work"&&find res assets -type f -print 2>/dev/null|sort))"
 python - "$source" "$aligned" "$expected" "$out_hash" "$added" "$changed" "$removed" <<'PY'
import json,sys,zipfile,os,datetime
source,out,src_hash,out_hash,added,changed,removed=sys.argv[1:]
with zipfile.ZipFile(out) as z:
 names=z.namelist()
 checks={"archive":"PASS","manifest":"PASS" if "AndroidManifest.xml" in names else "FAIL","resourceTable":"PASS" if "resources.arsc" in names else "FAIL","signature":"NOT TESTED • unsigned output","runtime":"NOT TESTED","install":"NOT TESTED"}
 counts={"entries":len(names),"resources":sum(x.startswith("res/") for x in names),"dex":sum(x.endswith(".dex") for x in names),"nativeLibraries":sum(x.startswith("lib/") and x.endswith(".so") for x in names)}
report={"product":"OMNI CYBER LAB on-device resource rebuild","generatedUtc":datetime.datetime.now(datetime.timezone.utc).isoformat(),"source":source,"sourceSha256":src_hash,"output":out,"outputSha256":out_hash,"checks":checks,"counts":counts,"resourceChanges":{"added":added.splitlines(),"changed":changed.splitlines(),"removed":removed.splitlines()},"result":"PASS" if checks["manifest"]=="PASS" and checks["resourceTable"]=="PASS" else "FAIL","limitations":["Archive build does not prove runtime correctness.","Signature is NOT TESTED: output is unsigned.","Install and functional tests remain NOT TESTED until performed."]}
base=os.path.dirname(out)
with open(os.path.join(base,"omni-ondevice-build-report.json"),"w") as f:json.dump(report,f,indent=2)
with open(os.path.join(base,"omni-ondevice-build-report.txt"),"w") as f:
 f.write("OMNI CYBER LAB • ON-DEVICE RESOURCE BUILD REPORT\nResult: "+report["result"]+"\nSource SHA-256: "+src_hash+"\nOutput SHA-256: "+out_hash+"\n")
 f.write("Checks: "+json.dumps(checks)+"\nCounts: "+json.dumps(counts)+"\nADDED:\n"+added+"\nCHANGED:\n"+changed+"\nREMOVED:\n"+removed+"\nRuntime/install: NOT TESTED unless separately performed.\n")
print("REPORTS WRITTEN • JSON + TXT")
print("SIGNATURE: NOT TESTED • unsigned output")
print("RUNTIME / INSTALL: NOT TESTED")
PY
 echo "BUILD COMPLETE • $aligned"
 echo "Source SHA-256: $expected"
 echo "Output SHA-256: $out_hash"
}
sign_apk(){
 local input="$1" key="$2" alias="$3"
 [ -f "$input" ]&&[ -f "$key" ]||{ echo "APK or keystore missing.";exit 2; }
 need_cmd apksigner
 local signed="${input%.apk}-signed.apk"
 [ ! -e "$signed" ]||{ echo "Signed output exists; refusing overwrite.";exit 2; }
 echo "Enter passwords interactively; never put keystore secrets in scripts or Git."
 apksigner sign --ks "$key" --ks-key-alias "$alias" --out "$signed" "$input"
 apksigner verify --verbose "$signed"
 echo "SIGNATURE PASS • $signed"
}
case "${1:-}" in
 setup) setup;;
 decode) [ $# -eq 2 ]||{ usage;exit 2; };check_arch;decode "$2";;
 build) [ $# -eq 2 ]||{ usage;exit 2; };check_arch;build "$2";;
 sign) [ $# -eq 4 ]||{ usage;exit 2; };sign_apk "$2" "$3" "$4";;
 *) usage;exit 2;;
esac
