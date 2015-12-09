#!/bin/bash

bin=$(basename "$0")
usage() {
	echo >&2 "Usage: $bin { -x | -xx }"
	echo >&2 "Usage: $bin { -h | --help }"
	echo >&2
	echo >&2 "Run tests for ghg binary in the same dir."
	echo >&2 "Specify -x option to actually start these, -xx for verbose mode."
	exit "${1:-1}"
}
[[ "$1" = -h || "$1" = --help ]] && usage 0
[[ -n "$1" && -z "$2" ]] || usage
[[ "$1" = -x || "$1" = -xx ]] || usage
[[ "$1" = -xx ]] && debug=t || debug=


set -e -o pipefail
[[ -z "$debug" ]] || set -x
tmp=$(mktemp -d /tmp/.ghg-test.XXXXXX)
[[ -n "$debug" ]] || trap "rm -rf '$tmp'" EXIT

cat >"$tmp"/ghg.yaml <<EOF
core:
  key: mykey
keys:
  mykey: $(./ghg -g)
  key-2: $(./ghg -g)
  key-3: $(./ghg -g)
EOF
ghg="./ghg -c $tmp/ghg.yaml"

sha256() { chk=$(sha256sum -b "$1" | cut -d\  -f1); echo "$chk"; }
die() { echo >&2 "Test FAILED, run with -xx to see how exactly"; exit 1; }



echo "-- test: simple"

p="$tmp"/file.3M
dd if=/dev/urandom of="$p" bs=3M count=1 status=none

$ghg <"$p" >"$p".1.ghg
$ghg -e <"$p" >"$p".2.ghg
cp "$p" "$p".3
$ghg "$p".3
cp "$p" "$p".4
$ghg -e "$p".4
cat "$p" | $ghg -e >"$p".5.ghg

$ghg -s <"$p" >"$p".stable1.ghg
$ghg -s <"$p" >"$p".stable2.ghg
cat "$p" | $ghg -s >"$p".stable3.ghg

sha256 "$p".1.ghg >"$p".chk
sha256 "$p".2.ghg >>"$p".chk
sha256 "$p".stable1.ghg >>"$p".chk
[[ "$(sort -u "$p".chk | wc -l)" -eq 3 && "$(wc -l <"$p".chk)" -eq 3 ]] || { cat "$p".chk; die; }

$ghg <"$p".1.ghg >"$p".1
$ghg -d <"$p".2.ghg >"$p".2
$ghg "$p".3.ghg
$ghg -d "$p".4.ghg
cat "$p".5.ghg | $ghg >"$p".5
cat "$p".5.ghg | $ghg -d >"$p".6

sha256 "$p" >"$p".chk
for n in 1 2 3 4 5 6; do sha256 "$p"."$n" >>"$p".chk; done
[[ "$(sort -u "$p".chk | wc -l)" -eq 1 && "$(wc -l <"$p".chk)" -eq 7 ]] || { cat "$p".chk; die; }

$ghg -so "$p".6 >"$p".stable4.ghg
if [[ -e "$p".6.ghg ]]; then die; fi
$ghg -od "$p".stable4.ghg >"$p".6x

: >"$p".chk
for pn in "$p".stable*.ghg; do sha256 "$pn" >>"$p".chk; done
[[ "$(sort -u "$p".chk | wc -l)" -eq 1 && "$(wc -l <"$p".chk)" -eq 4 ]] || { cat "$p".chk; die; }

$ghg "$p".stable1.ghg
$ghg "$p".stable3.ghg
$ghg "$p".stable4.ghg

sha256 "$p" >"$p".chk
sha256 "$p".stable1 >>"$p".chk
sha256 "$p".stable3 >>"$p".chk
sha256 "$p".6x >>"$p".chk
sha256 "$p".stable4 >>"$p".chk
[[ "$(sort -u "$p".chk | wc -l)" -eq 1 && "$(wc -l <"$p".chk)" -eq 5 ]] || { cat "$p".chk; die; }

if [[ -e "$p".7 ]]; then die; fi
echo xxx >"$p".7.ghg
cat "$p".5.ghg >>"$p".7.ghg
if $ghg -d "$p".7.ghg 2>/dev/null; then die; fi
if [[ -e "$p".7 ]]; then die; fi

echo -n xxx >"$p".7.ghg
cat "$p".5.ghg >>"$p".7.ghg
if $ghg -d "$p".7.ghg 2>/dev/null; then die; fi
if [[ -e "$p".7 ]]; then die; fi

dd if="$p".5.ghg of="$p".7.ghg bs=1M count=1 status=none
if $ghg -d "$p".7.ghg 2>/dev/null; then die; fi
if [[ -e "$p".7 ]]; then die; fi

dd if=/dev/urandom of="$p".5.ghg bs=16 seek=100 count=1 status=none
if $ghg -d "$p".5.ghg 2>/dev/null; then die; fi



echo "-- test: small"

p="$tmp"/file.test
v="asdf678-+"
echo "$v" >"$p"

$ghg <"$p" >"$p".1.ghg
$ghg -s <"$p" >"$p".stable.ghg

if grep -qF "$v" "$p".1.ghg; then die; fi
$ghg "$p".1.ghg
if grep -qF "$v" "$p".stable.ghg; then die; fi
$ghg "$p".stable.ghg

sha256 "$p" >"$p".chk
sha256 "$p".1 >>"$p".chk
sha256 "$p".stable >>"$p".chk
[[ "$(sort -u "$p".chk | wc -l)" -eq 1 && "$(wc -l <"$p".chk)" -eq 3 ]] || { cat "$p".chk; die; }

: >"$p"
if [[ -s "$p" ]]; then die; fi
$ghg "$p"
[[ -s "$p".ghg ]] || die
$ghg "$p".ghg
if [[ -s "$p" ]]; then die; fi



echo "-- test: multikey"

p="$tmp"/file.multi
dd if=/dev/urandom of="$p" bs=300 count=1 status=none

$ghg -so -r $($ghg -p) "$p" >"$p".stable1.ghg
$ghg -so -r $($ghg -p mykey) "$p" >"$p".stable2.ghg
$ghg -so -r mykey "$p" >"$p".stable3.ghg

: >"$p".chk
for pn in "$p".stable*.ghg; do sha256 "$pn" >>"$p".chk; done
[[ "$(sort -u "$p".chk | wc -l)" -eq 1 && "$(wc -l <"$p".chk)" -eq 3 ]] || { cat "$p".chk; die; }

$ghg -so -r key-2 "$p" >"$p".k2-1.ghg
$ghg -so -k key-2 "$p" >"$p".k2-2.ghg
$ghg -so -k key-3 -r key-2 "$p" >"$p".k2-3.ghg

sha256 "$p" >"$p".chk
sha256 "$p".stable1.ghg >>"$p".chk
sha256 "$p".k2-1.ghg >>"$p".chk
sha256 "$p".k2-2.ghg >>"$p".chk
sha256 "$p".k2-3.ghg >>"$p".chk
[[ "$(sort -u "$p".chk | wc -l)" -eq 5 && "$(wc -l <"$p".chk)" -eq 5 ]] || { cat "$p".chk; die; }

$ghg -d "$p".k2-1.ghg
$ghg -d "$p".k2-2.ghg
$ghg -d "$p".k2-3.ghg
$ghg -d "$p".stable1.ghg

sha256 "$p" >"$p".chk
sha256 "$p".k2-1 >>"$p".chk
sha256 "$p".k2-2 >>"$p".chk
sha256 "$p".k2-3 >>"$p".chk
sha256 "$p".stable1 >>"$p".chk
[[ "$(sort -u "$p".chk | wc -l)" -eq 1 && "$(wc -l <"$p".chk)" -eq 5 ]] || { cat "$p".chk; die; }

$ghg -r pub64-DZqKsImH_Rizt38ariDw-jD-E9pXFbNQ38aoyKIIn2k= -r key-3 <"$p" >"$p".k2-1.ghg
$ghg -k key-2 -r pub64-mIkC20NfVcFLgKJ5bm5ck93BB55R0XjXTElbtKZ6zSs= -r key-3 <"$p" >"$p".k2-2.ghg
$ghg -r mykey -r pub64-DZqKsImH_Rizt38ariDw-jD-E9pXFbNQ38aoyKIIn2k= <"$p" >"$p".k2-3.ghg
$ghg -d "$p".k2-1.ghg
$ghg -d "$p".k2-2.ghg
$ghg -d "$p".k2-3.ghg

sha256 "$p" >"$p".chk
sha256 "$p".k2-1 >>"$p".chk
sha256 "$p".k2-2 >>"$p".chk
sha256 "$p".k2-3 >>"$p".chk
[[ "$(sort -u "$p".chk | wc -l)" -eq 1 && "$(wc -l <"$p".chk)" -eq 4 ]] || { cat "$p".chk; die; }

$ghg -r pub64-DZqKsImH_Rizt38ariDw-jD-E9pXFbNQ38aoyKIIn2k= -r pub64-mIkC20NfVcFLgKJ5bm5ck93BB55R0XjXTElbtKZ6zSs= <"$p" >"$p".k2-1.ghg
$ghg -k key-2 -r pub64-DZqKsImH_Rizt38ariDw-jD-E9pXFbNQ38aoyKIIn2k= <"$p" >"$p".k2-2.ghg
rm "$p".k2-1
if $ghg -d "$p".k2-1.ghg 2>/dev/null; then die; fi
if [[ -e "$p".k2-1 ]]; then die; fi
rm "$p".k2-2
if $ghg -d "$p".k2-2.ghg 2>/dev/null; then die; fi
if [[ -e "$p".k2-2 ]]; then die; fi



echo "-- test: 20M"

p="$tmp"/file.20M
dd if=/dev/urandom of="$p" bs=20M count=1 status=none

$ghg <"$p" >"$p".1.ghg
$ghg -s <"$p" >"$p".stable1.ghg
$ghg -s <"$p" >"$p".stable2.ghg
if cat "$p" | $ghg -s >"$p".stable3.ghg 2>/dev/null; then die; fi

sha256 "$p".1.ghg >"$p".chk
sha256 "$p".stable1.ghg >>"$p".chk
[[ "$(sort -u "$p".chk | wc -l)" -eq 2 && "$(wc -l <"$p".chk)" -eq 2 ]] || { cat "$p".chk; die; }

sha256 "$p".stable1.ghg >"$p".chk
sha256 "$p".stable2.ghg >>"$p".chk
[[ "$(sort -u "$p".chk | wc -l)" -eq 1 && "$(wc -l <"$p".chk)" -eq 2 ]] || { cat "$p".chk; die; }

echo xxx >"$p".1
echo xxx >>"$p".1.ghg
cat "$p".1.ghg | $ghg >"$p".1
$ghg "$p".stable1.ghg
$ghg -d "$p".stable2.ghg
if $ghg -d "$p".stable3.ghg 2>/dev/null; then die; fi

sha256 "$p".1 >"$p".chk
sha256 "$p".stable1 >>"$p".chk
sha256 "$p".stable2 >>"$p".chk
[[ "$(sort -u "$p".chk | wc -l)" -eq 1 && "$(wc -l <"$p".chk)" -eq 3 ]] || { cat "$p".chk; die; }

dd if=/dev/urandom of="$p".1.ghg bs=16 seek=500 count=1 status=none
if $ghg -d "$p".1.ghg 2>/dev/null; then die; fi
