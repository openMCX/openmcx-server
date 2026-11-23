#!/usr/bin/env bash
#
# OpenMCX Licence Information : AGPL-3.0-or-later
#
# The reSIProcate prototype's SIP over TLS with OpenMCX's TLS profile (prototype/resiprocate/README.md), on loopback
# in the development image, judged by the regression's own rules (tests/integration/tls_profile_check.py: its
# refused handshakes and its allowed suites and groups):
#   1. mutual TLS: a call to a TLS listener that requires a client certificate gets its 200;
#   2. the listener refuses RSA key exchange, CBC, DHE, ffdhe and TLS 1.1 (TS 33.210 clause 6.2);
#   3. the listener refuses a client without a certificate (TS 33.180 clause 6.1);
#   4. the client's ClientHello (seen by openssl s_server -trace) offers only the profile's suites and groups;
#   5. the client refuses a server whose certificate another CA issued.
#
#   prototype/resiprocate/run-tls-probe.sh        (MCX_DEV_IMAGE picks the development image, default openmcx-dev:0.5)
set -euo pipefail
cd "$(dirname "$0")/../.."
dev_image=${MCX_DEV_IMAGE:-openmcx-dev:0.5}
work=.cache/resip-prototype
mkdir -p "$work"
docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -v "$PWD:/workspace" -w /workspace "$dev_image" bash -c '
set -euo pipefail
work='"$work"'
prefix=/opt/resiprocate
[ -f $prefix/include/resip/dum/DialogUsageManager.hxx ] || prefix=/workspace/$work/resiprocate
cmake -S . -B $work/build -DCMAKE_PREFIX_PATH=$prefix > /dev/null
cmake --build $work/build -j8 --target tls_probe > $work/tls-probe-build.log 2>&1
probe=$work/build/tls_probe
certs=$(mktemp -d)
trap "kill \$(jobs -p) 2>/dev/null || true" EXIT

# Certificates: a CA, the listener (localhost), the client (bob), and a server of another CA (rogue).
make_ca() { openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$1" -days 2 \
  -keyout $certs/$1.key -out $certs/$1.pem 2>/dev/null; }
make_cert() {
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$1" -keyout $certs/$1.key \
    -out $certs/$1.csr 2>/dev/null
  printf "subjectAltName=DNS:localhost,DNS:%s\nextendedKeyUsage=serverAuth,clientAuth\n" $1 > $certs/$1.ext
  openssl x509 -req -in $certs/$1.csr -CA $certs/$2.pem -CAkey $certs/$2.key -CAcreateserial -days 2 \
    -extfile $certs/$1.ext -out $certs/$1.pem 2>/dev/null
}
make_ca ca; make_ca otherca; make_cert alice ca; make_cert bob ca; make_cert rogue otherca
mkdir -p $certs/rogue-dir && cp $certs/otherca.pem $certs/rogue-dir/ca.pem && cp $certs/rogue.pem $certs/rogue.key $certs/rogue-dir/

failures=0
check() { if [ "$1" = 0 ]; then echo "  ok   $2"; else echo "  FAIL $2"; failures=$((failures + 1)); fi; }
handshake() { # whether the listener answers a ClientHello with a ServerHello
  timeout 5 openssl s_client -connect 127.0.0.1:$1 -msg "${@:2}" </dev/null 2>&1 | grep -c ServerHello || true; }

$probe serve --certs $certs --name alice --port 15071 --seconds 60 > $work/tls-serve.log 2>&1 &
sleep 1
echo "1. mutual TLS"
$probe call --certs $certs --name bob --target "sip:alice@localhost:15071;transport=tls" > $work/tls-call.log 2>&1
check $? "a call over TLS with a client certificate gets 200 ($(tail -1 $work/tls-call.log))"

echo "2. the listener refuses what TS 33.210 clause 6.2 forbids"
python3 - <<EOF > $work/tls-refused.txt
import sys; sys.path.insert(0, "tests/integration")
from tls_profile_check import GOOD, REFUSED
print("GOOD|-tls1_2 -cipher " + GOOD)
for name, options in REFUSED: print(name + "|" + " ".join(options))
EOF
while IFS="|" read -r name options; do
  answered=$(handshake 15071 $options -cert $certs/bob.pem -key $certs/bob.key)
  if [ "$name" = GOOD ]; then check $([ "$answered" != 0 ]; echo $?) "the profile suites are accepted";
  else check $([ "$answered" = 0 ]; echo $?) "refused: $name"; fi
done < $work/tls-refused.txt

echo "3. the listener requires a client certificate"
without=$(timeout 5 openssl s_client -connect 127.0.0.1:15071 -tls1_3 -ign_eof </dev/null 2>&1 | grep -ci "alert certificate required\|alert handshake failure" || true)
check $([ "$without" != 0 ]; echo $?) "a client without a certificate is refused (TLS alert)"

echo "4. the client offers only the profile (TLS 1.3 and TLS 1.2 ECDHE AEAD suites, the allowed groups)"
# s_server stops at the end of its input: it is kept open.
sleep 20 | timeout 20 openssl s_server -accept 15072 -cert $certs/alice.pem -key $certs/alice.key -CAfile $certs/ca.pem \
  -Verify 1 -trace > $work/tls-hello.log 2>&1 &
sleep 1
$probe call --certs $certs --name bob --target "sip:alice@localhost:15072;transport=tls" > /dev/null 2>&1 || true
sleep 1
python3 - <<EOF
import re, sys; sys.path.insert(0, "tests/integration")
from tls_profile_check import TLS12, TLS13, SCSV, GROUPS
text = open("$work/tls-hello.log").read()
hello = text[text.index("ClientHello"):]
suites_text = hello[hello.index("cipher_suites"):hello.index("compression_methods")]
suites = {int(a, 16) << 8 | int(b, 16) for a, b in re.findall(r"\{0x([0-9A-Fa-f]{2}), 0x([0-9A-Fa-f]{2})\}", suites_text)}
groups_text = hello[hello.index("supported_groups"):]
groups_text = groups_text[:groups_text.find("extension_type", 10)]
groups = {int(value) for value in re.findall(r"\((\d+)\)\s*$", groups_text, re.M)} - {10}
bad_suites, bad_groups = suites - TLS12 - TLS13 - SCSV, groups - GROUPS
print(f"  offered {len(suites)} suites {sorted(hex(s) for s in suites)}, groups {sorted(groups)}")
print(("  ok   " if suites and not bad_suites and not bad_groups else "  FAIL ")
      + f"the ClientHello offers nothing outside the profile (bad suites {sorted(hex(s) for s in bad_suites)}, bad groups {sorted(bad_groups)})")
sys.exit(0 if suites and not bad_suites and not bad_groups else 1)
EOF
check $? "ClientHello within TS 33.210 clause 6.2"

echo "5. the client verifies the server"
$probe serve --certs $certs/rogue-dir --name rogue --port 15073 --seconds 20 > $work/tls-rogue.log 2>&1 &
sleep 1
$probe call --certs $certs --name bob --target "sip:alice@localhost:15073;transport=tls" > $work/tls-rogue-call.log 2>&1 && rogue=0 || rogue=1
check $([ "$rogue" = 1 ]; echo $?) "a server whose certificate another CA issued is refused ($(tail -1 $work/tls-rogue-call.log))"

echo "$( [ $failures = 0 ] && echo PASS || echo FAIL ): SIP over TLS with the TLS profile on reSIProcate, $failures failed checks"
exit $failures
'
