#!/bin/bash
#
# tmOrion -- trigger network detections on a deployed Suricata/Zeek sensor.
# Modelled on tmNIDS (github.com/0xtf/testmynids.org).
#
# Run it from a host INSIDE the network the sensor is watching. Each test
# generates one piece of ordinary-looking traffic that a stock Emerging Threats
# ruleset alerts on. Nothing malicious runs, nothing is installed, nothing is
# written outside /tmp.
#
#   ./tmOrion.sh          menu
#   ./tmOrion.sh -1       run test 1
#   ./tmOrion.sh -99      run everything
#   ./tmOrion.sh -l       list tests
#
# Two hosts to point it at:
#   TARGET      an external HTTP host. Any will do -- the signatures match the
#               request, not the reply, so a 404 is fine. Default example.com.
#   LAN_TARGET  a host on your own network, used by the scan and lateral
#               movement tests. No default: those two tests generate traffic
#               you need to be authorised to send, so you have to name it.
#   LAN_URL     an HTTP server on your own network, used by the CVE exploit-
#               attempt tests (9, 10). Any server will do, even a throwaway
#               `python3 -m http.server 8080`; the signatures match the
#               request. No default, for the same reason as LAN_TARGET: an
#               exploit-shaped request should only go to a host you own.
#
# Tests 7-10 fire rules that carry CVE metadata (ET `metadata: cve CVE_...`),
# for checking that CVE tagging survives your pipeline end to end (ECS-style
# pipelines usually map it to vulnerability.id).
#
TARGET="${TMORION_TARGET:-example.com}"
LAN_TARGET="${TMORION_LAN_TARGET:-}"
LAN_URL="${TMORION_LAN_URL%/}"

test1_name="Malware C2 check-in            -> sid 2029231  ET MALWARE Zeoticus Ransomware CnC"
test2_name="Malicious domain DNS lookup    -> sid 2029346  ET MALWARE Possible Winnti DNS Lookup"
test3_name="Phishing credential submission -> sid 2017753  ET PHISHING Successful Remax Phish"
test4_name="Port scan / host discovery     -> sid 2003068  ET SCAN Potential SSH Scan OUTBOUND"
test5_name="Lateral movement SSH + RDP     -> sid 2038967  ET INFO SSH-2.0-Go version string"
test6_name="Command output in HTTP reply   -> sid 2100498  GPL ATTACK_RESPONSE id check returned root"
test7_name="CVE-2021-44228 Log4Shell DNS   -> sid 2034820  ET ATTACK_RESPONSE DNS Query for CVE-2021-44228 Scanner Domain"
test8_name="CVE-2017-0144 WannaCry DNS     -> sid 2024291  ET MALWARE Possible WannaCry DNS Lookup 1"
test9_name="CVE-2021-44228 Log4j JNDI HTTP -> sid 2034647  ET EXPLOIT Apache log4j RCE Attempt (http ldap)"
test10_name="CVE-2020-5902 F5 TMUI HTTP     -> sid 2030469  ET EXPLOIT F5 TMUI RCE CVE-2020-5902 Attempt M1"

# ---------------------------------------------------------------------------

need_lan_target() {
  [ -n "$LAN_TARGET" ] && return 0
  echo "  SKIPPED. This test sends traffic to a host on your own network."
  echo "  Name it first:  export TMORION_LAN_TARGET=10.0.0.5"
  return 1
}

need_lan_url() {
  [ -n "$LAN_URL" ] && return 0
  echo "  SKIPPED. This test sends an exploit-shaped request to an HTTP server on"
  echo "  your own network. Name one first:  export TMORION_LAN_URL=http://10.0.0.5:8080"
  echo "  (a throwaway 'python3 -m http.server 8080' on that host is enough)"
  return 1
}

# A C2 check-in: the URI and the three-character User-Agent are what the
# signature keys on. The reply is irrelevant, so any HTTP host works.
test1() {
  curl -s -m 10 -A "DxD" \
    "http://${TARGET}/supersecretstring?babyDontHeartMe=1" > /dev/null 2>&1
}

# A lookup for a domain on a public C2 list. Only the DNS query leaves the
# host -- nothing ever connects to the domain, so this is the safest test here.
# Also lands in Zeek's dns.log.
#
# Queries the resolver explicitly rather than going through the system stub.
# On anything running systemd-resolved, /etc/resolv.conf points at 127.0.0.53
# and the query travels over loopback, where no sensor will ever see it.
dns_server() {
  local s
  s=$(awk '/^nameserver/ && $2 !~ /^127\./ {print $2; exit}' /etc/resolv.conf 2>/dev/null)
  echo "${TMORION_DNS:-${s:-1.1.1.1}}"
}

test2() {
  dig +short +timeout=3 +tries=1 "@$(dns_server)" update.livehost.live > /dev/null 2>&1
}

# The victim submitting credentials to a phishing kit, which is the half of a
# phish a network sensor can actually see. The "Sign+In" field and the
# /hotmail.php path are the match.
test3() {
  curl -s -m 10 \
    -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36" \
    -d "login=user%40example.com&passwd=Summer2026%21&Sign+In=Sign+In" \
    "http://${TARGET}/hotmail.php" > /dev/null 2>&1
}

# Two halves, and they deliberately go to different hosts.
#
# The signature is scoped $HOME_NET -> $EXTERNAL_NET 22, so the SSH probes have
# to leave the network to match -- pointing them at a host on your own LAN
# fires nothing, because then the destination is HOME_NET too. It counts SYNs
# by source, 5 within 120 seconds, so six attempts is enough; this does not
# need to be a real nmap run.
#
# Zeek's scan detection has no such direction constraint but wants breadth, so
# the wide sweep goes at the LAN host instead of hammering a stranger's box
# with 300 connections.
test4() {
  for _ in 1 2 3 4 5 6; do
    nc -z -w 1 "$TARGET" 22 > /dev/null 2>&1
  done
  need_lan_target || return 0
  echo "      sweeping 300 ports on ${LAN_TARGET} for Zeek scan detection ..."
  for p in $(seq 1 300); do
    nc -z -w 1 "$LAN_TARGET" "$p" > /dev/null 2>&1 &
  done
  wait
}

# An SSH client identifying itself as SSH-2.0-Go, then an RDP connection
# request carrying an mstshash cookie. Both are logged by Zeek (ssh.log,
# rdp.log) whether or not the target actually runs those services.
test5() {
  need_lan_target || return 0
  printf 'SSH-2.0-Go\r\n' | nc -w 3 "$LAN_TARGET" 22 > /dev/null 2>&1
  # 0x33 is the total TPKT length and 0x2e the X.224 length indicator (total
  # minus the 4-byte TPKT header and the indicator itself). Both have to match
  # the cookie length or Zeek's RDP analyzer rejects the message and rdp.log
  # stays empty -- change the username and these two bytes change with it.
  printf '\x03\x00\x00\x33\x2e\xe0\x00\x00\x00\x00\x00Cookie: mstshash=administrator\r\n\x01\x00\x08\x00\x03\x00\x00\x00' \
    | nc -w 3 "$LAN_TARGET" 3389 > /dev/null 2>&1
}

# Command output coming back over HTTP -- the classic sign of a web shell or a
# successful RCE. The signature matches the string anywhere in the payload, so
# sending it works as well as receiving it.
test6() {
  curl -s -m 10 -d "uid=0(root) gid=0(root) groups=0(root)" \
    "http://${TARGET}/" > /dev/null 2>&1
}

# A lookup for a Log4Shell *scanner* domain (Huntress's public log4shell
# tester). DNS query only, like test 2: nothing connects anywhere. The rule
# matches any name ending in .log4shell.huntress.com, so the label is free.
test7() {
  dig +short +timeout=3 +tries=1 "@$(dns_server)" \
    tmorion-test.log4shell.huntress.com > /dev/null 2>&1
}

# A lookup for the WannaCry kill-switch domain. DNS query only. The domain has
# been a researchers' sinkhole since 2017, so it resolves, but nothing here
# connects to it. The rule allows at most 5 bytes after the label, so the name
# must be exactly this plus ".com".
test8() {
  dig +short +timeout=3 +tries=1 "@$(dns_server)" \
    iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com > /dev/null 2>&1
}

# A Log4j JNDI lookup string in a request header -- the classic Log4Shell probe.
# The rule is scoped `any -> $HOME_NET`, so it only fires against a server on
# your own network, which is why this goes to LAN_URL and not TARGET. Inert:
# the lookup points at 127.0.0.1 on the *receiving* host and nothing evaluates
# it unless that host runs a vulnerable Log4j. Needs a real HTTP server there
# (the rule wants an established flow), but any server works.
test9() {
  need_lan_url || return 0
  curl -s -m 10 -o /dev/null \
    -H 'X-Api-Version: ${jndi:ldap://127.0.0.1:1389/a}' \
    "${LAN_URL}/" > /dev/null 2>&1
}

# An F5 BIG-IP TMUI path-traversal URI (CVE-2020-5902): /tmui/login.jsp followed
# by a ';'. The rule matches the URI alone, so a 404 from a non-F5 server is
# fine. --path-as-is stops curl from normalising the "..;" segment away.
test10() {
  need_lan_url || return 0
  curl -s -m 10 -o /dev/null --path-as-is \
    "${LAN_URL}/tmui/login.jsp/..;/tmui/system/user/authproperties.jsp" \
    > /dev/null 2>&1
}

# ---------------------------------------------------------------------------

run() {
  local n="$1" name
  eval "name=\$test${n}_name"
  echo
  echo "  [$n] ${name}"
  "test${n}"
  echo "      done."
}

usage() {
  echo
  echo "  tmOrion -- trigger network detections on a Suricata/Zeek sensor"
  echo
  echo "    -1   $test1_name"
  echo "    -2   $test2_name"
  echo "    -3   $test3_name"
  echo "    -4   $test4_name"
  echo "    -5   $test5_name"
  echo "    -6   $test6_name"
  echo "    -7   $test7_name"
  echo "    -8   $test8_name"
  echo "    -9   $test9_name"
  echo "    -10  $test10_name"
  echo "    -99  run all of them"
  echo
  echo "  TMORION_TARGET      external HTTP host           (now: $TARGET)"
  echo "  TMORION_LAN_TARGET  host on your network         (now: ${LAN_TARGET:-not set})"
  echo "  TMORION_LAN_URL     HTTP server on your network  (now: ${LAN_URL:-not set})"
  echo
}

ALL_TESTS="1 2 3 4 5 6 7 8 9 10"

for dep in curl dig nc; do
  command -v "$dep" > /dev/null 2>&1 || echo "  warning: '$dep' not found, some tests will not run"
done

if [ $# -gt 0 ]; then
  for arg in "$@"; do
    case "$arg" in
      -1|-2|-3|-4|-5|-6|-7|-8|-9|-10) run "${arg#-}" ;;
      -99) for n in $ALL_TESTS; do run "$n"; done ;;
      -l|--list|-h|--help) usage ;;
      *) echo "  unknown argument: $arg"; usage; exit 1 ;;
    esac
  done
  echo
  exit 0
fi

while true; do
  echo
  echo "  tmOrion -- target: ${TARGET}   lan: ${LAN_TARGET:-not set}   lan url: ${LAN_URL:-not set}"
  echo
  PS3="
  Choose which test you'd like to run: "
  options=("$test1_name" "$test2_name" "$test3_name" "$test4_name"
           "$test5_name" "$test6_name" "$test7_name" "$test8_name"
           "$test9_name" "$test10_name" "CHAOS! RUN ALL!" "Quit!")
  select _opt in "${options[@]}"; do
    case $REPLY in
      1|2|3|4|5|6|7|8|9|10) run "$REPLY"; break ;;
      11) for n in $ALL_TESTS; do run "$n"; done; break ;;
      12) echo; exit 0 ;;
      *) echo "  pick a number from the list"; break ;;
    esac
  done
done
