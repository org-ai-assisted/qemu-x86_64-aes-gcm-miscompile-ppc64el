#!/bin/bash

## Reproduce Bug 2: amd64 OpenSSL AES-256-GCM "bad record mac" under qemu-x86_64.
##
## Strategy: build a tiny amd64 (x86_64) Debian rootfs with 'openssl' and CA
## certificates, then run an AES-256-GCM TLS 1.3 handshake from inside it. On a
## host with binfmt_misc registered for x86_64 (qemu-user-static), the amd64
## 'openssl' executes under qemu-x86_64. A working OpenSSL completes the
## handshake ("Verify return code: 0"); the bug makes it fail with
## "bad record mac". The script also shows that OPENSSL_ia32cap=0 (forcing
## OpenSSL's software crypto) makes the same handshake succeed -- proving the
## defect is in qemu's emulation of the AES-NI / PCLMULQDQ instructions, not in
## OpenSSL.
##
## Override points (environment variables):
##   OPENSSL_ROOTFS  Path to an existing amd64 rootfs that already contains
##                   'openssl' and 'ca-certificates'. If set, none is built.
##   HOST_PORT       TLS endpoint to connect to (default: example.com:443).
##   SUITE           Debian suite to bootstrap (default: trixie).
##   MIRROR          Debian mirror URL (default: https://deb.debian.org/debian).
##   KEEP_ROOTFS     If "true", do not delete a rootfs this script created.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit

[ -v HOST_PORT ] || HOST_PORT="example.com:443"
[ -v SUITE ] || SUITE="trixie"
[ -v MIRROR ] || MIRROR="https://deb.debian.org/debian"
[ -v KEEP_ROOTFS ] || KEEP_ROOTFS="false"

host="${HOST_PORT%%:*}"

info() { printf 'INFO: %s\n' "$*" ; }
error() { printf 'ERROR: %s\n' "$*" >&2 ; exit 1 ; }

created_rootfs=""
cleanup() {
   if [ -n "$created_rootfs" ] && [ ! "$KEEP_ROOTFS" = "true" ]; then
      rm --recursive --force -- "$created_rootfs"
   fi
}
trap cleanup EXIT

check_binfmt() {
   [ -e /proc/sys/fs/binfmt_misc/qemu-x86_64 ] || error "binfmt_misc has no
'qemu-x86_64' entry. Install 'qemu-user-static' and ensure binfmt registration
is active."
   local interp
   interp="$(sed -n 's/^interpreter //p' /proc/sys/fs/binfmt_misc/qemu-x86_64)"
   info "qemu-x86_64 binfmt interpreter: ${interp:-unknown}"
}

build_rootfs() {
   command -v mmdebstrap >/dev/null 2>&1 || error "mmdebstrap not found."
   local rootfs
   rootfs="$(mktemp --directory --tmpdir openssl-amd64-rootfs.XXXXXX)"
   created_rootfs="$rootfs"
   info "Bootstrapping a minimal amd64 rootfs into '$rootfs' ..."
   mmdebstrap \
      --architectures=amd64 \
      --variant=apt \
      --include=openssl,ca-certificates \
      -- \
      "$SUITE" \
      "$rootfs" \
      "$MIRROR"
   printf '%s' "$rootfs"
}

run_one() {
   ## $1: rootfs, $2: label, $3...: extra env assignments for the chroot.
   local rootfs="$1" label="$2"; shift 2
   local out rc mac
   rc=0
   out="$(printf 'Q\n' | chroot "$rootfs" env "$@" \
      openssl s_client -connect "$HOST_PORT" -servername "$host" \
         -tls1_3 -ciphersuites TLS_AES_256_GCM_SHA384 2>&1)" || rc="$?"
   mac="$(printf '%s\n' "$out" | grep -c -iE 'bad record mac|decryption failed' || true)"
   printf -- '----- %s -----\n' "$label"
   printf '%s\n' "$out" | grep -iE 'bad record mac|Cipher is|Verify return code' | head -3 || true
   printf -- '---------------\n'
   printf '%s' "$mac"
}

run_kat() {
   ## FIPS-197 AES-256-ECB known-answer test through the guest openssl (no
   ## network). $1: rootfs, $2...: extra env for the chroot. Prints hex.
   local rootfs="$1"; shift
   printf '\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a' \
      | chroot "$rootfs" env "$@" openssl enc -aes-256-ecb \
         -K 603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4 \
         -nopad 2>/dev/null | od -An -tx1 | tr -d ' \n'
}

main() {
   [ "$(id -u)" = "0" ] || error "run as root: chroot and mmdebstrap require root."
   check_binfmt

   local rootfs
   if [ -v OPENSSL_ROOTFS ]; then
      info "Using pre-existing rootfs: $OPENSSL_ROOTFS"
      rootfs="$OPENSSL_ROOTFS"
   else
      rootfs="$(build_rootfs)"
   fi
   cp -- /etc/resolv.conf "$rootfs/etc/resolv.conf" 2>/dev/null || true

   ## Deterministic, network-free check first.
   local kat_expected="f3eed1bdb5d2a03c064b5a7e3db181f8"
   local kat_default kat_software
   kat_default="$(run_kat "$rootfs")"
   kat_software="$(run_kat "$rootfs" OPENSSL_ia32cap=0)"
   info "AES-256-ECB KAT: expected=$kat_expected default=$kat_default software=$kat_software"
   if [ "$kat_default" != "$kat_expected" ] && [ "$kat_software" = "$kat_expected" ]; then
      error "Bug reproduces: AES-256-ECB is wrong with hardware AES-NI
($kat_default) but correct with software crypto ($kat_software) -- qemu-x86_64
mis-emulates the AES-NI round instructions."
   fi

   info "Handshake with DEFAULT (hardware) crypto ..."
   local mac_default
   mac_default="$(run_one "$rootfs" "default crypto")"

   info "Handshake with OPENSSL_ia32cap=0 (software crypto) ..."
   local mac_software
   mac_software="$(run_one "$rootfs" "OPENSSL_ia32cap=0" OPENSSL_ia32cap=0)"

   info "bad-record-mac count: default=$mac_default software=$mac_software"
   if [ "$mac_default" != "0" ] && [ "$mac_software" = "0" ]; then
      error "Bug reproduces: AES-GCM fails with hardware crypto but works with
software crypto -- qemu-x86_64 mis-emulates the AES-NI round instructions."
   fi
   if [ "$mac_default" = "0" ]; then
      info "No bad record mac with hardware crypto -- the bug does NOT reproduce
in this environment (qemu may be fixed, or crypto instructions unused)."
      return 0
   fi
   error "Unexpected: software crypto also failed; environment problem, not the
target bug."
}

main "$@"
