#!/bin/bash

## Reproduce: amd64 OpenSSL AES mis-emulated by qemu-x86_64 (surfacing as
## "bad record mac" in AES-256-GCM TLS).
##
## Strategy: build a tiny amd64 (x86_64) Debian rootfs with 'openssl' and CA
## certificates; on a host with binfmt_misc registered for x86_64
## (qemu-user-static) the amd64 'openssl' runs under qemu-x86_64. Two checks:
##   1. A deterministic, network-free AES-256-ECB known-answer test (the
##      primary signal).
##   2. A real AES-256-GCM TLS 1.3 handshake ("Verify return code: 0" when OK,
##      "bad record mac" when broken).
## Each is also run with OPENSSL_ia32cap=0 (forcing OpenSSL's software crypto):
## software crypto is correct, proving the defect is in qemu's emulation of the
## x86 AES-NI instructions, not in OpenSSL.
##
## Exit status (health-check convention): 0 if this qemu is NOT affected (the
## bug does not reproduce); non-zero if the bug reproduces or the environment
## is broken (the reason is printed).
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

## Diagnostics go to stderr so command substitutions capture only real return
## values (the rootfs path / the mac count), not log lines.
info() { printf 'INFO: %s\n' "$*" >&2 ; }
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
   ## Sets the global 'created_rootfs' (which the cleanup trap deletes). It does
   ## NOT print the path to stdout and is called directly (not in a subshell),
   ## so the assignment is visible to the trap and no log output can corrupt the
   ## path. mmdebstrap's own output is sent to stderr.
   command -v mmdebstrap >/dev/null 2>&1 || error "mmdebstrap not found."
   created_rootfs="$(mktemp --directory --tmpdir openssl-amd64-rootfs.XXXXXX)"
   info "Bootstrapping a minimal amd64 rootfs into '$created_rootfs' ..."
   mmdebstrap \
      --architectures=amd64 \
      --variant=apt \
      --include=openssl,ca-certificates \
      -- \
      "$SUITE" \
      "$created_rootfs" \
      "$MIRROR" >&2
}

run_one() {
   ## $1: rootfs, $2: label, $3...: extra env assignments for the chroot.
   local rootfs="$1" label="$2"; shift 2
   local out mac
   ## '|| true' swallows openssl's non-zero exit (e.g. on 'Q') under errexit;
   ## the mac count below is the actual signal.
   out="$(printf 'Q\n' | chroot "$rootfs" env "$@" \
      openssl s_client -connect "$HOST_PORT" -servername "$host" \
         -tls1_3 -ciphersuites TLS_AES_256_GCM_SHA384 2>&1)" || true
   mac="$(printf '%s\n' "$out" | grep -c -iE 'bad record mac|decryption failed' || true)"
   ## Human-readable report to stderr; only the mac count to stdout (captured).
   printf -- '----- %s -----\n' "$label" >&2
   printf '%s\n' "$out" | grep -iE 'bad record mac|Cipher is|Verify return code' | head -3 >&2 || true
   printf -- '---------------\n' >&2
   printf '%s' "$mac"
}

run_kat() {
   ## NIST SP 800-38A F.1 AES-256-ECB known-answer test through the guest
   ## openssl (no network). $1: rootfs, $2...: extra env. Prints hex.
   ## '|| true' keeps a crashing openssl from aborting the script under errexit
   ## (a mis-emulation produces WRONG output with exit 0, not a crash, but be
   ## defensive); the caller validates the hex.
   local rootfs="$1"; shift
   printf '\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a' \
      | chroot "$rootfs" env "$@" openssl enc -aes-256-ecb \
         -K 603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4 \
         -nopad 2>/dev/null | od -An -tx1 | tr -d ' \n' || true
}

main() {
   [ "$(id -u)" = "0" ] || error "run as root: chroot and mmdebstrap require root."
   check_binfmt

   local rootfs
   if [ -v OPENSSL_ROOTFS ]; then
      info "Using pre-existing rootfs: $OPENSSL_ROOTFS"
      rootfs="$OPENSSL_ROOTFS"
   else
      build_rootfs
      rootfs="$created_rootfs"
   fi
   cp -- /etc/resolv.conf "$rootfs/etc/resolv.conf" 2>/dev/null || true

   ## Deterministic, network-free check first.
   local kat_expected="f3eed1bdb5d2a03c064b5a7e3db181f8"
   local kat_default kat_software
   kat_default="$(run_kat "$rootfs")"
   kat_software="$(run_kat "$rootfs" OPENSSL_ia32cap=0)"
   info "AES-256-ECB KAT: expected=$kat_expected default=$kat_default software=$kat_software"
   ## Self-validate first: software crypto MUST give the correct answer. If it
   ## does not, the guest openssl / rootfs is broken -- an environment problem,
   ## not the qemu bug -- so do not misattribute it.
   if [ "$kat_software" != "$kat_expected" ]; then
      error "Environment problem: software-crypto AES-256-ECB is wrong
($kat_software, expected $kat_expected); the guest openssl or rootfs is broken,
not the target qemu bug."
   fi
   if [ "$kat_default" != "$kat_expected" ]; then
      error "Bug reproduces: AES-256-ECB is wrong under hardware AES-NI
($kat_default, expected $kat_expected) but correct with software crypto --
qemu-x86_64 mis-emulates the AES-NI round instructions."
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
