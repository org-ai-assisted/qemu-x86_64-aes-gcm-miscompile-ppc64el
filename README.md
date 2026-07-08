# qemu-x86_64 mis-emulates AES-NI on a little-endian POWER8 host

A `qemu-user` bug with a fix: `qemu-x86_64` mis-emulates the x86 **AES-NI**
round instructions (`aesenc`/`aesenclast`) on a little-endian POWER host, so an
amd64 guest's AES (hence AES-GCM TLS) computes wrong output. Guests see it as
OpenSSL:

```
error:0A000119:SSL routines:tls_get_more_records:decryption failed or bad record mac
```

This README doubles as the write-up for qemu-devel. The fix is
`0001-host-include-ppc64-Fix-AES-acceleration-on-little-endian-POWER8.patch`.

## Symptom (deterministic, no network)

NIST SP 800-38A F.1 AES-256-ECB known-answer test through an amd64 OpenSSL
under `qemu-x86_64`:

- key `603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4`,
  plaintext block `6bc1bee22e409f96e93d7e117393172a`
- correct ciphertext: `f3eed1bdb5d2a03c064b5a7e3db181f8`
- qemu with hardware AES-NI: `a280f0f614c007bc85d66de286d6bdf8` (WRONG)
- qemu with `OPENSSL_ia32cap=0` (software AES): `f3eed1...81f8` (correct)

So AES-NI is mis-emulated. PCLMULQDQ/GHASH is fine (ppc64 has no `clmul.h`, so
it uses the correct generic path).

## Root cause

qemu accelerates a guest's AES-NI with the POWER host's `vcipher`/`vcipherlast`
in `host/include/ppc64/host/crypto/aes-round.h`. On a little-endian host the
128-bit AES state must be byte-reversed into the vector register first. The
load/store helpers do this correctly with the POWER9 `lxvb16x`/`stxvb16x`
byte-indexed instructions, but the POWER8 fallback (built without
`__POWER9_VECTOR__`) uses `lxvd2x` + `xxpermdi 2`, which loads the state in
natural memory order WITHOUT the byte-reversal. `vcipher` then processes
wrongly-ordered data.

Native (no-qemu) check on the POWER9 host, loading bytes `00 01 ... 0f`:

```
lxvd2x + xxpermdi 2  ->  00 01 02 ... 0f   (identity: no byte-reversal, BUG)
lxvb16x              ->  0f 0e 0d ... 00   (full byte-reversal, correct)
```

Debian builds qemu for the POWER8 baseline, so the buggy path is used even on
POWER9 hardware. Reproduces on qemu 10.0.8, 10.2.0, and git master.

## Fix

Enable the acceleration only where the byte-reversing load/store is correct:

```
-#ifdef __ALTIVEC__
+#if defined(__ALTIVEC__) && (HOST_BIG_ENDIAN || defined(__POWER9_VECTOR__))
```

(plus an explanatory comment; see the patch). Little-endian POWER8-baseline
builds then use the correct generic C AES; `-mcpu=power9` builds keep the
correct `lxvb16x` acceleration. A follow-up could restore POWER8 acceleration
with a correct byte-reversing load -- GCC's `vec_xl_be` produces the right
result, and a raw `lxvd2x` + `vperm` would too, but with a non-obvious mask
(the naive `{15..0}` permute does not work), so it needs care.

## Verification (POWER9 / ppc64le host)

With the patch, a default (POWER8-baseline) build of `qemu-x86_64`, under
DEFAULT crypto (no `OPENSSL_ia32cap` override):

- AES-256-ECB KAT: `f3eed1...81f8` (correct).
- AES-256-GCM TLS 1.3 handshake: `Verify return code: 0`, no "bad record mac".

A `-mcpu=power9` build also passes (keeps the correct `lxvb16x` acceleration).

## Reproduce

Requires `qemu-user-static` + binfmt for x86_64, `mmdebstrap`, and root:

```sh
sudo ./reproduce.sh
```

It builds a throwaway amd64 rootfs and runs the AES-256-ECB KAT plus a real
AES-256-GCM TLS handshake, with the `OPENSSL_ia32cap=0` discriminator.

## Submitting upstream

Not found reported upstream as of 2026-07-08. To post the patch to qemu-devel,
set the commit author to yourself and add your own `Signed-off-by` per qemu's
DCO (the included patch carries a placeholder author).

## Files

- `0001-host-include-ppc64-Fix-AES-acceleration-on-little-endian-POWER8.patch`
- `reproduce.sh`
- `LICENSE` (CC0)
