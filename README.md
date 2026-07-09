# qemu-x86_64 mis-emulates AES-NI on a little-endian POWER8 host

A `qemu-user` bug with a fix: `qemu-x86_64` mis-emulates the x86 **AES-NI**
round instructions (`aesenc`/`aesenclast`) on a little-endian POWER host, so an
amd64 guest's AES (hence AES-GCM TLS) computes wrong output. Guests see it as
OpenSSL:

```
error:0A000119:SSL routines:tls_get_more_records:decryption failed or bad record mac
```

This README doubles as the write-up for qemu-devel. The fix is
`0001-host-include-ppc64-Fix-little-endian-POWER8-AES-byte-order.patch`.

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

Complete the missing byte-reversal on the POWER8 path instead of disabling
the acceleration. After the `lxvd2x` + `xxpermdi` that corrects the doubleword
order, add a `vperm` that reverses the 16 bytes on load; the store does the
inverse before `xxpermdi` + `stxvd2x`:

```
 #else
+        AESStateVec rev = { 0, 1, 2, ... , 15 };
         asm("lxvd2x %x0, 0, %1\n\t"
-            "xxpermdi %x0, %x0, %x0, 2"
-            : "=v"(r) : "r"(p), "m"(*p));
+            "xxpermdi %x0, %x0, %x0, 2\n\t"
+            "vperm %0, %0, %0, %2"
+            : "=v"(r) : "r"(p), "v"(rev), "m"(*p));
 #endif
```

This keeps the vector AES acceleration on little-endian POWER8-baseline
builds; `-mcpu=power9` builds still use the correct `lxvb16x` path.

The reversal selector is the **ascending** `{0..15}` on a little-endian host
-- that is what raw `vperm` consumes to fully reverse the 16 bytes. (The
descending `{15..0}` belongs to the big-endian branch above and is a no-op
here: raw `vperm` is not the endianness-aware `vec_perm` builtin, so the
selector convention flips on LE. `vec_xl_be`/`vec_xst_be` also give the
correct result and are an equally valid, more readable alternative; the
raw-asm form is kept to match the surrounding code, which deliberately avoids
the altivec builtins.)

A more conservative alternative -- if one would rather not touch the POWER8
codegen -- is the one-line guard `#if defined(__ALTIVEC__) && (HOST_BIG_ENDIAN
|| defined(__POWER9_VECTOR__))`, which disables the acceleration on this path
and falls back to the correct generic C AES. It is smaller and trivially safe
but gives up POWER8 acceleration, so the byte-reversal fix above is preferred.

## Verification (POWER9 / ppc64le host)

Verified on a POWER9 (ppc64le) host by building `qemu-x86_64` from qemu
**v10.0.8** at the DEFAULT (POWER8) baseline -- confirmed the compiled binary
contains no `lxvb16x`, i.e. it takes the buggy path -- then running an amd64
OpenSSL under it. Before the patch the KAT gives the wrong `a280f0f6..bdf8`;
after the patch, under DEFAULT crypto (no `OPENSSL_ia32cap` override):

- AES-128/192/256-ECB known-answer vectors (NIST SP 800-38A): all correct,
  encrypt and decrypt (the decrypt path exercises `vncipher` too).
- AES-256-ECB, all four F.1 blocks: `f3eed1..81f8 591ccb..2870 b6ed21..ed1d
  23304b..ecc7` (correct).
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

Not found reported upstream as of 2026-07-08. QEMU splits bugs and patches
across two channels, and does NOT use GitLab merge requests or GitHub PRs:

- **Bug** -> file a GitLab issue at
  <https://gitlab.com/qemu-project/qemu/-/issues>.
- **Patch** -> email it to `qemu-devel@nongnu.org` via `git send-email` (do not
  attach it to the issue). Set the commit author to yourself, add your own
  `Signed-off-by` per QEMU's DCO (the included patch carries a placeholder
  author), and add a `Resolves: <issue-URL>` trailer to link the issue.

Before sending, note QEMU's code-provenance policy
(<https://www.qemu.org/docs/master/devel/code-provenance.html>): as of
2026-07-08 the merged policy DECLINES contributions "believed to include or
derive from AI generated content" (Anthropic's Claude is named explicitly), and
the DCO `Signed-off-by` certifies the human author takes responsibility for the
ENTIRE patch. This reproducer and patch were AI-assisted, so they cannot be
submitted silently under the current policy. Compliant options: have a human who
genuinely authors and understands the change submit it under their own DCO;
raise it on qemu-devel and request an exception; or track the proposed (not yet
merged, May 2026) relaxation that would permit small (<=20-line) fixes with an
`AI-used-for: code` disclosure trailer. Re-check code-provenance.rst on master
before sending, as the policy is in flux.

## Files

- `0001-host-include-ppc64-Fix-little-endian-POWER8-AES-byte-order.patch`
- `reproduce.sh`
- `LICENSE` (CC0)
