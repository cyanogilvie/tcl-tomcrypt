---
name: using-tomcrypt
description: Use the tomcrypt Tcl package (a libtomcrypt wrapper) for hashing, HMAC, HKDF, base64url, symmetric ciphers, AEAD, ECC, RSA, and PRNG operations from Tcl scripts. Use when writing or debugging Tcl code that calls tomcrypt::* commands, or when the user mentions tomcrypt, libtomcrypt, or asks to do crypto from Tcl.
---

# Using the tomcrypt Tcl package

A thin Tcl wrapper around a subset of libtomcrypt. All commands live in the `::tomcrypt::` namespace. Load with `package require tomcrypt`.

## The most important rule: bytes, not strings

Almost every input that takes "bytes" is parsed via `Tcl_GetBytesFromObj`. The behaviour has a footgun:

- **Codepoints ≤ U+00FF** (latin-1) are **silently accepted** and folded to their low byte. So `"héllo"` (with `é` = U+00E9) hashes as the 5 bytes `h \xE9 l l o`, **not** as UTF-8 bytes. This is the same on both Tcl 8.6 and Tcl 9.
- **Codepoints ≥ U+0100** raise `expected byte sequence but character N was '…'` with errorCode `{TCL VALUE BYTES}`.

So passing a Tcl string literal containing non-ASCII characters will:
- silently produce a wrong (latin-1) hash if every char is in [U+0080, U+00FF], **or**
- throw if any char is ≥ U+0100.

**Always construct bytes explicitly. Never trust an unconverted string.** Use:

```tcl
tomcrypt::hash sha256 [encoding convertto utf-8 $string]   ;# text → UTF-8 bytes
tomcrypt::hash sha256 [binary decode hex $hex]             ;# hex → bytes
tomcrypt::hash sha256 [binary format c* $ints]             ;# ints → bytes
```

Pure-ASCII literals technically work (the test suite uses them) — but only because every char is < U+0080. As soon as a string can contain anything else, you have a bug. Make the conversion explicit unconditionally.

This applies to: hash, hmac, hkdf (salt/info/in), base64url encode, encrypt/decrypt, aead, rsa_sign_hash `-hash`, rsa `-msg`/`-ciphertext`/`-lparam`, ecc_sign/ecc_verify message, prng entropy, prng `add_entropy`, ecc_ansi_x963_import.

RSA and ECC **key** arguments are an exception — they accept ordinary Tcl strings (PEM is text) as well as raw DER bytes.

## Hash, HMAC, HKDF

```tcl
set digest [tomcrypt::hash sha256 $bytes]                   ;# raw bytes out
set mac    [tomcrypt::hmac sha256 $key $message]            ;# raw bytes out
set okm    [tomcrypt::hkdf sha256 $salt $info $ikm $length] ;# RFC 5869 extract+expand
```

- `algorithm` is any libtomcrypt hash name: `md5`, `sha1`, `sha224`, `sha256`, `sha384`, `sha512`, `sha3-256`, `blake2b-512`, etc. Unknown name → `{TOMCRYPT LOOKUP HASH <name>}`.
- HKDF `salt` and `info` may be empty (`{}`); `length` 0 returns `{}`; negative `length` → `{TOMCRYPT VALUE} length must be non-negative`.
- HKDF can produce more bytes than the hash size — it expands. **But not arbitrarily**: per RFC 5869 the maximum output is 255 × hash size (8160 bytes for sha256, 16320 for sha512). Asking for more raises `hmac_memory failed: Invalid argument provided.` with `errorCode {TOMCRYPT HMAC COMPUTE}` — which doesn't mention HKDF; if you see that error from `hkdf`, this is the cause.

## base64url

```tcl
tomcrypt::base64url encode        $bytes    ;# no padding
tomcrypt::base64url strict_encode $bytes    ;# pads with = to multiple of 4
tomcrypt::base64url decode        $string   ;# lenient — silently skips invalid chars
tomcrypt::base64url strict_decode $string   ;# strict — throws on any non-alphabet char
```

`encode`/`strict_encode` use the URL-safe alphabet (`-`/`_`).

**`decode` is dangerously lenient**: it silently *skips* any character that isn't in the URL-safe base64 alphabet, then decodes what's left. Whitespace, stray `=`, and even standard-base64 chars `+` and `/` are silently dropped — they don't terminate decoding, they're just ignored. So `tomcrypt::base64url decode "Zm9v+YmFy"` returns `foobar`, not an error. Use `strict_decode` for any input you don't fully control — it raises `base64url decode failed: Invalid input packet.` on any non-alphabet character (still tolerates `=` padding either present or absent).

## Symmetric cipher (encrypt / decrypt)

```tcl
set spec [list aes 256 cbc]
set ciphertext [tomcrypt::encrypt $spec $key $iv $plaintext]
set plaintext  [tomcrypt::decrypt $spec $key $iv $ciphertext]
```

Spec is a 3- or 4-element list: `{cipher keysize_bits mode ?mode_opt?}`.

- **Modes**: `cbc`, `cfb`, `ofb`, `ctr`, `lrw`, `f8`. There is no `gcm`/`ccm`/etc here — those live under `tomcrypt::aead`.
- **`keysize` is in BITS**, not bytes. For a 32-byte AES key write `256`, not `32`. Idiom: `expr {8*[string length $key]}`.
- **`iv` length must equal the cipher's block size** (8 for blowfish, 16 for aes). Otherwise: `IV must be same length as cipher block size` / `{TOMCRYPT VALUE IV_SIZE}`.
- **`cbc` does PKCS#7 padding automatically** on encrypt and unpads on decrypt — do not pre-pad. Other modes do not pad and accept arbitrary lengths.
- **`ctr` defaults to BIG-endian counter** (NIST SP 800-38A / OpenSSL convention). This wrapper deliberately overrides libtomcrypt's own little-endian default to match the rest of the world. If you need to interop with libtomcrypt-native or other little-endian CTR code, pass `CTR_COUNTER_LITTLE_ENDIAN` as the 4th element (a list of flags). Available flags: `CTR_COUNTER_BIG_ENDIAN`, `CTR_COUNTER_LITTLE_ENDIAN`, `LTC_CTR_RFC3686`. Example: `[list aes 256 ctr {CTR_COUNTER_LITTLE_ENDIAN}]`.
- `lrw` requires a tweak as 4th element; `f8` requires a salt.

## AEAD (authenticated encryption)

```tcl
lassign [tomcrypt::aead encrypt $mode $cipher $key $iv $aad $plaintext] ct tag
set pt  [tomcrypt::aead decrypt $mode $cipher $key $iv $aad $ct $tag]
```

Modes (registered in `aead.c`):

| mode               | cipher arg     | required cipher block size | typical IV |
|--------------------|----------------|----------------------------|------------|
| `gcm`              | required (e.g. `aes`) | **must be 16 bytes**       | 12 bytes   |
| `ocb3`             | required       | **must be 16 bytes**       | 12 bytes   |
| `ocb`              | required       | **must be 16 bytes**       | block size (16 bytes for AES) — OCB1, prefer `ocb3` for new code |
| `ccm`              | required       | **must be 16 bytes**       | 7–13 bytes (8 in tests) |
| `eax`              | required       | any (works with blowfish)  | flexible   |
| `chacha20poly1305` | **ignored** — pass `""` | n/a            | 12 bytes (must be 12) |

- **GCM/OCB3/OCB/CCM only work with 16-byte block ciphers** (i.e. `aes`). Using e.g. `blowfish` raises `gcm requires 16-byte block cipher` / `{TOMCRYPT AEAD BLOCKSIZE}`.
- **Tag is always 16 bytes** (no way to ask for a shorter tag).
- **OCB1 (`ocb`) does not authenticate AAD** — the `aad` argument is silently ignored on both encrypt and decrypt. Use `ocb3` (or another mode) if you need AAD authentication.
- **chacha20poly1305 ignores the cipher arg entirely** — pass `""` by convention, but anything works.
- `aad` and `plaintext` may be empty (`{}`).
- Tag/AAD/IV mismatch on decrypt → error matching `*failed*`, errorCode `{TOMCRYPT AEAD DECRYPT <mode>}`. Always wrap decrypt in `try`/`catch` if untrusted input is possible.
- For GCM the IV **must not be reused** with the same key. Generate a fresh 12-byte IV per message with `tomcrypt::rng_bytes 12`.

## ECC

```tcl
set privkey [tomcrypt::ecc_generate_key secp256r1 ?$prng?]    ;# PEM string out
set pubkey  [tomcrypt::ecc_extract_pubkey $privkey]           ;# PEM string out
set sig     [tomcrypt::ecc_sign $privkey $hash ?$prng?]       ;# ANSI X9.62 sig
set ok      [tomcrypt::ecc_verify $sig $hash $pubkey]         ;# 1/0
set secret  [tomcrypt::ecc_shared_secret $privkey $peer_pub]  ;# raw x-coord; pass through hkdf before use
```

### Curve names
Anything libtomcrypt recognises: standard names (`secp256r1`, `secp384r1`, `secp521r1`, `secp256k1`), aliases (`P-256`, `P-384`, `P-521`, `prime256v1`), or OIDs (`1.2.840.10045.3.1.7`). Custom curves: pass a dict `{prime A B order Gx Gy ?cofactor? ?OID?}` (all hex strings; cofactor defaults to 1).

### Key formats accepted
ECC key arguments accept any of:

1. **PEM** with `-----BEGIN EC PRIVATE KEY-----` or `-----BEGIN EC PUBLIC KEY-----` (note: `EC PUBLIC KEY`, not `PUBLIC KEY`).
2. **OpenSSL DER** (raw DER bytes, no PEM wrapping).
3. **Raw ANSI X9.63** bytes (uncompressed, starts with 0x04) — but only when the function expects a public key, and the parser tries `secp256r1` as a fallback. For other curves use `ecc_ansi_x963_import` with an explicit curve.

`ecc_generate_key` / `ecc_extract_pubkey` return a **PEM-encoded string**. The same Tcl_Obj also caches an internal rep so repeated use is cheap.

### Sign and verify operate on a hash
The arg called *message* is **the bytes you want to sign**, not "the message before hashing". For a long message you **must hash it first**:

```tcl
set h   [tomcrypt::hash sha256 [encoding convertto utf-8 $msg]]
set sig [tomcrypt::ecc_sign $privkey $h]
tomcrypt::ecc_verify $sig $h $pubkey
```

`ecc_verify` returns `1`/`0`; it only **throws** if the signature or key blob is unparseable, not on a valid-but-mismatching signature.

### ANSI X9.63 import / export

```tcl
set raw [tomcrypt::ecc_ansi_x963_export $pubkey]             ;# 0x04 || x || y
set k   [tomcrypt::ecc_ansi_x963_import $raw ?$curve?]
```

When `curve` is omitted, the curve is **inferred from the byte length** and only works for: secp112r1, secp128r1, secp160r1, secp192r1, secp224r1, secp256r1, secp384r1, secp521r1. For anything else, pass the curve explicitly.

### ECDH key agreement
`ecc_shared_secret` returns the raw x-coordinate of the shared point. Always feed it through `hkdf` (or another KDF) before using as a key:

```tcl
set shared [tomcrypt::ecc_shared_secret $my_priv $peer_pub]
set key    [tomcrypt::hkdf sha256 $salt "session-key" $shared 32]
```

## RSA

```tcl
set privkey [tomcrypt::rsa_make_key ?-keysize 2048? ?-exponent 65537? ?-prng $prng?]
set pubkey  [tomcrypt::rsa_extract_pubkey $privkey]

set sig [tomcrypt::rsa_sign_hash   -key $privkey -hash $h ?-padding pss? ?-hashalg sha256? ?-saltlen 0? ?-prng $prng?]
set ok  [tomcrypt::rsa_verify_hash -key $pubkey  -sig $sig -hash $h ?-padding pss? ?-hashalg sha256? ?-saltlen 0?]

set ct  [tomcrypt::rsa_encrypt_key -key $pubkey  -msg $bytes ?-padding oaep? ?-hashalg sha256? ?-lparam $label? ?-prng $prng?]
set pt  [tomcrypt::rsa_decrypt_key -key $privkey -ciphertext $ct ?-padding oaep? ?-hashalg sha256? ?-lparam $label?]
```

### Defaults
- `rsa_make_key`: keysize **2048**, exponent **65537** (0x10001). Keysize must be a multiple of 8 in [1024, 4096]; exponent must be ≥ 3.
- `rsa_sign_hash` / `rsa_verify_hash`: padding **`pss`**, hashalg **`sha256`**, saltlen **0**.
- `rsa_encrypt_key` / `rsa_decrypt_key`: padding **`oaep`**, hashalg **`sha256`** (OAEP only), lparam **empty**.

### Key formats accepted
- PEM: `-----BEGIN RSA PRIVATE KEY-----` (PKCS#1) or `-----BEGIN PUBLIC KEY-----` (note: not `RSA PUBLIC KEY`).
- Raw DER bytes (PKCS#1).

`rsa_make_key` returns a PEM-encoded private key string. `rsa_extract_pubkey` only accepts a *private* key — passing a public key raises `{TOMCRYPT KEY TYPE} Expected private key but got public key`. Likewise `rsa_sign_hash`/`rsa_decrypt_key` need a private key, `rsa_verify_hash`/`rsa_encrypt_key` need a public key.

### Padding interactions (these will trip you up)
- **`-padding pss`** (default for sign/verify): supports `-hashalg`, `-saltlen`, and `-prng` (sign only).
- **`-padding v1.5`**: supports `-hashalg` (sign/verify); does **not** accept `-prng` or `-saltlen`. Passing `-prng` raises `-prng only applies to pss padding`.
- **`-padding v1.5_na1`** (sign/verify, SSL 3.0 compat): does **not** accept `-hashalg`. The hash is signed without ASN.1 wrapping.
- **`-padding oaep`** (default for encrypt/decrypt): supports `-hashalg` and `-lparam`.
- **`-padding v1.5`** for encrypt/decrypt: does **not** accept `-hashalg`. Raises `-hashalg does not apply for v1.5 padding` if you pass it.
- **PSS `-saltlen` is bounded**: max depends on hash and key size. Exceeding it raises `salt length N exceeds maximum M` with `{TOMCRYPT VALUE -saltlen}`.

### `rsa_verify_hash` returns 1/0; `rsa_decrypt_key` throws
- `rsa_verify_hash` returns `1` on valid, `0` on invalid (only throws on malformed inputs).
- `rsa_decrypt_key` **throws** on invalid ciphertext / padding. The errorCode is `{TOMCRYPT RSA DECRYPT}` for the common case (libtomcrypt returns `CRYPT_INVALID_PACKET`, e.g. wrong key, wrong lparam, tampered ciphertext) and `{TOMCRYPT RSA DECRYPT OAEP}` for the rarer "decrypt succeeded but stat=0" path. Match against the `{TOMCRYPT RSA DECRYPT}` prefix, not the full 4-element form. Wrap untrusted ciphertext in `try`/`catch`.

### Signing convention
You hash first, then sign the hash:

```tcl
set h   [tomcrypt::hash sha256 [encoding convertto utf-8 $message]]
set sig [tomcrypt::rsa_sign_hash -key $privkey -hash $h]
tomcrypt::rsa_verify_hash -key $pubkey -sig $sig -hash $h
```

For CloudFront-style signatures (PKCS#1 v1.5 + SHA-1):

```tcl
set h   [tomcrypt::hash sha1 [encoding convertto utf-8 $policy]]
set sig [tomcrypt::rsa_sign_hash -key $privkey -hash $h -padding v1.5 -hashalg sha1]
```

## PRNG

Two flavours of randomness:

```tcl
set bytes [tomcrypt::rng_bytes 32]   ;# system secure RNG, one-shot

tomcrypt::prng create $name $type ?$entropy?   ;# named instance
set p [tomcrypt::prng new   $type ?$entropy?]  ;# auto-named instance
```

### `type` argument
- A libtomcrypt PRNG name: `fortuna`, `chacha20`, `rc4`, `sober128`, `yarrow`, etc.
- The empty string `""` selects the "recommended default" (currently `fortuna`; may change in future releases).
- Unknown name → `{TOMCRYPT UNREGISTERED PRNG <name>}`.

### `entropy` argument
- Optional. If omitted, the instance is bootstrapped with ~256 bits from `rng_get_bytes` (the platform secure RNG).
- If supplied, **must be at least 8 bytes** (raises `{TOMCRYPT VALUE} insufficient entropy supplied`) and a valid bytearray.
- If its length exactly equals the PRNG's `export_size` (64 bytes for fortuna and yarrow, 40 for chacha20 and sober128, 32 for rc4) the constructor uses `pimport`; otherwise it's mixed in with `add_entropy`. Either way the new PRNG is then `ready()`ed before use.

### Instance methods
The instance is a TclOO object; method names are:

```tcl
$prng bytes $count        ;# raw random bytes (count >= 0)
$prng add_entropy $bytes  ;# mix more entropy in; empty input is a no-op
$prng integer $lo $hi     ;# uniform random integer in [lo, hi] inclusive (bignums OK, lo/hi may be negative)
                          ;# n-bit unsigned: [$prng integer 0 [expr {2**$n - 1}]]
$prng double              ;# uniform double in [0, 1)
$prng export              ;# deterministic seed blob — TREAT AS SECRET (see below)
$prng destroy             ;# explicit destroy (or `rename $prng {}`)
```

`bytes`, `integer`, `double` and `export` always return raw bytearrays / numbers — no string round-tripping.

`integer` uses uniform rejection sampling (no modulo bias) and supports arbitrary-size bignums on both ends. `double` returns one of 2^53 evenly-spaced values in [0, 1).

### Entropy-saving idiom and the truth about `export`
`export` produces a deterministic blob: **two PRNGs of the same type re-created from the same blob produce identical streams.** The blob is effectively a seed, not random output, so:

- **Treat the exported blob as secret keying material.** Anyone with read access to the file can replay every byte the next process generates from it. A world-readable entropy file undermines the PRNG entirely.
- The original PRNG and a fresh PRNG re-imported from `[orig export]` will *not* produce the same subsequent bytes — calling `export` advances the original's state, so it's no longer in the same place as the fresh import.
- Calling `export` twice on the same PRNG gives different blobs (state has advanced between calls).

The save/restore-across-runs idiom is still correct, just store the file with restrictive permissions:

```tcl
if {[file exists $state_file]} {
    tomcrypt::prng create csprng {} [readbin $state_file]   ;# seed from saved blob
} else {
    tomcrypt::prng create csprng {}                         ;# fresh seed from system RNG
}
writebin $state_file [csprng export]
file attributes $state_file -permissions 0600               ;# secret seed!
```

### Where PRNGs are accepted
Anywhere a `?prng?` arg appears (`ecc_generate_key`, `ecc_sign`, `rsa_make_key`, `rsa_sign_hash` for PSS, `rsa_encrypt_key`), pass an instance command name (e.g. `csprng`). Omitting it uses the system secure RNG.

## Error codes

The package uses structured `errorCode` lists, useful for programmatic handling:

- `{TCL VALUE BYTES}` — non-bytearray supplied where bytes required (most common mistake)
- `{TOMCRYPT LOOKUP HASH <name>}`, `{TOMCRYPT LOOKUP CIPHER <name>}`, `{TOMCRYPT LOOKUP AEAD_MODE <name>}`
- `{TOMCRYPT VALUE …}` — bad numeric argument
- `{TOMCRYPT VALUE IV_SIZE}` — IV doesn't match cipher block size
- `{TOMCRYPT VALUE -saltlen}` — PSS saltlen exceeds maximum
- `{TOMCRYPT ARGUMENT MISSING -opt}` — missing value for `-opt`
- `{TOMCRYPT KEY TYPE}` — wrong key type for the operation (e.g. private when public expected)
- `{TOMCRYPT FORMAT RSA}`, `{TOMCRYPT FORMAT PEM}` — unparseable key blob
- `{TOMCRYPT AEAD DECRYPT <mode>}`, `{TOMCRYPT RSA DECRYPT}` (sometimes `{TOMCRYPT RSA DECRYPT OAEP}`) — auth/padding failure on decrypt (these throw — handle them)
- `{TOMCRYPT UNREGISTERED PRNG <name>}` — unknown PRNG implementation

## Quick gotcha checklist

When code "looks right" but doesn't work, check in this order:

1. **Did you pass a string where bytes were expected?** Wrap with `[encoding convertto utf-8 …]`. Remember: latin-1 strings (`é`, etc.) silently produce *wrong* bytes — they don't even throw. Only U+0100+ throws.
2. **Cipher keysize in bits?** `[expr {8*[string length $key]}]`, not `[string length $key]`.
3. **Cipher IV length == block size?** 16 for aes, 8 for blowfish.
4. **AEAD using non-aes with gcm/ocb/ocb3/ccm?** Switch cipher to `aes` or mode to `eax`/`chacha20poly1305`.
5. **Hashing before sign/verify?** `ecc_sign`/`rsa_sign_hash` sign the *hash bytes you give them*, not the message.
6. **RSA padding default mismatch?** Sign default is `pss`; legacy systems often want `v1.5` — pass it explicitly.
7. **Reusing GCM IV?** Don't. Generate `tomcrypt::rng_bytes 12` per message.
8. **Trying to use `tomcrypt::encrypt` for GCM?** Wrong command — GCM lives in `tomcrypt::aead`.
9. **CTR mode interop with code that uses libtomcrypt's native little-endian counter?** This wrapper's default is *big-endian* (NIST/OpenSSL); pass `{CTR_COUNTER_LITTLE_ENDIAN}` as the 4th spec element to opt into the libtomcrypt convention.
10. **Calling `rsa_extract_pubkey` on a public key?** It only accepts private keys.

## Worked examples

### AES-256-GCM round trip with random IV (and tamper detection)

```tcl
package require tomcrypt
set key [tomcrypt::rng_bytes 32]
set iv  [tomcrypt::rng_bytes 12]                        ;# fresh per message
set aad [encoding convertto utf-8 "v1|user=42"]
set pt  [encoding convertto utf-8 "secret payload"]

lassign [tomcrypt::aead encrypt gcm aes $key $iv $aad $pt] ct tag

# transmit/store {iv ct tag aad}; key stays secret

try {
    set decrypted [tomcrypt::aead decrypt gcm aes $key $iv $aad $ct $tag]
    puts [encoding convertfrom utf-8 $decrypted]
} trap {TOMCRYPT AEAD DECRYPT} {msg opts} {
    # Tag mismatch / AAD mismatch / wrong key — treat as tampering
    puts stderr "authentication failed: $msg"
}
```

### ECDSA over a JSON document

```tcl
tomcrypt::prng create rng fortuna
set privkey [tomcrypt::ecc_generate_key secp256r1 rng]
set pubkey  [tomcrypt::ecc_extract_pubkey $privkey]

set msg  [encoding convertto utf-8 {{"sub":"alice","exp":1700000000}}]
set h    [tomcrypt::hash sha256 $msg]
set sig  [tomcrypt::ecc_sign $privkey $h rng]

if {[tomcrypt::ecc_verify $sig $h $pubkey]} {
    puts ok
}
rng destroy
```

### ECDH → HKDF → AES-GCM

```tcl
set my_priv   [tomcrypt::ecc_generate_key secp256r1]
set peer_pub  $received_peer_public_key_pem
set shared    [tomcrypt::ecc_shared_secret $my_priv $peer_pub]
set key       [tomcrypt::hkdf sha256 $salt "v1 ecdh aes256gcm" $shared 32]
set iv        [tomcrypt::rng_bytes 12]
lassign [tomcrypt::aead encrypt gcm aes $key $iv $aad $pt] ct tag
```

### RSA-PSS sign/verify

```tcl
set privkey [tomcrypt::rsa_make_key -keysize 2048]
set pubkey  [tomcrypt::rsa_extract_pubkey $privkey]
set h       [tomcrypt::hash sha256 [encoding convertto utf-8 $document]]
set sig     [tomcrypt::rsa_sign_hash   -key $privkey -hash $h -saltlen 32]
set ok      [tomcrypt::rsa_verify_hash -key $pubkey  -sig $sig -hash $h -saltlen 32]
```

### RSA-OAEP encrypt small payload

```tcl
set ct [tomcrypt::rsa_encrypt_key -key $pubkey -msg [encoding convertto utf-8 $secret]]
# OAEP/SHA-256 on a 2048-bit key: max ~190 bytes of plaintext.
try {
    set pt [tomcrypt::rsa_decrypt_key -key $privkey -ciphertext $ct]
} on error {msg opts} {
    # OAEP failure throws — treat as tampering / wrong key
}
```

### Custom curve (toy example — use a real curve in production)

```tcl
set curve [dict create \
    prime    DB7C2ABF62E35E668076BEAD208B \
    A        DB7C2ABF62E35E668076BEAD2088 \
    B        659EF8BA043916EEDE8911702B22 \
    order    DB7C2ABF62E35E7628DFAC6561C5 \
    Gx       09487239995A5EE76B55F9C2F098 \
    Gy       A89CE5AF8724C0A23E0E0FF77500 \
    cofactor 1 \
]
set privkey [tomcrypt::ecc_generate_key $curve]
```
