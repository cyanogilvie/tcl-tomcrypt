#include "tomcryptInt.h"

// Must be kept in sync with the enum in tomcryptInt.tcl
static const char* lit_str[L_size] = {
#define X(name, str) str,
	LITSTRS
#undef X
};

TCL_DECLARE_MUTEX(g_register_mutex);
static int				g_register_init = 0;

TCL_DECLARE_MUTEX(g_intreps_mutex);
static Tcl_HashTable	g_intreps;
static int				g_intreps_init = 0;

// Internal API <<<
void free_interp_cx(ClientData cdata, Tcl_Interp* interp) //<<<
{
	struct interp_cx*	l = (struct interp_cx*)cdata;

	for (int i=0; i<L_size; i++) replace_tclobj(&l->lit[i], NULL);

	ckfree(l);
}

//>>>
void register_intrep(Tcl_Obj* obj) //<<<
{
	Tcl_HashEntry*		he = NULL;
	int					new = 0;

	Tcl_MutexLock(&g_intreps_mutex);
	he = Tcl_CreateHashEntry(&g_intreps, obj, &new);
	if (!new) Tcl_Panic("register_intrep: already registered");
	Tcl_SetHashValue(he, obj);
	Tcl_MutexUnlock(&g_intreps_mutex);
}

//>>>
void forget_intrep(Tcl_Obj* obj) //<<<
{
	Tcl_HashEntry*		he = NULL;

	Tcl_MutexLock(&g_intreps_mutex);
	he = Tcl_FindHashEntry(&g_intreps, obj);
	if (!he) Tcl_Panic("forget_intrep: not registered");
	Tcl_DeleteHashEntry(he);
	Tcl_MutexUnlock(&g_intreps_mutex);
}

//>>>
// Internal API >>>
// Script API <<<
OBJCMD(hash_cmd) //<<<
{
	int			code = TCL_OK;

	enum {A_cmd, A_HASH, A_BYTES, A_objc};
	CHECK_ARGS_LABEL(finally, code, "algorithm bytes");

	const int idx = find_hash(Tcl_GetString(objv[A_HASH]));
	if (idx == -1) {
		Tcl_SetErrorCode(interp, "TOMCRYPT", "LOOKUP", "HASH", Tcl_GetString(objv[A_HASH]), NULL);
		THROW_PRINTF_LABEL(finally, code, "Unknown hash %s", Tcl_GetString(objv[A_HASH]));
	}

	hash_state		md;
	const int		hashlen = hash_descriptor[idx].hashsize;
	uint8_t			hash[MAXBLOCKSIZE];
	int				bytes_len;
	const uint8_t*	bytes = Tcl_GetBytesFromObj(interp, objv[A_BYTES], &bytes_len);
	if (bytes == NULL) { code = TCL_ERROR; goto finally; }

	hash_descriptor[idx].init(&md);
	hash_descriptor[idx].process(&md, bytes, bytes_len);
	hash_descriptor[idx].done(&md, hash);

	Tcl_SetObjResult(interp, Tcl_NewByteArrayObj(hash, hashlen));

finally:
	return code;
}

//>>>
OBJCMD(hmac_cmd) //<<<
{
	int				code = TCL_OK;
	unsigned char*	out = NULL;
	unsigned long	outlen;
	Tcl_Obj*		res = NULL;

	enum {A_cmd, A_HASH, A_KEY, A_MSG, A_objc};
	CHECK_ARGS_LABEL(finally, code, "algorithm key message");

	// Find hash algorithm
	const int hash_idx = find_hash(Tcl_GetString(objv[A_HASH]));
	if (hash_idx == -1) {
		Tcl_SetErrorCode(interp, "TOMCRYPT", "LOOKUP", "HASH", Tcl_GetString(objv[A_HASH]), NULL);
		THROW_PRINTF_LABEL(finally, code, "Unknown hash %s", Tcl_GetString(objv[A_HASH]));
	}

	// Get key
	int keylen;
	const unsigned char* key = Tcl_GetBytesFromObj(interp, objv[A_KEY], &keylen);
	if (key == NULL) { code = TCL_ERROR; goto finally; }

	// Get message
	int msglen;
	const unsigned char* msg = Tcl_GetBytesFromObj(interp, objv[A_MSG], &msglen);
	if (msg == NULL) { code = TCL_ERROR; goto finally; }

	// Calculate output size and allocate buffer
	outlen = hash_descriptor[hash_idx].hashsize;
	replace_tclobj(&res, Tcl_NewByteArrayObj(NULL, outlen));
	out = Tcl_GetByteArrayFromObj(res, NULL);

	// Compute HMAC
	int err;
	if ((err = hmac_memory(hash_idx, key, keylen, msg, msglen, out, &outlen)) != CRYPT_OK) {
		Tcl_SetErrorCode(interp, "TOMCRYPT", "HMAC", "COMPUTE", NULL);
		THROW_PRINTF_LABEL(finally, code, "hmac_memory failed: %s", error_to_string(err));
	}

	Tcl_SetObjResult(interp, res);

finally:
	replace_tclobj(&res, NULL);
	return code;
}

//>>>
OBJCMD(base64url_cmd) // Base64 URL encode / decode <<<
{
	int					code = TCL_OK;
	Tcl_Obj*			res = NULL;
	static const char*	modes[] = {
		"encode",
		"strict_encode",
		"decode",
		"strict_decode",
		NULL
	};
	enum {
		M_ENCODE,
		M_STRICT_ENCODE,
		M_DECODE,
		M_STRICT_DECODE,
	} mode;

	enum {A_cmd, A_MODE, A_args};
	CHECK_MIN_ARGS_LABEL(finally, code, "mode ?arg ...?");
	TEST_OK_LABEL(finally, code, Tcl_GetIndexFromObj(interp, objv[A_MODE], modes, "mode", TCL_EXACT, &mode));
	switch (mode) {
		case M_ENCODE:
		case M_STRICT_ENCODE:
			{
				enum {A_cmd=1, A_BYTES, A_objc};
				CHECK_ARGS_LABEL(finally, code, "bytes");

				int				inlen;
				const uint8_t*	in = Tcl_GetBytesFromObj(interp, objv[A_BYTES], &inlen);
				if (in == NULL) { code = TCL_ERROR; goto finally; }

				const int		outlen_int = ((inlen + 2)/3) * 4;
				replace_tclobj(&res, Tcl_NewObj());
				Tcl_SetObjLength(res, outlen_int);
				char*	out = Tcl_GetString(res);
				unsigned long	outlen = outlen_int + 1;	// +1: base64url_*_encode appends NUL terminator

				const int	rc = mode == M_STRICT_ENCODE
					? base64url_strict_encode(in, inlen, out, &outlen)
					:        base64url_encode(in, inlen, out, &outlen);

				if (CRYPT_OK != rc) {
					Tcl_SetErrorCode(interp, "TOMCRYPT", "BASE64URL", "ENCODE", NULL);
					THROW_PRINTF_LABEL(finally, code, "base64url encode failed: %s", error_to_string(rc));
				}

				Tcl_SetObjLength(res, outlen);
			}
			break;

		case M_DECODE:
		case M_STRICT_DECODE:
			{
				enum {A_cmd=1, A_STR, A_objc};
				CHECK_ARGS_LABEL(finally, code, "string");

				int						inlen;
				const char*	in = Tcl_GetStringFromObj(objv[A_STR], &inlen);
				unsigned long			outlen = ((inlen+3)/4) * 3;
				replace_tclobj(&res, Tcl_NewByteArrayObj(NULL, outlen));
				unsigned char*			out = Tcl_GetBytesFromObj(interp, res, NULL);

				const int	rc = mode == M_STRICT_DECODE
					? base64url_strict_decode(in, inlen, out, &outlen)
					:        base64url_decode(in, inlen, out, &outlen);

				if (CRYPT_OK != rc) {
					Tcl_SetErrorCode(interp, "TOMCRYPT", "BASE64URL", "DECODE", NULL);
					THROW_PRINTF_LABEL(finally, code, "base64url decode failed: %s", error_to_string(rc));
				}

				Tcl_SetByteArrayLength(res, outlen);
			}
			break;
	}


	Tcl_SetObjResult(interp, res);

finally:
	replace_tclobj(&res, NULL);
	return code;
}

//>>>
OBJCMD(ecc_make_key_cmd) //<<<
{
	int			code = TCL_OK;
	ecc_key		key = {0};
	int			key_initialized = 0;
	prng_state	prng = {0};
	int			desc_idx;
	Tcl_Obj*	res = NULL;
	Tcl_Obj*	privkey = NULL;
	Tcl_Obj*	pubkey = NULL;

	enum {A_cmd, A_PRNG, A_SIZE, A_objc};
	CHECK_ARGS_LABEL(finally, code, "prng keysize");

	// Get key size
	int keysize;
	TEST_OK_LABEL(finally, code, Tcl_GetIntFromObj(interp, objv[A_SIZE], &keysize));
	if (keysize <= 0) {
		Tcl_SetErrorCode(interp, "TOMCRYPT", "VALUE", NULL);
		THROW_ERROR_LABEL(finally, code, "keysize must be positive");
	}

	// Get PRNG state and descriptor index
	TEST_OK_LABEL(finally, code, GetPrngFromObj(interp, objv[A_PRNG], &prng, &desc_idx));

	// Generate the key
	int err;
	if ((err = ecc_make_key(&prng, desc_idx, keysize, &key)) != CRYPT_OK) {
		Tcl_SetErrorCode(interp, "TOMCRYPT", "ECC", "GENERATE", NULL);
		THROW_PRINTF_LABEL(finally, code, "ecc_make_key failed: %s", error_to_string(err));
	}
	key_initialized = 1;

	// Export private key in internal format
	unsigned char privbuf[512];
	unsigned long privbuflen = sizeof(privbuf);
	if ((err = ecc_export(privbuf, &privbuflen, PK_PRIVATE, &key)) != CRYPT_OK) {
		Tcl_SetErrorCode(interp, "TOMCRYPT", "ECC", "EXPORT", NULL);
		THROW_PRINTF_LABEL(finally, code, "ecc_export failed: %s", error_to_string(err));
	}
	replace_tclobj(&privkey, Tcl_NewByteArrayObj(privbuf, privbuflen));

	// Export public key in X9.63 format
	unsigned char pubbuf[512];
	unsigned long pubbuflen = sizeof(pubbuf);
	if ((err = ecc_ansi_x963_export(&key, pubbuf, &pubbuflen)) != CRYPT_OK) {
		Tcl_SetErrorCode(interp, "TOMCRYPT", "ECC", "EXPORT", NULL);
		THROW_PRINTF_LABEL(finally, code, "ecc_ansi_x963_export failed: %s", error_to_string(err));
	}
	replace_tclobj(&pubkey, Tcl_NewByteArrayObj(pubbuf, pubbuflen));

	// Create result list
	replace_tclobj(&res, Tcl_NewListObj(2, NULL));
	TEST_OK_LABEL(finally, code, Tcl_ListObjAppendElement(interp, res, privkey));
	TEST_OK_LABEL(finally, code, Tcl_ListObjAppendElement(interp, res, pubkey));

	Tcl_SetObjResult(interp, res);

finally:
	if (key_initialized) 
		ecc_free(&key);
	replace_tclobj(&res, NULL);
	replace_tclobj(&privkey, NULL);
	replace_tclobj(&pubkey, NULL);
	return code;
}

//>>>
OBJCMD(ecc_verify) //<<<
{
	struct interp_cx*	l = cdata;
	int					code = TCL_OK;

	enum {A_cmd, A_SIG, A_HASH, A_KEY, A_objc};
	CHECK_ARGS_LABEL(finally, code, "sig message key");

	ecc_key*	key = NULL;
	TEST_OK_LABEL(finally, code, GetECCKeyFromObj(interp, objv[A_KEY], ECC_EXPECT_PUBLIC, &key));

	int				siglen, msglen, stat;
	const uint8_t*	sig = Tcl_GetBytesFromObj(interp, objv[A_SIG],  &siglen);
	if (sig == NULL) { code = TCL_ERROR; goto finally; }
	const uint8_t*	msg = Tcl_GetBytesFromObj(interp, objv[A_HASH], &msglen);
	if (msg == NULL) { code = TCL_ERROR; goto finally; }
	const int		verify_rc = ecc_verify_hash(sig, siglen, msg, msglen, &stat, key);
	if (verify_rc != CRYPT_OK) {
		Tcl_SetErrorCode(interp, "TOMCRYPT", "FORMAT", NULL);
		THROW_PRINTF_LABEL(finally, code, "ecc_verify_hash failed: %s", error_to_string(verify_rc));
	}

	Tcl_SetObjResult(interp, l->lit[stat ? L_TRUE : L_FALSE]);

finally:
	return code;
}

//>>>
OBJCMD(ecc_sign_cmd) //<<<
{
	int			code = TCL_OK;
	ecc_key*	key = NULL;
	prng_state	prng = {0};
	int			desc_idx;
	Tcl_Obj*	res = NULL;

	enum {A_cmd, A_PRIVKEY, A_MSG, A_args, A_objc};
	const int A_PRNG = A_args;
	CHECK_RANGE_ARGS_LABEL(finally, code, "privkey message ?prng?");

	// Get the private key
	TEST_OK_LABEL(finally, code, GetECCKeyFromObj(interp, objv[A_PRIVKEY], ECC_EXPECT_PRIVATE, &key));
	if (key->type != PK_PRIVATE) {
		Tcl_SetErrorCode(interp, "TOMCRYPT", "KEY", "TYPE", NULL);
		THROW_ERROR_LABEL(finally, code, "key is not a private key");
	}

	// Get message to sign
	int msglen;
	const unsigned char* msg = Tcl_GetBytesFromObj(interp, objv[A_MSG], &msglen);
	if (msg == NULL) { code = TCL_ERROR; goto finally; }

	// Get PRNG details - either from supplied prng or use system prng
	if (objc > A_PRNG) {
		// Use supplied PRNG
		TEST_OK_LABEL(finally, code, GetPrngFromObj(interp, objv[A_PRNG], &prng, &desc_idx));
	} else {
		// Use system PRNG
		desc_idx = find_prng("sprng");
	}

	// Allocate signature buffer - start with a reasonable size
	unsigned long siglen = 256;  // Should be plenty for ECC signatures
	replace_tclobj(&res, Tcl_NewByteArrayObj(NULL, siglen));
	unsigned char* sig = Tcl_GetByteArrayFromObj(res, NULL);

	// Sign the message
	int err;
	if ((err = ecc_sign_hash(msg, msglen, sig, &siglen, objc > A_PRNG ? &prng : NULL, desc_idx, key)) != CRYPT_OK) {
		Tcl_SetErrorCode(interp, "TOMCRYPT", "ECC", "SIGN", NULL);
		THROW_PRINTF_LABEL(finally, code, "ecc_sign_hash failed: %s", error_to_string(err));
	}

	// Adjust the byte array length to match the actual signature size
	Tcl_SetByteArrayLength(res, siglen);
	Tcl_SetObjResult(interp, res);

finally:
	replace_tclobj(&res, NULL);
	return code;
}

//>>>
OBJCMD(rng_bytes) //<<<
{
	int				code = TCL_OK;
	Tcl_Obj*		res = NULL;

	enum {A_cmd, A_BYTES, A_objc};
	CHECK_ARGS_LABEL(finally, code, "count");

	int	count;
	TEST_OK_LABEL(finally, code, Tcl_GetIntFromObj(interp, objv[A_BYTES], &count));
	if (count < 0) {
		Tcl_SetErrorCode(interp, "TOMCRYPT", "VALUE", NULL);
		THROW_ERROR_LABEL(finally, code, "count cannot be negative");
	}
	replace_tclobj(&res, Tcl_NewByteArrayObj(NULL, count));
	uint8_t*	bytes = Tcl_GetByteArrayFromObj(res, NULL);
	int			remain = count;
	while (remain) {
		const unsigned long got = rng_get_bytes(bytes+(count-remain), remain, NULL);
		if (got <= 0) THROW_ERROR_LABEL(finally, code, "Failed to read rng bytes");
		remain -= got;
	}

	Tcl_SetObjResult(interp, res);

finally:
	replace_tclobj(&res, NULL);
	return code;
}

//>>>
OBJCMD(rsa_make_key_cmd) //<<<
{
	int			code = TCL_OK;
	rsa_key*	key = NULL;
	int			key_initialized = 0;
	prng_state	prng = {0};
	int			prng_desc_idx = -1;
	int			keysize = 2048;
	long		exponent = 65537;

	for (int i=1; i<objc; i++) {
		static const char *opts[] = {
			"-keysize",
			"-exponent", 
			"-prng",
			NULL
		};
		enum optvals {
			OPT_KEYSIZE,
			OPT_EXPONENT,
			OPT_PRNG,
		} opt;
		int optidx;

#define REQUIRE_OPT_VAL \
		do { \
			if (i+1 >= objc) { \
				Tcl_SetErrorCode(interp, "TOMCRYPT", "ARGUMENT", "MISSING", opts[opt], NULL); \
				THROW_ERROR_LABEL(finally, code, "Missing argument for ", opts[opt]); \
			} \
		} while (0)

		TEST_OK_LABEL(finally, code, Tcl_GetIndexFromObj(interp, objv[i], opts, "option", TCL_EXACT, &optidx)); opt = optidx;
		REQUIRE_OPT_VAL;
		switch (opt) {
			case OPT_KEYSIZE:
				TEST_OK_LABEL(finally, code, Tcl_GetIntFromObj(interp, objv[++i], &keysize));
				if (keysize < 1024 || keysize > 4096 || keysize % 8) {
					Tcl_SetErrorCode(interp, "TOMCRYPT", "VALUE", NULL);
					THROW_ERROR_LABEL(finally, code, "keysize must be a multiple of 8 between 1024 and 4096 bits");
				}
				break;

			case OPT_EXPONENT:
				TEST_OK_LABEL(finally, code, Tcl_GetLongFromObj(interp, objv[++i], &exponent));
				if (exponent < 3) {
					Tcl_SetErrorCode(interp, "TOMCRYPT", "VALUE", NULL);
					THROW_ERROR_LABEL(finally, code, "exponent must be at least 3");
				}
				break;

			case OPT_PRNG:
				TEST_OK_LABEL(finally, code, GetPrngFromObj(interp, objv[++i], &prng, &prng_desc_idx));
				break;

			default:
				THROW_PRINTF_LABEL(finally, code, "Invalid opt %d", opt);
		}
#undef REQUIRE_OPT_VAL
	}

	if (prng_desc_idx == -1) {
		// Use system PRNG
		prng_desc_idx = find_prng("sprng");
	}

	// Generate the key
	key = ckalloc(sizeof(*key));
	*key = (rsa_key){0};
	int err;
	if ((err = rsa_make_key(prng_desc_idx != -1 ? &prng : NULL, prng_desc_idx, keysize/8, exponent, key)) != CRYPT_OK) {
		Tcl_SetErrorCode(interp, "TOMCRYPT", "RSA", "GENERATE", NULL);
		THROW_PRINTF_LABEL(finally, code, "rsa_make_key failed: %s", error_to_string(err));
	}
	key_initialized = 1;

	Tcl_SetObjResult(interp, NewRSAKeyObj(&key));

finally:
	if (key && key_initialized) rsa_free(key);
	if (key) {ckfree(key); key = NULL;}
	return code;
}

//>>>
OBJCMD(rsa_extract_pubkey_cmd) //<<<
{
	int			code = TCL_OK;
	rsa_key*	key = NULL;
	rsa_key*	pbkey = NULL;
	int			key_initialized = 0;

	enum {A_cmd, A_PRIVKEY, A_objc};
	CHECK_ARGS_LABEL(finally, code, "privkey");

	// Get the private key
	TEST_OK_LABEL(finally, code, GetRSAKeyFromObj(interp, objv[A_PRIVKEY], RSA_EXPECT_PRIVATE, &key));

	// Extract public key
	unsigned char pubbuf[2048];
	unsigned long pubbuflen = sizeof(pubbuf);
	int err;
	if ((err = rsa_export(pubbuf, &pubbuflen, PK_PUBLIC, key)) != CRYPT_OK) {
		Tcl_SetErrorCode(interp, "TOMCRYPT", "RSA", "EXPORT", NULL);
		THROW_PRINTF_LABEL(finally, code, "rsa_export failed: %s", error_to_string(err));
	}

	// Import as a pure public key
	pbkey = ckalloc(sizeof(*pbkey));
	*pbkey = (rsa_key){0};
	if ((err = rsa_import(pubbuf, pubbuflen, pbkey)) != CRYPT_OK) {
		Tcl_SetErrorCode(interp, "TOMCRYPT", "RSA", "IMPORT", NULL);
		THROW_PRINTF_LABEL(finally, code, "rsa_import failed: %s", error_to_string(err));
	}
	key_initialized = 1;

	Tcl_SetObjResult(interp, NewRSAKeyObj(&pbkey));

finally:
	if (pbkey && key_initialized) rsa_free(pbkey);
	if (pbkey) {ckfree(pbkey); pbkey = NULL;}
	return code;
}

//>>>
OBJCMD(rsa_sign_hash_cmd) //<<<
{
	int						code = TCL_OK;
	rsa_key*				key = NULL;
	prng_state				prng = {0};
	int						prng_desc_idx = -1;
	Tcl_Obj*				res = NULL;
	const unsigned char*	in = NULL;
	int						inlen = 0;
	int						padding = LTC_PKCS_1_PSS;
	int						hash_idx = -1;
	unsigned long			saltlen = 0;

	for (int i=1; i<objc; i++) {
		static const char *opts[] = {
			"-key",
			"-hash",
			"-padding",
			"-prng",
			"-hashalg",
			"-saltlen",
			NULL
		};
		enum optvals {
			OPT_KEY,
			OPT_HASH,
			OPT_PADDING,
			OPT_PRNG,
			OPT_HASHALG,
			OPT_SALTLEN,
		} opt;
		int optidx;

#define REQUIRE_OPT_VAL \
		do { \
			if (i+1 >= objc) { \
				Tcl_SetErrorCode(interp, "TOMCRYPT", "ARGUMENT", "MISSING", opts[opt], NULL); \
				THROW_ERROR_LABEL(finally, code, "Missing argument for ", opts[opt]); \
			} \
		} while (0)

		TEST_OK_LABEL(finally, code, Tcl_GetIndexFromObj(interp, objv[i], opts, "option", TCL_EXACT, &optidx)); opt = optidx;
		REQUIRE_OPT_VAL;
		switch (opt) {
			case OPT_KEY:
				TEST_OK_LABEL(finally, code, GetRSAKeyFromObj(interp, objv[++i], RSA_EXPECT_PRIVATE, &key));
				break;

			case OPT_HASH:
				in = Tcl_GetBytesFromObj(interp, objv[++i], &inlen);
				if (in == NULL) { code = TCL_ERROR; goto finally; }
				break;

			case OPT_PADDING:
			{
				static const char* padding_types[] = {"v1.5", "pss", "v1.5_na1", NULL};
				static int padding_map[] = {LTC_PKCS_1_V1_5, LTC_PKCS_1_PSS, LTC_PKCS_1_V1_5_NA1};
				int padding_idx;
				TEST_OK_LABEL(finally, code, Tcl_GetIndexFromObj(interp, objv[++i], padding_types, "padding", TCL_EXACT, &padding_idx));
				if (padding_idx < 0 || padding_idx > sizeof(padding_map)/sizeof(padding_map[0])) {
					Tcl_SetErrorCode(interp, "TOMCRYPT", "VALUE", NULL);
					THROW_ERROR_LABEL(finally, code, "Invalid padding type");
				}
				padding = padding_map[padding_idx];
				break;
			}

			case OPT_PRNG:
				TEST_OK_LABEL(finally, code, GetPrngFromObj(interp, objv[++i], &prng, &prng_desc_idx));
				break;

			case OPT_HASHALG:
				hash_idx = find_hash(Tcl_GetString(objv[++i]));
				if (hash_idx == -1) {
					Tcl_SetErrorCode(interp, "TOMCRYPT", "LOOKUP", "HASH", Tcl_GetString(objv[i]), NULL);
					THROW_PRINTF_LABEL(finally, code, "Unknown hash %s", Tcl_GetString(objv[i]));
				}
				break;

			case OPT_SALTLEN:
			{
				Tcl_WideInt	tmpint;
				TEST_OK_LABEL(finally, code, Tcl_GetWideIntFromObj(interp, objv[++i], &tmpint));
				if (tmpint < 0) {
					Tcl_SetErrorCode(interp, "TOMCRYPT", "VALUE", NULL);
					THROW_ERROR_LABEL(finally, code, "salt length cannot be negative");
				}
				if (tmpint > 0xFFFFFFFF) {
					Tcl_SetErrorCode(interp, "TOMCRYPT", "VALUE", NULL);
					THROW_ERROR_LABEL(finally, code, "salt length too large");
				}
				saltlen = (unsigned long)tmpint;
			}
		}
#undef REQUIRE_OPT_VAL
	}

	if (!key) {
		Tcl_SetErrorCode(interp, "TOMCRYPT", "ARGUMENT", "MISSING", "-key", NULL);
		THROW_ERROR_LABEL(finally, code, "Missing -key argument");
	}
	if (!in) {
		Tcl_SetErrorCode(interp, "TOMCRYPT", "ARGUMENT", "MISSING", "-hash", NULL);
		THROW_ERROR_LABEL(finally, code, "Missing -hash argument");
	}

	if (padding != LTC_PKCS_1_PSS && prng_desc_idx != -1) {
		THROW_ERROR_LABEL(finally, code, "-prng only applies to pss padding");
	} else if (prng_desc_idx == -1) {
		// Use system PRNG
		prng_desc_idx = find_prng("sprng");
	}

	if (padding == LTC_PKCS_1_V1_5_NA1 && hash_idx != -1) {
		THROW_ERROR_LABEL(finally, code, "-hash does not apply for v1.5_na1 padding");
	} else if (hash_idx == -1) {
		hash_idx = find_hash("sha256"); // Use sha256 as default hash
	}

	if (padding == LTC_PKCS_1_PSS && saltlen > rsa_sign_saltlen_get_max(hash_idx, key)) {
		Tcl_SetErrorCode(interp, "TOMCRYPT", "VALUE", "-saltlen", NULL);
		THROW_PRINTF_LABEL(finally, code, "salt length %lu exceeds maximum %u", saltlen, rsa_sign_saltlen_get_max(hash_idx, key));
	}

	// Allocate signature buffer
	unsigned long siglen = rsa_get_size(key);
	replace_tclobj(&res, Tcl_NewByteArrayObj(NULL, siglen));
	unsigned char* sig = Tcl_GetByteArrayFromObj(res, NULL);

	int err;
	if ((err = rsa_sign_hash_ex(in, inlen, sig, &siglen, padding, &prng, prng_desc_idx, hash_idx, saltlen, key)) != CRYPT_OK) {
		Tcl_SetErrorCode(interp, "TOMCRYPT", "RSA", "SIGN", NULL);
		THROW_PRINTF_LABEL(finally, code, "rsa_sign_hash_ex failed: %s", error_to_string(err));
	}

	// Adjust the byte array length to match the actual signature size
	Tcl_SetByteArrayLength(res, siglen);
	Tcl_SetObjResult(interp, res);

finally:
	replace_tclobj(&res, NULL);
	return code;
}

//>>>
OBJCMD(rsa_verify_hash_cmd) //<<<
{
	struct interp_cx*		l = cdata;
	int						code = TCL_OK;
	rsa_key*				key = NULL;
	const unsigned char*	sig = NULL;
	int						siglen = 0;
	const unsigned char*	hash = NULL;
	int						hashlen = 0;
	int						padding = LTC_PKCS_1_PSS;
	int						hash_idx = -1;
	unsigned long			saltlen = 0;

	for (int i=1; i<objc; i++) {
		static const char *opts[] = {
			"-key",
			"-sig",
			"-hash",
			"-padding",
			"-hashalg",
			"-saltlen",
			NULL
		};
		enum optvals {
			OPT_KEY,
			OPT_SIG,
			OPT_HASH,
			OPT_PADDING,
			OPT_HASHALG,
			OPT_SALTLEN,
		} opt;
		int optidx;

#define REQUIRE_OPT_VAL \
		do { \
			if (i+1 >= objc) { \
				Tcl_SetErrorCode(interp, "TOMCRYPT", "ARGUMENT", "MISSING", opts[opt], NULL); \
				THROW_ERROR_LABEL(finally, code, "Missing argument for ", opts[opt]); \
			} \
		} while (0)

		TEST_OK_LABEL(finally, code, Tcl_GetIndexFromObj(interp, objv[i], opts, "option", TCL_EXACT, &optidx)); opt = optidx;
		REQUIRE_OPT_VAL;
		switch (opt) {
			case OPT_KEY:
				TEST_OK_LABEL(finally, code, GetRSAKeyFromObj(interp, objv[++i], RSA_EXPECT_PUBLIC, &key));
				break;

			case OPT_SIG:
				sig = Tcl_GetBytesFromObj(interp, objv[++i], &siglen);
				if (sig == NULL) { code = TCL_ERROR; goto finally; }
				break;

			case OPT_HASH:
				hash = Tcl_GetBytesFromObj(interp, objv[++i], &hashlen);
				if (hash == NULL) { code = TCL_ERROR; goto finally; }
				break;

			case OPT_PADDING:
			{
				static const char* padding_types[] = {"v1.5", "pss", "v1.5_na1", NULL};
				static int padding_map[] = {LTC_PKCS_1_V1_5, LTC_PKCS_1_PSS, LTC_PKCS_1_V1_5_NA1};
				int padding_idx;
				TEST_OK_LABEL(finally, code, Tcl_GetIndexFromObj(interp, objv[++i], padding_types, "padding", TCL_EXACT, &padding_idx));
				if (padding_idx < 0 || padding_idx >= sizeof(padding_map)/sizeof(padding_map[0])) {
					Tcl_SetErrorCode(interp, "TOMCRYPT", "VALUE", NULL);
					THROW_ERROR_LABEL(finally, code, "Invalid padding type");
				}
				padding = padding_map[padding_idx];
				break;
			}

			case OPT_HASHALG:
				hash_idx = find_hash(Tcl_GetString(objv[++i]));
				if (hash_idx == -1) {
					Tcl_SetErrorCode(interp, "TOMCRYPT", "LOOKUP", "HASH", Tcl_GetString(objv[i]), NULL);
					THROW_PRINTF_LABEL(finally, code, "Unknown hash %s", Tcl_GetString(objv[i]));
				}
				break;

			case OPT_SALTLEN:
			{
				Tcl_WideInt	tmpint;
				TEST_OK_LABEL(finally, code, Tcl_GetWideIntFromObj(interp, objv[++i], &tmpint));
				if (tmpint < 0) {
					Tcl_SetErrorCode(interp, "TOMCRYPT", "VALUE", NULL);
					THROW_ERROR_LABEL(finally, code, "salt length cannot be negative");
				}
				if (tmpint > 0xFFFFFFFF) {
					Tcl_SetErrorCode(interp, "TOMCRYPT", "VALUE", NULL);
					THROW_ERROR_LABEL(finally, code, "salt length too large");
				}
				saltlen = (unsigned long)tmpint;
				break;
			}
		}
#undef REQUIRE_OPT_VAL
	}

	if (!key) {
		Tcl_SetErrorCode(interp, "TOMCRYPT", "ARGUMENT", "MISSING", "-key", NULL);
		THROW_ERROR_LABEL(finally, code, "Missing -key argument");
	}
	if (!sig) {
		Tcl_SetErrorCode(interp, "TOMCRYPT", "ARGUMENT", "MISSING", "-sig", NULL);
		THROW_ERROR_LABEL(finally, code, "Missing -sig argument");
	}
	if (!hash) {
		Tcl_SetErrorCode(interp, "TOMCRYPT", "ARGUMENT", "MISSING", "-hash", NULL);
		THROW_ERROR_LABEL(finally, code, "Missing -hash argument");
	}

	if (padding == LTC_PKCS_1_V1_5_NA1 && hash_idx != -1) {
		THROW_ERROR_LABEL(finally, code, "-hashalg does not apply for v1.5_na1 padding");
	} else if (hash_idx == -1) {
		hash_idx = find_hash("sha256"); // Use sha256 as default hash
	}

	int stat;
	const int verify_rc = rsa_verify_hash_ex(sig, siglen, hash, hashlen, padding, hash_idx, saltlen, &stat, key);
	if (verify_rc != CRYPT_OK) {
		Tcl_SetErrorCode(interp, "TOMCRYPT", "RSA", "VERIFY", NULL);
		THROW_PRINTF_LABEL(finally, code, "rsa_verify_hash_ex failed: %s", error_to_string(verify_rc));
	}

	Tcl_SetObjResult(interp, l->lit[stat ? L_TRUE : L_FALSE]);

finally:
	return code;
}

//>>>
OBJCMD(rsa_encrypt_key_cmd) //<<<
{
	int						code = TCL_OK;
	rsa_key*				key = NULL;
	prng_state				prng = {0};
	int						prng_desc_idx = -1;
	Tcl_Obj*				res = NULL;
	const unsigned char*	msg = NULL;
	int						msglen = 0;
	int						padding = LTC_PKCS_1_OAEP;
	int						hash_idx = -1;
	const unsigned char*	lparam = NULL;
	int						lparamlen = 0;

	for (int i=1; i<objc; i++) {
		static const char *opts[] = {
			"-key",
			"-msg",
			"-padding",
			"-prng",
			"-hashalg",
			"-lparam",
			NULL
		};
		enum optvals {
			OPT_KEY,
			OPT_MSG,
			OPT_PADDING,
			OPT_PRNG,
			OPT_HASHALG,
			OPT_LPARAM,
		} opt;
		int optidx;

#define REQUIRE_OPT_VAL \
		do { \
			if (i+1 >= objc) { \
				Tcl_SetErrorCode(interp, "TOMCRYPT", "ARGUMENT", "MISSING", opts[opt], NULL); \
				THROW_ERROR_LABEL(finally, code, "Missing argument for ", opts[opt]); \
			} \
		} while (0)

		TEST_OK_LABEL(finally, code, Tcl_GetIndexFromObj(interp, objv[i], opts, "option", TCL_EXACT, &optidx)); opt = optidx;
		REQUIRE_OPT_VAL;
		switch (opt) {
			case OPT_KEY:
				TEST_OK_LABEL(finally, code, GetRSAKeyFromObj(interp, objv[++i], RSA_EXPECT_PUBLIC, &key));
				break;

			case OPT_MSG:
				msg = Tcl_GetBytesFromObj(interp, objv[++i], &msglen);
				if (msg == NULL) { code = TCL_ERROR; goto finally; }
				break;

			case OPT_PADDING:
			{
				static const char* padding_types[] = {"v1.5", "oaep", NULL};
				static int padding_map[] = {LTC_PKCS_1_V1_5, LTC_PKCS_1_OAEP};
				int padding_idx;
				TEST_OK_LABEL(finally, code, Tcl_GetIndexFromObj(interp, objv[++i], padding_types, "padding", TCL_EXACT, &padding_idx));
				if (padding_idx < 0 || padding_idx >= sizeof(padding_map)/sizeof(padding_map[0])) {
					Tcl_SetErrorCode(interp, "TOMCRYPT", "VALUE", NULL);
					THROW_ERROR_LABEL(finally, code, "Invalid padding type");
				}
				padding = padding_map[padding_idx];
				break;
			}

			case OPT_PRNG:
				TEST_OK_LABEL(finally, code, GetPrngFromObj(interp, objv[++i], &prng, &prng_desc_idx));
				break;

			case OPT_HASHALG:
				hash_idx = find_hash(Tcl_GetString(objv[++i]));
				if (hash_idx == -1) {
					Tcl_SetErrorCode(interp, "TOMCRYPT", "LOOKUP", "HASH", Tcl_GetString(objv[i]), NULL);
					THROW_PRINTF_LABEL(finally, code, "Unknown hash %s", Tcl_GetString(objv[i]));
				}
				break;

			case OPT_LPARAM:
				lparam = Tcl_GetBytesFromObj(interp, objv[++i], &lparamlen);
				if (lparam == NULL) { code = TCL_ERROR; goto finally; }
				break;
		}
#undef REQUIRE_OPT_VAL
	}

	if (!key) {
		Tcl_SetErrorCode(interp, "TOMCRYPT", "ARGUMENT", "MISSING", "-key", NULL);
		THROW_ERROR_LABEL(finally, code, "Missing -key argument");
	}
	if (!msg) {
		Tcl_SetErrorCode(interp, "TOMCRYPT", "ARGUMENT", "MISSING", "-msg", NULL);
		THROW_ERROR_LABEL(finally, code, "Missing -msg argument");
	}

	if (padding == LTC_PKCS_1_V1_5 && hash_idx != -1) {
		THROW_ERROR_LABEL(finally, code, "-hashalg does not apply for v1.5 padding");
	} else if (padding == LTC_PKCS_1_OAEP && hash_idx == -1) {
		hash_idx = find_hash("sha256"); // Use sha256 as default hash for OAEP
	}

	if (prng_desc_idx == -1) {
		// Use system PRNG
		prng_desc_idx = find_prng("sprng");
	}

	// Allocate output buffer
	unsigned long outlen = rsa_get_size(key);
	replace_tclobj(&res, Tcl_NewByteArrayObj(NULL, outlen));
	unsigned char* out = Tcl_GetByteArrayFromObj(res, NULL);

	int err;
	if ((err = rsa_encrypt_key_ex(msg, msglen, out, &outlen, 
						 lparamlen > 0 ? lparam : NULL, lparamlen,
						 prng_desc_idx != -1 ? &prng : NULL, prng_desc_idx, hash_idx, hash_idx, padding, key)) != CRYPT_OK) {
		Tcl_SetErrorCode(interp, "TOMCRYPT", "RSA", "ENCRYPT", NULL);
		THROW_PRINTF_LABEL(finally, code, "rsa_encrypt_key_ex failed: %s", error_to_string(err));
	}

	// Adjust the byte array length to match the actual output size
	Tcl_SetByteArrayLength(res, outlen);
	Tcl_SetObjResult(interp, res);

finally:
	replace_tclobj(&res, NULL);
	return code;
}

//>>>
OBJCMD(rsa_decrypt_key_cmd) //<<<
{
	int						code = TCL_OK;
	rsa_key*				key = NULL;
	Tcl_Obj*				res = NULL;
	const unsigned char*	ciphertext = NULL;
	int						ctlen = 0;
	int						padding = LTC_PKCS_1_OAEP;
	int						hash_idx = -1;
	const unsigned char*	lparam = NULL;
	int						lparamlen = 0;

	for (int i=1; i<objc; i++) {
		static const char *opts[] = {
			"-key",
			"-ciphertext",
			"-padding",
			"-hashalg",
			"-lparam",
			NULL
		};
		enum optvals {
			OPT_KEY,
			OPT_CIPHERTEXT,
			OPT_PADDING,
			OPT_HASHALG,
			OPT_LPARAM,
		} opt;
		int optidx;

#define REQUIRE_OPT_VAL \
		do { \
			if (i+1 >= objc) { \
				Tcl_SetErrorCode(interp, "TOMCRYPT", "ARGUMENT", "MISSING", opts[opt], NULL); \
				THROW_ERROR_LABEL(finally, code, "Missing argument for ", opts[opt]); \
			} \
		} while (0)

		TEST_OK_LABEL(finally, code, Tcl_GetIndexFromObj(interp, objv[i], opts, "option", TCL_EXACT, &optidx)); opt = optidx;
		REQUIRE_OPT_VAL;
		switch (opt) {
			case OPT_KEY:
				TEST_OK_LABEL(finally, code, GetRSAKeyFromObj(interp, objv[++i], RSA_EXPECT_PRIVATE, &key));
				break;

			case OPT_CIPHERTEXT:
				ciphertext = Tcl_GetBytesFromObj(interp, objv[++i], &ctlen);
				if (ciphertext == NULL) { code = TCL_ERROR; goto finally; }
				break;

			case OPT_PADDING:
			{
				static const char* padding_types[] = {"v1.5", "oaep", NULL};
				static int padding_map[] = {LTC_PKCS_1_V1_5, LTC_PKCS_1_OAEP};
				int padding_idx;
				TEST_OK_LABEL(finally, code, Tcl_GetIndexFromObj(interp, objv[++i], padding_types, "padding", TCL_EXACT, &padding_idx));
				if (padding_idx < 0 || padding_idx >= sizeof(padding_map)/sizeof(padding_map[0])) {
					Tcl_SetErrorCode(interp, "TOMCRYPT", "VALUE", NULL);
					THROW_ERROR_LABEL(finally, code, "Invalid padding type");
				}
				padding = padding_map[padding_idx];
				break;
			}

			case OPT_HASHALG:
				hash_idx = find_hash(Tcl_GetString(objv[++i]));
				if (hash_idx == -1) {
					Tcl_SetErrorCode(interp, "TOMCRYPT", "LOOKUP", "HASH", Tcl_GetString(objv[i]), NULL);
					THROW_PRINTF_LABEL(finally, code, "Unknown hash %s", Tcl_GetString(objv[i]));
				}
				break;

			case OPT_LPARAM:
				lparam = Tcl_GetBytesFromObj(interp, objv[++i], &lparamlen);
				if (lparam == NULL) { code = TCL_ERROR; goto finally; }
				break;
		}
#undef REQUIRE_OPT_VAL
	}

	if (!key) {
		Tcl_SetErrorCode(interp, "TOMCRYPT", "ARGUMENT", "MISSING", "-key", NULL);
		THROW_ERROR_LABEL(finally, code, "Missing -key argument");
	}
	if (!ciphertext) {
		Tcl_SetErrorCode(interp, "TOMCRYPT", "ARGUMENT", "MISSING", "-ciphertext", NULL);
		THROW_ERROR_LABEL(finally, code, "Missing -ciphertext argument");
	}

	if (padding == LTC_PKCS_1_V1_5 && hash_idx != -1) {
		THROW_ERROR_LABEL(finally, code, "-hashalg does not apply for v1.5 padding");
	} else if (padding == LTC_PKCS_1_OAEP && hash_idx == -1) {
		hash_idx = find_hash("sha256"); // Use sha256 as default hash for OAEP
	}

	// Allocate output buffer
	unsigned long outlen = rsa_get_size(key);
	replace_tclobj(&res, Tcl_NewByteArrayObj(NULL, outlen));
	unsigned char* out = Tcl_GetByteArrayFromObj(res, NULL);

	int stat;
	int err;
	if ((err = rsa_decrypt_key_ex(ciphertext, ctlen, out, &outlen, lparam, lparamlen, hash_idx, hash_idx, padding, &stat, key)) != CRYPT_OK) {
		Tcl_SetErrorCode(interp, "TOMCRYPT", "RSA", "DECRYPT", NULL);
		THROW_PRINTF_LABEL(finally, code, "rsa_decrypt_key_ex failed: %s", error_to_string(err));
	}

	if (!stat) {
		Tcl_SetErrorCode(interp, "TOMCRYPT", "RSA", "DECRYPT", "OAEP", NULL);
		THROW_ERROR_LABEL(finally, code, "Invalid ciphertext or padding");
	}

	// Adjust the byte array length to match the actual output size
	Tcl_SetByteArrayLength(res, outlen);
	Tcl_SetObjResult(interp, res);

finally:
	replace_tclobj(&res, NULL);
	return code;
}

//>>>
#if TESTMODE
OBJCMD(hasGetBytesFromObj) //<<<
{
	int					code = TCL_OK;
	struct interp_cx*	l = cdata;

	enum {A_cmd, A_objc};
	CHECK_ARGS_LABEL(finally, code);

	// For now - we don't implement a polyfill yet
	Tcl_SetObjResult(interp, l->lit[L_TRUE]);

finally:
	return code;
}

//>>>
OBJCMD(isByteArray) // Snoop on the objtype, use this rather than parse tcl::unsupported::representation because that upsets valgrind <<<
{
	int					code = TCL_OK;
	struct interp_cx*	l = cdata;

	enum {A_cmd, A_OBJ, A_objc};
	CHECK_ARGS_LABEL(finally, code, "value");

#if TCL_MAJOR_VERSION < 9
	// Have to assume old typePtr handling because 8.7 registers the legacy bytearray type for "bytearray",
	// and leaves out the properByteArrayType, so we can't test for it.
	Tcl_SetObjResult(interp, l->lit[
			objv[A_OBJ]->typePtr &&
			strcmp(objv[A_OBJ]->typePtr->name, "bytearray") == 0
				? L_TRUE
				: L_FALSE
	]);
#else
	const Tcl_ObjType*		tclByteArrayType = Tcl_GetObjType("bytearray");
	if (tclByteArrayType == NULL) THROW_ERROR_LABEL(finally, code, "Failed to lookup bytearray type");

	Tcl_ObjInternalRep*	ir = Tcl_FetchInternalRep(objv[A_OBJ], tclByteArrayType);
	Tcl_SetObjResult(interp, l->lit[ir ? L_TRUE : L_FALSE]);
#endif

finally:
	return code;
}

//>>>
OBJCMD(leakObj) // Deliberately leak a Tcl_Obj <<<
{
	int					code = TCL_OK;
	Tcl_Obj*			leaked = NULL;

	enum {A_cmd, A_OBJ, A_objc};
	CHECK_ARGS_LABEL(finally, code, "value");

	// Duplicate this obj so that this function is in the call stack for the
	// allocation, so we can write a valgrind suppression for it
	int				len;
	const uint8_t*	bytes = Tcl_GetBytesFromObj(interp, objv[A_OBJ], &len);
	if (bytes == NULL) { code = TCL_ERROR; goto finally; }
	replace_tclobj(&leaked, Tcl_NewByteArrayObj(bytes, len));
	fprintf(stderr, "Deliberately leaking %p\n", leaked);

	Tcl_SetObjResult(interp, leaked);

finally:
	return code;
}

//>>>
OBJCMD(dupObj) // Force duplicate a Tcl_Obj <<<
{
	int					code = TCL_OK;

	enum {A_cmd, A_OBJ, A_objc};
	CHECK_ARGS_LABEL(finally, code, "value");

	Tcl_SetObjResult(interp, Tcl_DuplicateObj(objv[A_OBJ]));

finally:
	return code;
}

//>>>
OBJCMD(refCount) // Inspect a Tcl_Obj's refCount <<<
{
	int					code = TCL_OK;

	enum {A_cmd, A_OBJ, A_objc};
	CHECK_ARGS_LABEL(finally, code, "value");

	Tcl_SetObjResult(interp, Tcl_NewIntObj(objv[A_OBJ]->refCount));

finally:
	return code;
}

//>>>
OBJCMD(doubleMatissaHist) // Somewhat inaccurately named, returns the bit==1 count histogram for d, for the double arg as if it were in the form d/(52<<5), in 5 bit fractional part fixed point int.  To meet the claimed uniform distribution and uniform spacing, this histogram should have .5 probability for bits 0 through 52 in the whole portion (<<5) and 0 everywhere else <<<
{
	int					code = TCL_OK;
	Tcl_Obj*			get_double = NULL;
	Tcl_Obj*			res = NULL;

	enum {A_cmd, A_CMD, A_IT, A_objc};
	CHECK_ARGS_LABEL(finally, code, "cmd iterations");
	Tcl_WideInt		it;
	TEST_OK_LABEL(finally, code, Tcl_GetWideIntFromObj(interp, objv[A_IT], &it));
	if (it < 0) {
		Tcl_SetErrorCode(interp, "TOMCRYPT", "VALUE", NULL);
		THROW_ERROR_LABEL(finally, code, "iterations cannot be negative");
	}

	if (sizeof (double) != sizeof (uint64_t))
		THROW_ERROR_LABEL(finally, code, "double and uint64_t are not the same size, platform not supported");

	replace_tclobj(&get_double, Tcl_ObjPrintf("[%s]", Tcl_GetString(objv[A_CMD])));

#define BITS	64
	uint64_t	hist[BITS] = {0};

	for (Tcl_WideInt i=0; i<it; i++) {
		double		val;
		uint64_t	ival;
		TEST_OK_LABEL(finally, code, Tcl_ExprDoubleObj(interp, get_double, &val));
		memcpy(&ival, &val, sizeof ival);
		const int sign = ival >> 63;

		ival &= ~(UINT64_C(1) << 63);	// Clear the sign bit
		const int exp = ((ival >> 52) & 0x7ff);
		const int shift = exp - 1023 + 5;

		uint64_t       ival2 = ival & ((UINT64_C(1) << 52) -1);	// Clear the exponent and sign

		if (exp != 0)  ival2 |= UINT64_C(1) << 52;	// Set the implicit 1 bit

		if (shift < 0) ival2 >>= -shift;
		else           ival2 <<= shift;

		if (sign)      ival2 = -ival2;

		for (int j=0; j<BITS; j++)
			if (ival2 & (UINT64_C(1) << j)) hist[j]++;
	}

	replace_tclobj(&res, Tcl_NewListObj(BITS, NULL));
	for (int i=0; i<BITS; i++)
		Tcl_ListObjAppendElement(interp, res, Tcl_NewIntObj(hist[i]));

	Tcl_SetObjResult(interp, res);

finally:
#undef BITS
	replace_tclobj(&get_double, NULL);
	replace_tclobj(&res, NULL);
	return code;
}

//>>>
#endif

static struct cmd {
	char*			name;
	Tcl_ObjCmdProc*	proc;
	Tcl_ObjCmdProc*	nrproc;
} cmds[] = {
	{NS "::hash",							hash_cmd,				NULL},
	{NS "::hmac",							hmac_cmd,				NULL},
	{NS "::ecc_make_key",					ecc_make_key_cmd,		NULL},
	{NS "::ecc_verify",						ecc_verify,				NULL},
	{NS "::ecc_sign",						ecc_sign_cmd,			NULL},
	{NS "::rsa_make_key",					rsa_make_key_cmd,		NULL},
	{NS "::rsa_extract_pubkey",				rsa_extract_pubkey_cmd, NULL},
	{NS "::rsa_sign_hash",					rsa_sign_hash_cmd,		NULL},
	{NS "::rsa_verify_hash",				rsa_verify_hash_cmd,	NULL},
	{NS "::rsa_encrypt_key",				rsa_encrypt_key_cmd,	NULL},
	{NS "::rsa_decrypt_key",				rsa_decrypt_key_cmd,	NULL},
	{NS "::rng_bytes",						rng_bytes,				NULL},
	{NS "::encrypt",						cipher_encrypt_cmd,		NULL},
	{NS "::decrypt",						cipher_decrypt_cmd,		NULL},
	{NS "::base64url",						base64url_cmd,			NULL},
#if TESTMODE
	{NS "::_testmode_hasGetBytesFromObj",	hasGetBytesFromObj,		NULL},
	{NS "::_testmode_isByteArray",			isByteArray,			NULL},
	{NS "::_testmode_leakObj",				leakObj,				NULL},
	{NS "::_testmode_dupObj",				dupObj,					NULL},
	{NS "::_testmode_refCount",				refCount,				NULL},
	{NS "::_testmode_doubleMantissaHist",	doubleMatissaHist,		NULL},
#endif
	{0}
};
// Script API >>>

#ifdef __cplusplus
extern "C" {
#endif
DLLEXPORT int Tomcrypt_Init(Tcl_Interp* interp) //<<<
{
	int					code = TCL_OK;
	struct interp_cx*	l = NULL;

#if USE_TCL_STUBS
	if (Tcl_InitStubs(interp, TCL_VERSION, 0) == NULL) return TCL_ERROR;
	if (Tcl_OOInitStubs(interp) == NULL) return TCL_ERROR;
#endif

	Tcl_MutexLock(&g_register_mutex);
	if (!g_register_init) {
		register_all_ciphers();
		register_all_hashes();
		register_all_prngs();

#ifdef USE_LTM
		ltc_mp = ltm_desc;
#elif defined(USE_TFM)
		ltc_mp = tfm_desc;
#elif defined(USE_GMP)
		ltc_mp = gmp_desc;
#endif

		g_register_init = 1;
	}
	Tcl_MutexUnlock(&g_register_mutex);

	l = (struct interp_cx*)ckalloc(sizeof *l);
	*l = (struct interp_cx){0};

	for (int i=0; i<L_size; i++)
		replace_tclobj(&l->lit[i], Tcl_NewStringObj(lit_str[i], -1));

	// Start L_NOBYTES off as a bytearray (mainly for the test suite)
	if (NULL == Tcl_GetBytesFromObj(interp, l->lit[L_NOBYTES], NULL)) {
		code = TCL_ERROR;
		goto finally;
	}

	Tcl_Namespace*		ns = Tcl_CreateNamespace(interp, NS, NULL, NULL);
	TEST_OK_LABEL(finally, code, Tcl_Export(interp, ns, "*", 0));

	struct cmd*	c = cmds;
	while (c->name) {
		Tcl_Command		r = NULL;
		if (c->nrproc) {
			r = Tcl_NRCreateCommand(interp, c->name, c->proc, c->nrproc, l, NULL);
		} else {
			r = Tcl_CreateObjCommand(interp, c->name, c->proc, l, NULL);
		}
		if (r == NULL) {
			code = TCL_ERROR;
			goto finally;
		}
		c++;
	}

	Tcl_MutexLock(&g_intreps_mutex);
	if (g_intreps_init == 0) {
		Tcl_InitHashTable(&g_intreps, TCL_ONE_WORD_KEYS);
		g_intreps_init = 1;
	}
	Tcl_MutexUnlock(&g_intreps_mutex);

	TEST_OK_LABEL(finally, code, prng_class_init(interp, l));

	TEST_OK_LABEL(finally, code, Tcl_PkgProvide(interp, PACKAGE_NAME, PACKAGE_VERSION));

	Tcl_SetAssocData(interp, PACKAGE_NAME, free_interp_cx, l);

finally:
	if (code != TCL_OK) {
		if (l) {
			free_interp_cx(l, interp);
			ckfree(l);
			l = NULL;
		}
	}
	return code;
}

//>>>
#if 0
DLLEXPORT int Tomcrypt_SafeInit(Tcl_Interp* interp) //<<<
{
	return Tomcrypt_Init(interp);
}

//>>>
#endif
#if UNLOAD
DLLEXPORT int Tomcrypt_Unload(Tcl_Interp* interp, int flags) //<<<
{
	int			code = TCL_OK;

	Tcl_DeleteAssocData(interp, PACKAGE_NAME);	// Have to do this here, otherwise Tcl will try to call it after we're unloaded

	if (flags == TCL_UNLOAD_DETACH_FROM_PROCESS) {
		Tcl_MutexLock(&g_intreps_mutex);
		if (g_intreps_init) {
			Tcl_HashEntry*	he;
			Tcl_HashSearch	search;
			while ((he = Tcl_FirstHashEntry(&g_intreps, &search))) {
				Tcl_Obj*	obj = (Tcl_Obj*)Tcl_GetHashValue(he);
				Tcl_GetString(obj);
				Tcl_FreeInternalRep(obj);	// Calls Tcl_DeleteHashEntry on this entry
			}
			Tcl_DeleteHashTable(&g_intreps);
			g_intreps_init = 0;
		}
		Tcl_MutexUnlock(&g_intreps_mutex);
		Tcl_MutexFinalize(&g_intreps_mutex);
		g_intreps_mutex = NULL;

		Tcl_MutexFinalize(&g_register_mutex);
		g_register_mutex = NULL;
	}

	return code;
}

//>>>
#if 0
DLLEXPORT int Tomcrypt_SafeUnload(Tcl_Interp* interp, int flags) //<<<
{
	return Tomcrypt_Unload(interp, flags);
}

//>>>
#endif
#endif //UNLOAD
#ifdef __cplusplus
}
#endif

// vim: foldmethod=marker foldmarker=<<<,>>> ts=4 shiftwidth=4
