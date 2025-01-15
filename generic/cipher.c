#include "tomcryptInt.h"

struct cipher_md {
	Tcl_Obj*			spec_obj;
	enum cipher_mode	mode;			// Copied here so that teardown_cipher_md doesn't need to extract it from spec_obj (requires interp)
	int					initialized;	// Track initialization

	union {
#define X(lower, upper) symmetric_##upper state_##lower;
		CIPHER_MODES_MAP
#undef X
	};

	unsigned char	residual[MAXBLOCKSIZE];	// For partial blocks in CBC mode
	int				residual_length;		// Number of bytes in residual
};

static int setup_cipher_md(Tcl_Interp* interp, struct cipher_md* md, Tcl_Obj* spec_obj, Tcl_Obj* key_obj, Tcl_Obj* iv_obj) //<<<
{
	int				code = TCL_OK;
	int				err = CRYPT_OK;
	int				keylen, ivlen;
	cipher_spec*	spec = NULL;

	// Get cipher specification
	TEST_OK_LABEL(finally, code, GetCipherSpecFromObj(interp, spec_obj, &spec));

	*md = (struct cipher_md){
		.mode = spec->mode,
	};
	replace_tclobj(&md->spec_obj, spec_obj);

	const unsigned char*	key = Tcl_GetBytesFromObj(interp, key_obj, &keylen);
	if (key == NULL) { code = TCL_ERROR; goto finally; }
	const unsigned char*	iv = Tcl_GetBytesFromObj(interp, iv_obj, &ivlen);
	if (iv == NULL) { code = TCL_ERROR; goto finally; }

	if (keylen < cipher_descriptor[spec->cipher_idx].min_key_length)
		THROW_PRINTF_LABEL(finally, code, "Key must be at least %d bytes long for %s",
					cipher_descriptor[spec->cipher_idx].min_key_length,
					cipher_descriptor[spec->cipher_idx].name);

	if (keylen > cipher_descriptor[spec->cipher_idx].max_key_length)
		THROW_PRINTF_LABEL(finally, code, "Key must be at must %d bytes long for %s",
					cipher_descriptor[spec->cipher_idx].max_key_length,
					cipher_descriptor[spec->cipher_idx].name);

	const int blocksize = cipher_descriptor[spec->cipher_idx].block_length;
	if (ivlen != blocksize) {
		Tcl_SetErrorCode(interp, "TOMCRYPT", "VALUE", "IV_SIZE", NULL);
		THROW_ERROR_LABEL(finally, code, "IV must be same length as cipher block size");
	}

	switch (md->mode) {
		case CM_CTR:
			// CTR mode takes an extra arg: ctr_mode
			err = ctr_start(spec->cipher_idx, iv, key, keylen, 0/*num_rounds, default*/, spec->ctr_mode, &md->state_ctr);
			break;

#if 0
		case CM_ECR:
			// ECR mode doesn't take iv
			err = ctr_start(spec->cipher_idx, key, keylen, 0/*num_rounds, default*/, &md->state_ecb);
			break;
#endif

		case CM_LRW:
			// LRW mode takes tweak
			err = lrw_start(spec->cipher_idx, iv, key, keylen, Tcl_GetByteArrayFromObj(spec->tweak, NULL), 0/*num_rounds, default*/, &md->state_lrw);
			break;

		case CM_F8:
			{
				// F8 mode takes salt
				int						saltlen;
				const unsigned char*	salt = Tcl_GetByteArrayFromObj(spec->salt, &saltlen);
				err = f8_start(spec->cipher_idx, iv, key, keylen, salt, saltlen, 0/*num_rounds, default*/, &md->state_f8);
			}
			break;

		// All the others follow this pattern
#define X(lower, upper) \
		case CM_##upper: err = lower##_start(spec->cipher_idx, iv, key, keylen, 0/*num_rounds, default*/, &md->state_##lower); break;

		CIPHER_MODES_MAP_REGULAR
#undef X

		default:
			THROW_ERROR_LABEL(finally, code, "Unhandled cipher mode", cipher_descriptor[spec->cipher_idx].name);
	}

	if (err != CRYPT_OK) {
		Tcl_SetErrorCode(interp, "TOMCRYPT", "CIPHER", "ENCRYPT", cipher_mode_strs[md->mode], NULL);
		THROW_PRINTF_LABEL(finally, code, "encryption failed: %s", error_to_string(err));
	}

	md->initialized = 1;

finally:
	return code;
}

//>>>
static void teardown_cipher_md(struct cipher_md* md) //<<<
{
	if (md) {
		replace_tclobj(&md->spec_obj, NULL);
		memset(md->residual, 0, MAXBLOCKSIZE);	// zero any plaintext residual remaining before handing back memory

		if (md->initialized) {
			switch (md->mode) {
#define X(lower, upper) \
				case CM_##upper: lower##_done(&md->state_##lower); break;
				CIPHER_MODES_MAP
#undef X
				default: break;
			}

			md->initialized = 0;
		}
	}
}

//>>>
static int encrypt_chunk(Tcl_Interp* interp, struct cipher_md* md, Tcl_Obj* plaintext, Tcl_Obj** ciphertext) //<<<
{
	int						code = TCL_OK;
	Tcl_Obj*				res = NULL;
	const unsigned char*	in = NULL;
	int						inlen;
	cipher_spec*			spec = NULL;

	// Get input data
	int datalen;
	const unsigned char* data = Tcl_GetBytesFromObj(interp, plaintext, &datalen);
	if (data == NULL) { code = TCL_ERROR; goto finally; }

	TEST_OK_LABEL(finally, code, GetCipherSpecFromObj(interp, md->spec_obj, &spec));

	switch (md->mode) {
		case CM_CBC: // Handle partial blocks
			{
				const int blocksize = cipher_descriptor[spec->cipher_idx].block_length;
				if (md->residual_length) {
					inlen = md->residual_length + datalen;
					in = ckalloc(inlen);
					memcpy((char*)in, md->residual, md->residual_length);
					memcpy((char*)in+md->residual_length, data, datalen);
					md->residual_length = 0;
				} else {
					in = data;
					inlen = datalen;
				}
				if (inlen % blocksize) {
					md->residual_length = inlen % blocksize;
					memcpy(md->residual, in + inlen - md->residual_length, md->residual_length);
					inlen -= md->residual_length;
				}
			}
			break;

		default:
			in = data;
			inlen = datalen;
	}

	replace_tclobj(&res, Tcl_NewByteArrayObj(NULL, inlen));
	unsigned char* out = Tcl_GetByteArrayFromObj(res, NULL);

	int err;
	switch (md->mode) {
#define X(lower, upper) case CM_##upper: err = lower##_encrypt(in, out, inlen, &md->state_##lower); break;
		CIPHER_MODES_MAP
#undef X
		default: THROW_PRINTF_LABEL(finally, code, "Unhandled cipher mode %d", md->mode);
	}

	if (err != CRYPT_OK) {
		Tcl_SetErrorCode(interp, "TOMCRYPT", "CIPHER", "ENCRYPT", cipher_mode_strs[md->mode], NULL);
		THROW_PRINTF_LABEL(finally, code, "encryption failed: %s", error_to_string(err));
	}

	replace_tclobj(ciphertext, res);

finally:
	replace_tclobj(&res, NULL);
	if (in && in != data) {
		ckfree(in);
	}
	in = NULL;
	return code;
}

//>>>
static int encrypt_final(Tcl_Interp* interp, struct cipher_md* md, Tcl_Obj** ciphertext) //<<<
{
	int				code = TCL_OK;
	Tcl_Obj*		tail = NULL;
	Tcl_Obj*		tmp = NULL;
	cipher_spec*	spec = NULL;

	TEST_OK_LABEL(finally, code, GetCipherSpecFromObj(interp, md->spec_obj, &spec));

	switch (md->mode) {
		case CM_CBC:	// Pad and encrypt the residual
			{
				const int		blocksize = cipher_descriptor[spec->cipher_idx].block_length;
				unsigned long	pad_len = blocksize - md->residual_length;

				// PKCS#7 padding
				if (pad_len == 0) pad_len = blocksize;
				memset(md->residual + md->residual_length, pad_len, pad_len);
				unsigned char	out[MAXBLOCKSIZE];
				int err = cbc_encrypt(md->residual, out, blocksize, &md->state_cbc);
				if (err != CRYPT_OK) {
					Tcl_SetErrorCode(interp, "TOMCRYPT", "CIPHER", "ENCRYPT", cipher_mode_strs[md->mode], NULL);
					THROW_PRINTF_LABEL(finally, code, "encryption failed: %s", error_to_string(err));
				}
				replace_tclobj(&tail, Tcl_NewByteArrayObj(out, blocksize));
			}
			break;

		default:
			// Nothing to do here (keep compiler happy)
			break;
	}

	if (tail) {
		if (Tcl_IsShared(*ciphertext)) {
			replace_tclobj(&tmp, *ciphertext);
			replace_tclobj(ciphertext, Tcl_DuplicateObj(*ciphertext));
		}
		Tcl_AppendObjToObj(*ciphertext, tail);
	}

finally:
	replace_tclobj(&tail, NULL);
	replace_tclobj(&tmp, NULL);
	return code;
}

//>>>
OBJCMD(cipher_encrypt_cmd) //<<<
{
	int					code = TCL_OK;
	struct cipher_md	md;
	Tcl_Obj*			res = NULL;

	enum {A_cmd, A_SPEC, A_KEY, A_IV, A_DATA, A_objc};
	CHECK_ARGS_LABEL(finally, code, "spec key iv data");

	// Create cipher state
	TEST_OK_LABEL(finally, code, setup_cipher_md(interp, &md, objv[A_SPEC], objv[A_KEY], objv[A_IV]));

	// Encrypt
	TEST_OK_LABEL(finally, code, encrypt_chunk(interp, &md, objv[A_DATA], &res));
	TEST_OK_LABEL(finally, code, encrypt_final(interp, &md, &res));

	Tcl_SetObjResult(interp, res);

finally:
	teardown_cipher_md(&md);
	replace_tclobj(&res, NULL);
	return code;
}

//>>>

// vim: foldmethod=marker foldmarker=<<<,>>> ts=4 shiftwidth=4
