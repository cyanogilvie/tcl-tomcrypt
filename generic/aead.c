#include "tomcryptInt.h"

// Mode descriptor structure for unified AEAD handling
typedef struct {
	const char*		name;
	int (*encrypt_fn)(int cipher, const unsigned char *key, unsigned long keylen,
					 const unsigned char *nonce, unsigned long noncelen,
					 const unsigned char *header, unsigned long headerlen,
					 const unsigned char *pt, unsigned long ptlen,
					 unsigned char *ct,
					 unsigned char *tag, unsigned long *taglen);
	int (*decrypt_fn)(int cipher, const unsigned char *key, unsigned long keylen,
					 const unsigned char *nonce, unsigned long noncelen,
					 const unsigned char *header, unsigned long headerlen,
					 const unsigned char *ct, unsigned long ctlen,
					 unsigned char *pt,
					 unsigned char *tag, unsigned long *taglen);
	int				requires_cipher;		// 0 for ChaCha20-Poly1305
	int				block_size_required;	// 0 for any, 16 for GCM/CCM
	unsigned long	default_taglen;
} aead_mode_desc;

// Wrapper functions to normalize libtomcrypt AEAD APIs <<<
// GCM wrappers <<<
static int gcm_encrypt_wrapper(int cipher, //<<<
	const unsigned char *key, unsigned long keylen,
	const unsigned char *nonce, unsigned long noncelen,
	const unsigned char *header, unsigned long headerlen,
	const unsigned char *pt, unsigned long ptlen,
	unsigned char *ct,
	unsigned char *tag, unsigned long *taglen)
{
	return gcm_memory(cipher, key, keylen, nonce, noncelen,
					 header, headerlen, (unsigned char*)pt, ptlen, ct,
					 tag, taglen, GCM_ENCRYPT);
}

//>>>
static int gcm_decrypt_wrapper(int cipher, //<<<
	const unsigned char *key, unsigned long keylen,
	const unsigned char *nonce, unsigned long noncelen,
	const unsigned char *header, unsigned long headerlen,
	const unsigned char *ct, unsigned long ctlen,
	unsigned char *pt,
	unsigned char *tag, unsigned long *taglen)
{
	return gcm_memory(cipher, key, keylen, nonce, noncelen,
					 header, headerlen, pt, ctlen, (unsigned char*)ct,
					 tag, taglen, GCM_DECRYPT);
}

//>>>
// GCM wrappers >>>
// CCM wrappers <<<
static int ccm_encrypt_wrapper(int cipher, //<<<
	const unsigned char *key, unsigned long keylen,
	const unsigned char *nonce, unsigned long noncelen,
	const unsigned char *header, unsigned long headerlen,
	const unsigned char *pt, unsigned long ptlen,
	unsigned char *ct,
	unsigned char *tag, unsigned long *taglen)
{
	return ccm_memory(cipher, key, keylen, NULL, nonce, noncelen,
					 header, headerlen, (unsigned char*)pt, ptlen, ct,
					 tag, taglen, CCM_ENCRYPT);
}

//>>>
static int ccm_decrypt_wrapper(int cipher, //<<<
	const unsigned char *key, unsigned long keylen,
	const unsigned char *nonce, unsigned long noncelen,
	const unsigned char *header, unsigned long headerlen,
	const unsigned char *ct, unsigned long ctlen,
	unsigned char *pt,
	unsigned char *tag, unsigned long *taglen)
{
	return ccm_memory(cipher, key, keylen, NULL, nonce, noncelen,
					 header, headerlen, pt, ctlen, (unsigned char*)ct,
					 tag, taglen, CCM_DECRYPT);
}

//>>>
// CCM wrappers >>>
// ChaCha20-Poly1305 wrappers <<<
static int chacha20poly1305_encrypt_wrapper(int cipher, //<<<
	const unsigned char *key, unsigned long keylen,
	const unsigned char *nonce, unsigned long noncelen,
	const unsigned char *header, unsigned long headerlen,
	const unsigned char *pt, unsigned long ptlen,
	unsigned char *ct,
	unsigned char *tag, unsigned long *taglen)
{
	(void)cipher; // Unused - ChaCha20-Poly1305 has its own cipher
	return chacha20poly1305_memory(key, keylen, nonce, noncelen,
								   header, headerlen, pt, ptlen, ct,
								   tag, taglen, CHACHA20POLY1305_ENCRYPT);
}

//>>>
static int chacha20poly1305_decrypt_wrapper(int cipher, //<<<
	const unsigned char *key, unsigned long keylen,
	const unsigned char *nonce, unsigned long noncelen,
	const unsigned char *header, unsigned long headerlen,
	const unsigned char *ct, unsigned long ctlen,
	unsigned char *pt,
	unsigned char *tag, unsigned long *taglen)
{
	(void)cipher; // Unused
	return chacha20poly1305_memory(key, keylen, nonce, noncelen,
								   header, headerlen, ct, ctlen, pt,
								   tag, taglen, CHACHA20POLY1305_DECRYPT);
}

//>>>
// ChaCha20-Poly1305 wrappers >>>
// EAX wrappers <<<
static int eax_encrypt_wrapper(int cipher, //<<<
	const unsigned char *key, unsigned long keylen,
	const unsigned char *nonce, unsigned long noncelen,
	const unsigned char *header, unsigned long headerlen,
	const unsigned char *pt, unsigned long ptlen,
	unsigned char *ct,
	unsigned char *tag, unsigned long *taglen)
{
	return eax_encrypt_authenticate_memory(cipher, key, keylen, nonce, noncelen,
										   header, headerlen, pt, ptlen, ct,
										   tag, taglen);
}

//>>>
static int eax_decrypt_wrapper(int cipher, //<<<
	const unsigned char *key, unsigned long keylen,
	const unsigned char *nonce, unsigned long noncelen,
	const unsigned char *header, unsigned long headerlen,
	const unsigned char *ct, unsigned long ctlen,
	unsigned char *pt,
	unsigned char *tag, unsigned long *taglen)
{
	int stat;
	int err = eax_decrypt_verify_memory(cipher, key, keylen, nonce, noncelen,
										header, headerlen, ct, ctlen, pt,
										tag, *taglen, &stat);
	if (err != CRYPT_OK) return err;
	return (stat == 1) ? CRYPT_OK : CRYPT_ERROR;
}

//>>>
// EAX wrappers >>>
// OCB wrappers <<<
static int ocb_encrypt_wrapper(int cipher, //<<<
	const unsigned char *key, unsigned long keylen,
	const unsigned char *nonce, unsigned long noncelen,
	const unsigned char *header, unsigned long headerlen,
	const unsigned char *pt, unsigned long ptlen,
	unsigned char *ct,
	unsigned char *tag, unsigned long *taglen)
{
	(void)noncelen; // OCB nonce doesn't have explicit length parameter
	(void)header; // OCB doesn't support AAD
	(void)headerlen;
	return ocb_encrypt_authenticate_memory(cipher, key, keylen, nonce, pt, ptlen, ct,
										   tag, taglen);
}

//>>>
static int ocb_decrypt_wrapper(int cipher, //<<<
	const unsigned char *key, unsigned long keylen,
	const unsigned char *nonce, unsigned long noncelen,
	const unsigned char *header, unsigned long headerlen,
	const unsigned char *ct, unsigned long ctlen,
	unsigned char *pt,
	unsigned char *tag, unsigned long *taglen)
{
	(void)noncelen; // OCB nonce doesn't have explicit length parameter
	(void)header; // OCB doesn't support AAD
	(void)headerlen;
	int stat;
	int err = ocb_decrypt_verify_memory(cipher, key, keylen, nonce, ct, ctlen, pt,
										tag, *taglen, &stat);
	if (err != CRYPT_OK) return err;
	return (stat == 1) ? CRYPT_OK : CRYPT_ERROR;
}

//>>>
// OCB wrappers >>>
// OCB3 wrappers <<<
static int ocb3_encrypt_wrapper(int cipher, //<<<
	const unsigned char *key, unsigned long keylen,
	const unsigned char *nonce, unsigned long noncelen,
	const unsigned char *header, unsigned long headerlen,
	const unsigned char *pt, unsigned long ptlen,
	unsigned char *ct,
	unsigned char *tag, unsigned long *taglen)
{
	return ocb3_encrypt_authenticate_memory(cipher, key, keylen, nonce, noncelen,
											header, headerlen, pt, ptlen, ct,
											tag, taglen);
}

//>>>
static int ocb3_decrypt_wrapper(int cipher, //<<<
	const unsigned char *key, unsigned long keylen,
	const unsigned char *nonce, unsigned long noncelen,
	const unsigned char *header, unsigned long headerlen,
	const unsigned char *ct, unsigned long ctlen,
	unsigned char *pt,
	unsigned char *tag, unsigned long *taglen)
{
	int stat;
	int err = ocb3_decrypt_verify_memory(cipher, key, keylen, nonce, noncelen,
										 header, headerlen, ct, ctlen, pt,
										 tag, *taglen, &stat);
	if (err != CRYPT_OK) return err;
	return (stat == 1) ? CRYPT_OK : CRYPT_ERROR;
}

//>>>
// OCB3 wrappers >>>
// Wrapper functions >>>

// Mode registry - add new AEAD modes here
static const aead_mode_desc aead_modes[] = {
	{"gcm",					gcm_encrypt_wrapper,				gcm_decrypt_wrapper,				1, 16, 16},
	{"eax",					eax_encrypt_wrapper,				eax_decrypt_wrapper,				1,  0, 16},
	{"ocb",					ocb_encrypt_wrapper,				ocb_decrypt_wrapper,				1, 16, 16},
	{"ocb3",				ocb3_encrypt_wrapper,				ocb3_decrypt_wrapper,				1, 16, 16},
	{"ccm",					ccm_encrypt_wrapper,				ccm_decrypt_wrapper,				1, 16, 16},
	{"chacha20poly1305",	chacha20poly1305_encrypt_wrapper,	chacha20poly1305_decrypt_wrapper,	0,  0, 16},
	{NULL, NULL, NULL, 0, 0, 0}
};

OBJCMD(aead_cmd) //<<<
{
	int						code = TCL_OK;
	Tcl_Obj*				res = NULL;
	Tcl_Obj*				ct_obj = NULL;
	Tcl_Obj*				tag_obj = NULL;
	const aead_mode_desc*	mode = NULL;

	static const char* subcmds[] = {"encrypt", "decrypt", NULL};
	enum {SC_ENCRYPT, SC_DECRYPT};
	int subcmd;

	enum {A_cmd, A_SUBCMD, A_MODE, A_args};
	CHECK_MIN_ARGS_LABEL(finally, code, "encrypt|decrypt mode ...");

	TEST_OK_LABEL(finally, code, Tcl_GetIndexFromObj(interp, objv[A_SUBCMD],
													  subcmds, "subcommand",
													  TCL_EXACT, &subcmd));

	// Find the mode
	const char* mode_name = Tcl_GetString(objv[A_MODE]);
	for (int i = 0; aead_modes[i].name != NULL; i++) {
		if (strcmp(aead_modes[i].name, mode_name) == 0) {
			mode = &aead_modes[i];
			break;
		}
	}

	if (!mode) {
		Tcl_SetErrorCode(interp, "TOMCRYPT", "LOOKUP", "AEAD_MODE", mode_name, NULL);
		THROW_PRINTF_LABEL(finally, code, "Unknown AEAD mode: %s", mode_name);
	}

	if (subcmd == SC_ENCRYPT) {
		enum {A_CIPHER=3, A_KEY, A_IV, A_AAD, A_PT, A_objc};
		CHECK_ARGS_LABEL(finally, code, "encrypt mode cipher key iv aad plaintext");

		// Get cipher (unless it's ChaCha20-Poly1305)
		int cipher_idx = -1;
		if (mode->requires_cipher) {
			cipher_idx = find_cipher(Tcl_GetString(objv[A_CIPHER]));
			if (cipher_idx == -1) {
				Tcl_SetErrorCode(interp, "TOMCRYPT", "LOOKUP", "CIPHER", Tcl_GetString(objv[A_CIPHER]), NULL);
				THROW_PRINTF_LABEL(finally, code, "Unknown cipher: %s",
								 Tcl_GetString(objv[A_CIPHER]));
			}

			// Check block size requirement
			if (mode->block_size_required > 0 &&
				cipher_descriptor[cipher_idx].block_length != mode->block_size_required) {
				Tcl_SetErrorCode(interp, "TOMCRYPT", "AEAD", "BLOCKSIZE", NULL);
				THROW_PRINTF_LABEL(finally, code, "%s requires %d-byte block cipher",
								 mode->name, mode->block_size_required);
			}
		}

		// Get all the byte array parameters
		int keylen, ivlen, aadlen, ptlen;
		const unsigned char* key = Tcl_GetBytesFromObj(interp, objv[A_KEY], &keylen);
		if (key == NULL) { code = TCL_ERROR; goto finally; }
		const unsigned char* iv = Tcl_GetBytesFromObj(interp, objv[A_IV], &ivlen);
		if (iv == NULL) { code = TCL_ERROR; goto finally; }
		const unsigned char* aad = Tcl_GetBytesFromObj(interp, objv[A_AAD], &aadlen);
		if (aad == NULL) { code = TCL_ERROR; goto finally; }
		const unsigned char* pt = Tcl_GetBytesFromObj(interp, objv[A_PT], &ptlen);
		if (pt == NULL) { code = TCL_ERROR; goto finally; }

		// Allocate output buffers
		replace_tclobj(&ct_obj, Tcl_NewByteArrayObj(NULL, ptlen));
		unsigned char* ct = Tcl_GetByteArrayFromObj(ct_obj, NULL);

		unsigned long taglen = mode->default_taglen;
		replace_tclobj(&tag_obj, Tcl_NewByteArrayObj(NULL, taglen));
		unsigned char* tag = Tcl_GetByteArrayFromObj(tag_obj, NULL);

		// Call the mode-specific encrypt function
		int err = mode->encrypt_fn(cipher_idx, key, keylen, iv, ivlen,
								   aad, aadlen, pt, ptlen, ct, tag, &taglen);

		if (err != CRYPT_OK) {
			Tcl_SetErrorCode(interp, "TOMCRYPT", "AEAD", "ENCRYPT", mode->name, NULL);
			THROW_PRINTF_LABEL(finally, code, "%s encryption failed: %s",
							 mode->name, error_to_string(err));
		}

		// Adjust tag length to actual
		Tcl_SetByteArrayLength(tag_obj, taglen);

		// Return {ciphertext tag}
		replace_tclobj(&res, Tcl_NewListObj(2, NULL));
		TEST_OK_LABEL(finally, code, Tcl_ListObjAppendElement(interp, res, ct_obj));
		TEST_OK_LABEL(finally, code, Tcl_ListObjAppendElement(interp, res, tag_obj));

	} else { // SC_DECRYPT
		enum {A_CIPHER=3, A_KEY, A_IV, A_AAD, A_CT, A_TAG, A_objc};
		CHECK_ARGS_LABEL(finally, code, "decrypt mode cipher key iv aad ciphertext tag");

		// Get cipher (unless it's ChaCha20-Poly1305)
		int cipher_idx = -1;
		if (mode->requires_cipher) {
			cipher_idx = find_cipher(Tcl_GetString(objv[A_CIPHER]));
			if (cipher_idx == -1) {
				Tcl_SetErrorCode(interp, "TOMCRYPT", "LOOKUP", "CIPHER", Tcl_GetString(objv[A_CIPHER]), NULL);
				THROW_PRINTF_LABEL(finally, code, "Unknown cipher: %s",
								 Tcl_GetString(objv[A_CIPHER]));
			}

			if (mode->block_size_required > 0 &&
				cipher_descriptor[cipher_idx].block_length != mode->block_size_required) {
				Tcl_SetErrorCode(interp, "TOMCRYPT", "AEAD", "BLOCKSIZE", NULL);
				THROW_PRINTF_LABEL(finally, code, "%s requires %d-byte block cipher",
								 mode->name, mode->block_size_required);
			}
		}

		// Get parameters
		int keylen, ivlen, aadlen, ctlen, taglen;
		const unsigned char* key = Tcl_GetBytesFromObj(interp, objv[A_KEY], &keylen);
		if (key == NULL) { code = TCL_ERROR; goto finally; }
		const unsigned char* iv = Tcl_GetBytesFromObj(interp, objv[A_IV], &ivlen);
		if (iv == NULL) { code = TCL_ERROR; goto finally; }
		const unsigned char* aad = Tcl_GetBytesFromObj(interp, objv[A_AAD], &aadlen);
		if (aad == NULL) { code = TCL_ERROR; goto finally; }
		const unsigned char* ct = Tcl_GetBytesFromObj(interp, objv[A_CT], &ctlen);
		if (ct == NULL) { code = TCL_ERROR; goto finally; }
		unsigned char* tag = Tcl_GetBytesFromObj(interp, objv[A_TAG], &taglen);
		if (tag == NULL) { code = TCL_ERROR; goto finally; }

		// Allocate plaintext buffer
		replace_tclobj(&res, Tcl_NewByteArrayObj(NULL, ctlen));
		unsigned char* pt = Tcl_GetByteArrayFromObj(res, NULL);

		unsigned long taglen_ul = taglen;
		int err = mode->decrypt_fn(cipher_idx, key, keylen, iv, ivlen,
								   aad, aadlen, ct, ctlen, pt, tag, &taglen_ul);

		if (err != CRYPT_OK) {
			Tcl_SetErrorCode(interp, "TOMCRYPT", "AEAD", "DECRYPT", mode->name, NULL);
			THROW_PRINTF_LABEL(finally, code, "%s decryption failed: %s",
							 mode->name, error_to_string(err));
		}
	}

	Tcl_SetObjResult(interp, res);

finally:
	replace_tclobj(&res, NULL);
	replace_tclobj(&ct_obj, NULL);
	replace_tclobj(&tag_obj, NULL);
	return code;
}

//>>>

// vim: foldmethod=marker foldmarker=<<<,>>> ts=4 shiftwidth=4
