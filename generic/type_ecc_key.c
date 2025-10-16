#include "tomcryptInt.h"

static void free_ecc_key_internal_rep(Tcl_Obj* obj);
static void dup_ecc_key_internal_rep(Tcl_Obj* src, Tcl_Obj* dst);
static void update_string_rep(Tcl_Obj* obj);

static Tcl_ObjType ecc_key_objtype = {
	.name				= "ecc_key",
	.freeIntRepProc		= free_ecc_key_internal_rep,
	.dupIntRepProc		= dup_ecc_key_internal_rep,
	.updateStringProc	= update_string_rep,
};

static void free_ecc_key_internal_rep(Tcl_Obj* obj) //<<<
{
	Tcl_ObjInternalRep*	ir = Tcl_FetchInternalRep(obj, &ecc_key_objtype);

	ecc_key* key = (ecc_key*)obj->internalRep.ptrAndLongRep.ptr;
	forget_intrep(obj);

	// TODO: zeromem / mp_clear first?
	ecc_free(key);
	ckfree(key);
	ir->ptrAndLongRep.ptr = NULL;
}

//>>>
static void dup_ecc_key_internal_rep(Tcl_Obj* src, Tcl_Obj* dst) //<<<
{
	unsigned long		buflen = 2048;
	uint8_t				buf[buflen];
	Tcl_ObjInternalRep*	srcir = Tcl_FetchInternalRep(src, &ecc_key_objtype);
	ecc_key*			key = (ecc_key*)srcir->ptrAndLongRep.ptr;

	const int export_rc = ecc_export(buf, &buflen, key->type, key);
	if (export_rc != CRYPT_OK) Tcl_Panic("dup_ecc_key_internal_rep: ecc_export failed: %s", error_to_string(export_rc));

	ecc_key*		dupkey = ckalloc(sizeof(ecc_key));
	*dupkey = (ecc_key){0};
	const int import_rc = ecc_import(buf, buflen, dupkey);
	if (import_rc != CRYPT_OK) Tcl_Panic("dup_ecc_key_internal_rep: ecc_import failed: %s", error_to_string(import_rc));
	Tcl_StoreInternalRep(dst, &ecc_key_objtype, &(Tcl_ObjInternalRep){ .ptrAndLongRep.ptr = dupkey });
	dupkey = NULL;	// Hand ownership to intrep
	Tcl_InvalidateStringRep(dst);
	register_intrep(dst);
}

//>>>
static void update_string_rep(Tcl_Obj* obj) //<<<
{
	Tcl_ObjInternalRep*	ir = Tcl_FetchInternalRep(obj, &ecc_key_objtype);
	ecc_key*			key = (ecc_key*)ir->ptrAndLongRep.ptr;
	unsigned long		buflen = 2048;
	uint8_t				buf[buflen];
	Tcl_Obj*			pem = NULL;

	replace_tclobj(&pem, Tcl_NewStringObj(
				key->type == PK_PRIVATE
					? "-----BEGIN EC PRIVATE KEY-----\n"
					: "-----BEGIN EC PUBLIC KEY-----\n",
				-1
	));

	const int export_rc = ecc_export_openssl(buf, &buflen, key->type == PK_PRIVATE ? PK_PRIVATE : PK_PUBLIC, key);

	if (export_rc != CRYPT_OK)
		Tcl_Panic("update_string_rep: ecc_export_openssl failed: %s", error_to_string(export_rc));

	unsigned long	b64_len = ((buflen+2)/3)*4+1;	// Base64 encoding expands by 4/3, rounding up for padding
	char*			b64_buf = ckalloc(b64_len);
	const int encode_rc = base64_encode(
			buf,		buflen,
			b64_buf,	&b64_len
	);
	if (encode_rc != CRYPT_OK) Tcl_Panic("update_string_rep: base64_encode failed: %s", error_to_string(encode_rc));

	const char*const	e = b64_buf + b64_len;
	const char*			p = b64_buf;
	for (; p+64 < e; p+=64) Tcl_AppendPrintfToObj(pem, "%.*s\n", 64, p);
	Tcl_AppendPrintfToObj(pem, "%.*s\n-----END %s KEY-----\n", (int)(e-p), p,
			key->type == PK_PRIVATE ? "EC PRIVATE" : "EC PUBLIC");

	ckfree(b64_buf); b64_buf = NULL;

	int				pem_str_len;
	const char*		pem_str = Tcl_GetStringFromObj(pem, &pem_str_len);
	Tcl_InitStringRep(obj, pem_str, pem_str_len);
	replace_tclobj(&pem, NULL);
}

//>>>

// Internal API <<<
int GetECCKeyFromObj(Tcl_Interp* interp, Tcl_Obj* obj, ecc_key_type_t expect_type, ecc_key** key) //<<<
{
	int					code = TCL_OK;
	Tcl_ObjInternalRep*	ir = Tcl_FetchInternalRep(obj, &ecc_key_objtype);
	ecc_key*			newkey = NULL;
	int					key_initialized = 0;

	if (ir == NULL) {
		newkey = ckalloc(sizeof(ecc_key));
		*newkey = (ecc_key){0};
		unsigned long			der_len = 4096;
		uint8_t*				der_buf = NULL;
		int						is_private_key = -1;
		const unsigned char*	bytes_to_import = NULL;
		unsigned long			import_len = 0;
		const char*				type = NULL;

		// Remove PEM encoding if any
		TEST_OK_LABEL(finally, code, pem_load_first_key(interp, obj, &der_buf, &der_len, &is_private_key, &type));
		if (der_buf) {
			if (strncmp(type, "EC ", 3) != 0) {
				Tcl_SetErrorCode(interp, "TOMCRYPT", "FORMAT", "PEM", NULL);
				THROW_ERROR_LABEL(finally, code, "PEM does not contain an EC key");
			}

			// Check that the expected type matches the PEM label type if any
			// ECC public keys can be derived from the private key if needed, so either satisfies ECC_EXPECT_PUBLIC
			if (expect_type == ECC_EXPECT_PRIVATE && is_private_key == 0) {
				Tcl_SetErrorCode(interp, "TOMCRYPT", "FORMAT", "PRIVATE", NULL);
				THROW_ERROR_LABEL(finally, code, "Expected a private key, got a public key");
			}

			bytes_to_import = der_buf;
			import_len = der_len;
		} else {
			// Try it as raw DER bytes
			int tmplen;
			bytes_to_import = Tcl_GetBytesFromObj(interp, obj, &tmplen);
			if (bytes_to_import == NULL) { code = TCL_ERROR; goto finally; }
			import_len = tmplen;
		}

		// Handle OpenSSL DER format
		if (ecc_import_openssl(bytes_to_import, import_len, newkey) == CRYPT_OK)
			key_initialized = 1;

		// If we're expecting a public key, try X9.63 format on secp256r1 if OpenSSL import failed
		if (!key_initialized && expect_type == ECC_EXPECT_PUBLIC) {
			const ltc_ecc_curve*	cu = NULL;
			if (ecc_find_curve("secp256r1", &cu) != CRYPT_OK) {
				Tcl_SetErrorCode(interp, "TOMCRYPT", "CURVE", "secp256r1", NULL);
				THROW_ERROR_LABEL(finally, code, "Failed to find secp256r1 curve");
			}
			if (ecc_set_curve(cu, newkey) != CRYPT_OK) {
				Tcl_SetErrorCode(interp, "TOMCRYPT", "CURVE", "secp256r1", NULL);
				THROW_ERROR_LABEL(finally, code, "Failed to set secp256r1 curve");
			}
			if (ecc_set_key(bytes_to_import, import_len, PK_PUBLIC, newkey) == CRYPT_OK)
				key_initialized = 1;
		}

		if (!key_initialized)
			THROW_ERROR_LABEL(finally, code, "Invalid ECC key format");

		if (key_initialized) {
			Tcl_StoreInternalRep(obj, &ecc_key_objtype, &(Tcl_ObjInternalRep){ .ptrAndLongRep.ptr = newkey });
			register_intrep(obj);
			ir = Tcl_FetchInternalRep(obj, &ecc_key_objtype);
		}
	}

	*key = (ecc_key*)ir->ptrAndLongRep.ptr;
	newkey = NULL;

finally:
	if (newkey) {
		if (key_initialized) ecc_free(newkey);
		ckfree(newkey);
		newkey = NULL;
	}
	return code;
}

//>>>
Tcl_Obj* NewECCKeyObj(ecc_key** key) //<<<
{
	Tcl_Obj*	obj = Tcl_NewObj();

	Tcl_StoreInternalRep(obj, &ecc_key_objtype, &(Tcl_ObjInternalRep){
		.ptrAndLongRep.ptr = *key
	});
	register_intrep(obj);
	*key = NULL;	// Transfer ownership to obj
	Tcl_InvalidateStringRep(obj);

	return obj;
}

//>>>
// Internal API >>>

// vim: foldmethod=marker foldmarker=<<<,>>> ts=4 shiftwidth=4
