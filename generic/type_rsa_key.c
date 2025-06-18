#include "tomcryptInt.h"

static void free_rsa_key_internal_rep(Tcl_Obj* obj);
static void dup_rsa_key_internal_rep(Tcl_Obj* src, Tcl_Obj* dst);
static void update_string_rep(Tcl_Obj* obj);

static Tcl_ObjType rsa_key_objtype = {
	.name				= "rsa_key",
	.freeIntRepProc		= free_rsa_key_internal_rep,
	.dupIntRepProc		= dup_rsa_key_internal_rep,
	.updateStringProc	= update_string_rep,
};

static void free_rsa_key_internal_rep(Tcl_Obj* obj) //<<<
{
	Tcl_ObjInternalRep*	ir = Tcl_FetchInternalRep(obj, &rsa_key_objtype);

	rsa_key* key = (rsa_key*)obj->internalRep.ptrAndLongRep.ptr;
	forget_intrep(obj);

	rsa_free(key);
	ckfree(key);
	ir->ptrAndLongRep.ptr = NULL;
}

//>>>
static void dup_rsa_key_internal_rep(Tcl_Obj* src, Tcl_Obj* dst) //<<<
{
	unsigned long		buflen = 4096;
	uint8_t				buf[buflen];
	Tcl_ObjInternalRep*	srcir = Tcl_FetchInternalRep(src, &rsa_key_objtype);
	rsa_key*			key = (rsa_key*)srcir->ptrAndLongRep.ptr;

	const int export_rc = rsa_export(buf, &buflen, key->type, key);
	if (export_rc != CRYPT_OK) Tcl_Panic("dup_rsa_key_internal_rep: rsa_export failed: %s", error_to_string(export_rc));

	rsa_key*		dupkey = ckalloc(sizeof(rsa_key));
	*dupkey = (rsa_key){0};
	const int import_rc = rsa_import(buf, buflen, dupkey);
	if (import_rc != CRYPT_OK) Tcl_Panic("dup_rsa_key_internal_rep: rsa_import failed: %s", error_to_string(import_rc));
	Tcl_StoreInternalRep(dst, &rsa_key_objtype, &(Tcl_ObjInternalRep){ .ptrAndLongRep.ptr = dupkey });
	dupkey = NULL;	// Hand ownership to intrep
	Tcl_InvalidateStringRep(dst);
	register_intrep(dst);
}

//>>>
static void update_string_rep(Tcl_Obj* obj) //<<<
{
	Tcl_ObjInternalRep*	ir = Tcl_FetchInternalRep(obj, &rsa_key_objtype);
	rsa_key*			key = (rsa_key*)ir->ptrAndLongRep.ptr;
	unsigned long		der_buflen = 4096;
	uint8_t				der_buf[der_buflen];
	Tcl_Obj*			pem = NULL;

	replace_tclobj(&pem, Tcl_NewStringObj(
				key->type == PK_PRIVATE
					? "-----BEGIN RSA PRIVATE KEY-----\n"
					: "-----BEGIN PUBLIC KEY-----\n",
				-1
	));

	// Export key to DER format first
	const int export_rc = rsa_export(der_buf, &der_buflen, key->type | (key->type == PK_PUBLIC ? PK_STD : 0), key);
	if (export_rc != CRYPT_OK) Tcl_Panic("update_string_rep: rsa_export failed: %s", error_to_string(export_rc));

	unsigned long	b64_len = ((der_buflen+2)/3)*4+1;	// Base64 encoding expands by 4/3, rounding up for padding
	char*			b64_buf = ckalloc(b64_len);
	const int encode_rc = base64_encode(
			der_buf,	der_buflen,
			b64_buf,	&b64_len
	);
	if (encode_rc != CRYPT_OK) Tcl_Panic("update_string_rep: base64_encode failed: %s", error_to_string(encode_rc));

	const char*const	e = b64_buf + b64_len;
	const char*			p = b64_buf;
	for (; p+64 < e; p+=64) Tcl_AppendPrintfToObj(pem, "%.*s\n", 64, p);
	Tcl_AppendPrintfToObj(pem, "%.*s\n-----END %s KEY-----\n", (int)(e-p), p,
			key->type == PK_PRIVATE ? "RSA PRIVATE" : "PUBLIC");

	ckfree(b64_buf); b64_buf = NULL;

	int				pem_str_len;
	const char*		pem_str = Tcl_GetStringFromObj(pem, &pem_str_len);
	Tcl_InitStringRep(obj, pem_str, pem_str_len);
	replace_tclobj(&pem, NULL);
}

//>>>

// Internal API <<<
int GetRSAKeyFromObj(Tcl_Interp* interp, Tcl_Obj* obj, rsa_key_type_t expect_type, rsa_key** key) //<<<
{
	int					code = TCL_OK;
	Tcl_ObjInternalRep*	ir = Tcl_FetchInternalRep(obj, &rsa_key_objtype);
	rsa_key*			newkey = NULL;
	int					key_initialized = 0;
	unsigned long		der_len = 4096;
	uint8_t*			der_buf = NULL;

	if (ir == NULL) {
		newkey = ckalloc(sizeof(rsa_key));
		*newkey = (rsa_key){0};
		int						is_private_key = -1;
		const unsigned char*	bytes_to_import = NULL;
		unsigned long			import_len = 0;

		TEST_OK_LABEL(finally, code, pem_load_first_key(interp, obj, &der_buf, &der_len, &is_private_key));
		if (der_buf) {
			bytes_to_import = der_buf;
			import_len = der_len;
		} else {
			// Try it as raw DER bytes
			bytes_to_import = Tcl_GetBytesFromObj(interp, obj, &import_len);
			if (bytes_to_import == NULL) { code = TCL_ERROR; goto finally; }
		}

		if (import_len == 0) {
			// rsa_import aborts on this case
			Tcl_SetErrorCode(interp, "TOMCRYPT", "FORMAT", "RSA", NULL);
			THROW_PRINTF_LABEL(finally, code, "Invalid RSA key format");
		}

		if (rsa_import(bytes_to_import, import_len, newkey) != CRYPT_OK) {
			Tcl_SetErrorCode(interp, "TOMCRYPT", "FORMAT", "RSA", NULL);
			THROW_PRINTF_LABEL(finally, code, "Invalid RSA key format");
		}
		key_initialized = 1;

		if (is_private_key != -1) {
			// Check if the key type matches the PEM label type.  -1: wasn't PEM, so nothing to check
			if (newkey->type == PK_PUBLIC && is_private_key)	THROW_ERROR_LABEL(finally, code, "PEM claimed to be private key but imported as public key");
			if (newkey->type == PK_PRIVATE && !is_private_key)	THROW_ERROR_LABEL(finally, code, "PEM claimed to be public key but imported as private key");
		}

		Tcl_StoreInternalRep(obj, &rsa_key_objtype, &(Tcl_ObjInternalRep){ .ptrAndLongRep.ptr = newkey });
		register_intrep(obj);
		ir = Tcl_FetchInternalRep(obj, &rsa_key_objtype);
		newkey = NULL;	// Hand ownership to intrep
	}

	// Validate key type matches expectation
	if (expect_type == RSA_EXPECT_PUBLIC && ((rsa_key*)ir->ptrAndLongRep.ptr)->type != PK_PUBLIC) {
		Tcl_SetErrorCode(interp, "TOMCRYPT", "KEY", "TYPE", NULL);
		THROW_ERROR_LABEL(finally, code, "Expected public key but got private key");
	}
	if (expect_type == RSA_EXPECT_PRIVATE && ((rsa_key*)ir->ptrAndLongRep.ptr)->type != PK_PRIVATE) {
		Tcl_SetErrorCode(interp, "TOMCRYPT", "KEY", "TYPE", NULL);
		THROW_ERROR_LABEL(finally, code, "Expected private key but got public key");
	}

	*key = (rsa_key*)ir->ptrAndLongRep.ptr;

finally:
	if (der_buf) {
		ckfree(der_buf);
		der_buf = NULL;
	}
	if (newkey) {
		if (key_initialized) rsa_free(newkey);
		ckfree(newkey);
		newkey = NULL;
	}
	return code;
}

//>>>
Tcl_Obj* NewRSAKeyObj(rsa_key** key) //<<<
{
	Tcl_Obj* obj = Tcl_NewObj();

	// Store the key in the object's internal representation
	Tcl_StoreInternalRep(obj, &rsa_key_objtype, &(Tcl_ObjInternalRep){ .ptrAndLongRep.ptr = *key });
	register_intrep(obj);

	// Intrep now owns the key
	*key = NULL;

	// No string representation initially - will be generated on demand
	Tcl_InvalidateStringRep(obj);

	return obj;
}

//>>>
// Internal API >>>

// vim: foldmethod=marker foldmarker=<<<,>>> ts=4 shiftwidth=4
