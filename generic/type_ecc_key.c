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

	const int export_rc = ecc_export(buf, &buflen, key->type, key);
	if (export_rc != CRYPT_OK)
		Tcl_Panic("update_string_rep: ecc_export failed: %s", error_to_string(export_rc));

	Tcl_InitStringRep(obj, (char*)buf, buflen);
}

//>>>

// Internal API <<<
static int validate_private_key_structure(const unsigned char* bytes, unsigned long len) //<<<
{
	unsigned char	flags[1];
	unsigned long	key_size;
	mp_int			x, y, k;
	int				err;

	if (mp_init_multi(&x, &y, &k, NULL) != CRYPT_OK)
		return CRYPT_MEM;

	err = der_decode_sequence_multi(bytes, len,
			LTC_ASN1_BIT_STRING,		1UL, flags,
			LTC_ASN1_SHORT_INTEGER,		1UL, &key_size,
			LTC_ASN1_INTEGER,			1UL, &x,
			LTC_ASN1_INTEGER,			1UL, &y,
			LTC_ASN1_INTEGER,			1UL, &k,
			LTC_ASN1_EOL,				0UL, NULL);

	mp_clear_multi(&x, &y, &k, NULL);

	if (err != CRYPT_OK || flags[0] != 1)
		return CRYPT_INVALID_PACKET;

	return CRYPT_OK;
}

//>>>
int GetECCKeyFromObj(Tcl_Interp* interp, Tcl_Obj* obj, ecc_key_type_t expect_type, ecc_key** key) //<<<
{
	int					code = TCL_OK;
	Tcl_ObjInternalRep*	ir = Tcl_FetchInternalRep(obj, &ecc_key_objtype);
	ecc_key*			newkey = NULL;
	int					key_initialized = 0;

	if (ir == NULL) {
		newkey = ckalloc(sizeof(ecc_key));
		*newkey = (ecc_key){0};
		int				len;
		const uint8_t*	bytes = Tcl_GetBytesFromObj(interp, obj, &len);

		if (expect_type == ECC_EXPECT_PUBLIC) {
			// Handle X9.63 public key format
			if (ecc_ansi_x963_import(bytes, len, newkey) != CRYPT_OK) {
				Tcl_SetErrorCode(interp, "TOMCRYPT", "FORMAT", "X963", NULL);
				THROW_PRINTF_LABEL(finally, code, "Invalid X9.63 format key");
			}
			key_initialized = 1;
		} else {
			// Handle private key format
			if (validate_private_key_structure(bytes, len) != CRYPT_OK || ecc_import(bytes, len, newkey) != CRYPT_OK) {
				Tcl_SetErrorCode(interp, "TOMCRYPT", "FORMAT", "PRIVATE", NULL);
				THROW_PRINTF_LABEL(finally, code, "Invalid private key format");
			}
			key_initialized = 1;
		}

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
// Internal API >>>


// vim: foldmethod=marker foldmarker=<<<,>>> ts=4 shiftwidth=4
