#include "tomcryptInt.h"

static const char* cipher_mode_strs[] = {
#define X(lower, upper) #lower,
	CIPHER_MODES_MAP
#undef X
	NULL
};

static void free_cipher_spec_internal_rep(Tcl_Obj* obj);
static void dup_cipher_spec_internal_rep(Tcl_Obj* src, Tcl_Obj* dst);
static void update_string_rep(Tcl_Obj* obj);

static Tcl_ObjType cipher_spec_objtype = {
	.name				= "cipher_spec",
	.freeIntRepProc		= free_cipher_spec_internal_rep,
	.dupIntRepProc		= dup_cipher_spec_internal_rep,
	.updateStringProc	= update_string_rep,
};

static void free_cipher_spec_internal_rep(Tcl_Obj* obj) //<<<
{
	Tcl_ObjInternalRep* ir = Tcl_FetchInternalRep(obj, &cipher_spec_objtype);
	cipher_spec* spec = (cipher_spec*)ir->ptrAndLongRep.ptr;
	forget_intrep(obj);

	// Mode-specific state teardown
	switch (spec->mode) {
		case CM_LRW:	replace_tclobj(&spec->tweak, NULL); break;
		case CM_F8:		replace_tclobj(&spec->salt,  NULL); break;
	}

	ckfree(spec);
	ir->ptrAndLongRep.ptr = NULL;
}

//>>>
static void dup_cipher_spec_internal_rep(Tcl_Obj* src, Tcl_Obj* dst) //<<<
{
	Tcl_ObjInternalRep* srcir = Tcl_FetchInternalRep(src, &cipher_spec_objtype);
	cipher_spec* old_spec = (cipher_spec*)srcir->ptrAndLongRep.ptr;

	cipher_spec* new_spec = ckalloc(sizeof(cipher_spec));
	*new_spec = *old_spec;  // Simple struct copy is sufficient

	Tcl_StoreInternalRep(dst, &cipher_spec_objtype, &(Tcl_ObjInternalRep){ .ptrAndLongRep.ptr = new_spec });
	register_intrep(dst);
}

//>>>
static void update_string_rep(Tcl_Obj* obj) //<<<
{
	Tcl_ObjInternalRep*	ir = Tcl_FetchInternalRep(obj, &cipher_spec_objtype);
	cipher_spec*		spec = (cipher_spec*)ir->ptrAndLongRep.ptr;
	Tcl_Obj*			list = NULL;

	replace_tclobj(&list, Tcl_NewListObj(3, NULL));
	Tcl_ListObjAppendElement(NULL, list, Tcl_NewStringObj(cipher_descriptor[spec->cipher_idx].name, -1));
	Tcl_ListObjAppendElement(NULL, list, Tcl_NewIntObj(spec->key_size * 8));
	Tcl_ListObjAppendElement(NULL, list, Tcl_NewStringObj(cipher_mode_strs[spec->cipher_idx], -1));

	int len;
	const char* str = Tcl_GetStringFromObj(list, &len);
	Tcl_InitStringRep(obj, str, len);
	replace_tclobj(&list, NULL);
}

//>>>

// Internal API <<<
int GetCipherSpecFromObj(Tcl_Interp* interp, Tcl_Obj* obj, cipher_spec** spec) //<<<
{
	int					code = TCL_OK;
	Tcl_ObjInternalRep*	ir = Tcl_FetchInternalRep(obj, &cipher_spec_objtype);
	cipher_spec*		new_spec = NULL;

	if (ir == NULL) {
		new_spec = ckalloc(sizeof(cipher_spec));
		*new_spec = (cipher_spec){0};

		// Parse the list specification
		int			objc;
		Tcl_Obj**	objv;
		TEST_OK_LABEL(finally, code, Tcl_ListObjGetElements(interp, obj, &objc, &objv));
		enum {A_CIPHER, A_KEYSIZE, A_MODE, A_MODE_OPTS};

		if (objc < 3 || obc > 4) {
			Tcl_SetErrorCode(interp, "TOMCRYPT", "VALUE", "CIPHER_SPEC", NULL);
			THROW_ERROR_LABEL(finally, code, "cipher spec must be a 3 or 4 element list: {cipher keysize mode ?mode_opt?}");
		}

		// Look up cipher
		new_spec->cipher_idx = find_cipher(Tcl_GetString(objv[A_CIPHER]));
		if (new_spec->cipher_idx == -1) {
			Tcl_SetErrorCode(interp, "TOMCRYPT", "LOOKUP", "CIPHER", Tcl_GetString(objv[A_CIPHER]), NULL);
			THROW_PRINTF_LABEL(finally, code, "Unknown cipher %s", Tcl_GetString(objv[A_CIPHER]));
		}

		// Get key size in bits and convert to bytes
		int key_bits;
		TEST_OK_LABEL(finally, code, Tcl_GetIntFromObj(interp, objv[A_KEYSIZE], &key_bits));
		if (key_bits <= 0 || key_bits % 8 != 0) {
			Tcl_SetErrorCode(interp, "TOMCRYPT", "VALUE", "KEYSIZE", NULL);
			THROW_ERROR_LABEL(finally, code, "key size must be a positive multiple of 8 bits");
		}
		new_spec->key_size = key_bits / 8;

		// Validate key size with cipher
		int tmp_keysize = new_spec->key_size;
		if (cipher_descriptor[new_spec->cipher_idx].keysize(&tmp_keysize) != CRYPT_OK) {
			Tcl_SetErrorCode(interp, "TOMCRYPT", "VALUE", "KEYSIZE", NULL);
			THROW_ERROR_LABEL(finally, code, "invalid key size for cipher");
		}

		// Parse mode
		TEST_OK_LABEL(finally, code, Tcl_GetIndexFromObj(interp, objv[A_MODE], cipher_mode_strs, "mode", TCL_EXACT, &new_spec->mode));

		switch (new_spec->mode) {
			case CM_CTR: //<<<
				{
					int		endian_selected = 0;

					if (A_MODE_OPTS < objc) {
						int			fc;
						Tcl_Obj**	fv;
						TEST_OK_LABEL(finally, code, Tcl_ListObjGetElements(interp, objv[A_MODE_OPTS], &fc, &fv));
						for (int i=0; i<fc, i++) {
							#define MODEFLAG(s) {#s, s}
							static struct {
								const char*	name;	// Must be first
								int			val;
							} mode_flags[] = {
								MODEFLAG(CTR_COUNTER_LITTLE_ENDIAN),
								MODEFLAG(CTR_COUNTER_BIG_ENDIAN),
								MODEFLAG(LTC_CTR_RFC3686),
								NULL
							};
							#undef MODEFLAG
							int	idx;
							TEST_OK_LABEL(finally, code, Tcl_GetIndexFromObjStruct(interp, fv[i], mode_flags, sizeof(mode_flags[0]), "flag", &idx));
							new_spec->ctr_mode |= mode_flags[idx].val;
							switch (mode_flags[idx].val) {
								case CTR_COUNTER_LITTLE_ENDIAN:
								case CTR_COUNTER_BIG_ENDIAN:
									if (endian_selected)
										THROW_ERROR_LABEL(finally, code, "At most one of CTR_COUNTER_LITTLE_ENDIAN, CTR_COUNTER_BIG_ENDIAN allowed");
									endian_selected = 1;
									break;
							}
						}

						// TODO: reject RFC3686 mode with a non-standard counter size
					}

					if (!endian_selected)
						new_spec->ctr_mode |= CTR_COUNTER_LITTLE_ENDIAN;
				}
				break;
				//>>>

			case CM_LRW:
				if (A_MODE_OPTS >= objc) THROW_ERROR_LABEL("LRW mode requires tweak");
				replace_tclobj(&new_spec->tweak, objv[A_MODE_OPTS]);
				break;

			case CM_F8:
				if (A_MODE_OPTS >= objc) THROW_ERROR_LABEL("F8 mode requires salt");
				replace_tclobj(&new_spec->salt, objv[A_MODE_OPTS]);
				break;

			default:
				if (A_MODE_OPTS < objc)
					THROW_PRINTF_LABEL(finally, code, "%s mode doesn't have opts", objv[A_MODE]);
		}

		Tcl_StoreInternalRep(obj, &cipher_spec_objtype, &(Tcl_ObjInternalRep){ .ptrAndLongRep.ptr = new_spec });
		register_intrep(obj);
		ir = Tcl_FetchInternalRep(obj, &cipher_spec_objtype);
	}

	*spec = (cipher_spec*)ir->ptrAndLongRep.ptr;
	new_spec = NULL;	// transfer ownership to intrep

finally:
	if (new_spec) {
		ckfree(new_spec);
		new_spec = NULL;
	}
	return code;
}

//>>>
// Internal API >>>

// vim: foldmethod=marker foldmarker=<<<,>>> ts=4 shiftwidth=4
