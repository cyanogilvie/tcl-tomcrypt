#include "tomcryptInt.h"

// ptrAndLongRep.value flags
#define CURVE_IS_CUSTOM		1	// If set, curve strings need to be freed

static void free_ecc_curve_internal_rep(Tcl_Obj* obj);
static void dup_ecc_curve_internal_rep(Tcl_Obj* src, Tcl_Obj* dst);
static void update_string_rep(Tcl_Obj* obj);

static Tcl_ObjType ecc_curve_objtype = {
	.name				= "ecc_curve",
	.freeIntRepProc		= free_ecc_curve_internal_rep,
	.dupIntRepProc		= dup_ecc_curve_internal_rep,
	.updateStringProc	= update_string_rep,
};

static void free_ecc_curve_internal_rep(Tcl_Obj* obj) //<<<
{
	Tcl_ObjInternalRep*	ir = Tcl_FetchInternalRep(obj, &ecc_curve_objtype);
	ltc_ecc_curve*		curve = (ltc_ecc_curve*)ir->ptrAndLongRep.ptr;
	const int			is_custom = ir->ptrAndLongRep.value & CURVE_IS_CUSTOM;

	forget_intrep(obj);

	if (curve) {
		// Only free strings if this is a custom curve
		if (is_custom) {
			if (curve->prime) {ckfree((char*)curve->prime); curve->prime = NULL;}
			if (curve->A)     {ckfree((char*)curve->A);     curve->A = NULL;}
			if (curve->B)     {ckfree((char*)curve->B);     curve->B = NULL;}
			if (curve->order) {ckfree((char*)curve->order); curve->order = NULL;}
			if (curve->Gx)    {ckfree((char*)curve->Gx);    curve->Gx = NULL;}
			if (curve->Gy)    {ckfree((char*)curve->Gy);    curve->Gy = NULL;}
			if (curve->OID)   {ckfree((char*)curve->OID);   curve->OID = NULL;}
			ckfree(curve);
		}
	}

	ir->ptrAndLongRep.ptr = NULL;
	ir->ptrAndLongRep.value = 0;
}

//>>>
static void dup_ecc_curve_internal_rep(Tcl_Obj* src, Tcl_Obj* dst) //<<<
{
	Tcl_ObjInternalRep*		srcir = Tcl_FetchInternalRep(src, &ecc_curve_objtype);
	const ltc_ecc_curve*	src_curve = (const ltc_ecc_curve*)srcir->ptrAndLongRep.ptr;
	const int				is_custom = srcir->ptrAndLongRep.value & CURVE_IS_CUSTOM;

	if (is_custom) {
		// For custom curves, allocate new memory and duplicate strings
		ltc_ecc_curve*	new_curve = ckalloc(sizeof(ltc_ecc_curve));
		*new_curve = (ltc_ecc_curve){
			.prime    = src_curve->prime  ? ckalloc(strlen(src_curve->prime) + 1)  : NULL,
			.A        = src_curve->A      ? ckalloc(strlen(src_curve->A) + 1)      : NULL,
			.B        = src_curve->B      ? ckalloc(strlen(src_curve->B) + 1)      : NULL,
			.order    = src_curve->order  ? ckalloc(strlen(src_curve->order) + 1)  : NULL,
			.Gx       = src_curve->Gx     ? ckalloc(strlen(src_curve->Gx) + 1)     : NULL,
			.Gy       = src_curve->Gy     ? ckalloc(strlen(src_curve->Gy) + 1)     : NULL,
			.cofactor = src_curve->cofactor,
			.OID      = src_curve->OID    ? ckalloc(strlen(src_curve->OID) + 1)    : NULL,
		};

		if (src_curve->prime)  strcpy((char*)new_curve->prime,  src_curve->prime);
		if (src_curve->A)      strcpy((char*)new_curve->A,      src_curve->A);
		if (src_curve->B)      strcpy((char*)new_curve->B,      src_curve->B);
		if (src_curve->order)  strcpy((char*)new_curve->order,  src_curve->order);
		if (src_curve->Gx)     strcpy((char*)new_curve->Gx,     src_curve->Gx);
		if (src_curve->Gy)     strcpy((char*)new_curve->Gy,     src_curve->Gy);
		if (src_curve->OID)    strcpy((char*)new_curve->OID,    src_curve->OID);

		Tcl_StoreInternalRep(dst, &ecc_curve_objtype, &(Tcl_ObjInternalRep){
			.ptrAndLongRep.ptr   = new_curve,
			.ptrAndLongRep.value = CURVE_IS_CUSTOM
		});
	} else {
		// For built-in curves, just copy the pointer (points to static data)
		Tcl_StoreInternalRep(dst, &ecc_curve_objtype, &(Tcl_ObjInternalRep){
			.ptrAndLongRep.ptr   = (void*)src_curve,
			.ptrAndLongRep.value = 0
		});
	}

	Tcl_InvalidateStringRep(dst);
	register_intrep(dst);
}

//>>>
static void update_string_rep(Tcl_Obj* obj) //<<<
{
	Tcl_ObjInternalRep*		ir = Tcl_FetchInternalRep(obj, &ecc_curve_objtype);
	const ltc_ecc_curve*	curve = (const ltc_ecc_curve*)ir->ptrAndLongRep.ptr;

	// Use the curve's OID as the string representation if available, otherwise use the prime
	const char*		str = (curve->OID && curve->OID[0]) ? curve->OID : curve->prime;
	Tcl_InitStringRep(obj, str, strlen(str));
}

//>>>

// Internal API <<<
static int parse_custom_curve_dict(Tcl_Interp* interp, Tcl_Obj* dict, ltc_ecc_curve** curve_out) //<<<
{
	int				code = TCL_OK;
	ltc_ecc_curve*	curve = NULL;
	Tcl_Obj*		value = NULL;
	int				dict_size = 0;
	Tcl_Obj*		key = NULL;

	// Check if it's a valid dict
	if (Tcl_DictObjSize(interp, dict, &dict_size) != TCL_OK) {
		// Not a valid dict - set the "curve not found" error here
		const char* name_or_oid = Tcl_GetString(dict);
		Tcl_ResetResult(interp);
		Tcl_SetErrorCode(interp, "TOMCRYPT", "ECC", "CURVE", "NOT_FOUND", NULL);
		Tcl_SetObjResult(interp, Tcl_ObjPrintf("Unknown ECC curve: \"%s\"", name_or_oid));
		code = TCL_ERROR;
		goto finally;
	}

	// Allocate the curve structure
	curve = ckalloc(sizeof(ltc_ecc_curve));
	*curve = (ltc_ecc_curve){0};

	// Extract required fields: prime, A, B, order, Gx, Gy
	static const char* required_keys[] = {"prime", "A", "B", "order", "Gx", "Gy", NULL};
	const char** field_ptrs[] = {&curve->prime, &curve->A, &curve->B, &curve->order, &curve->Gx, &curve->Gy};

	for (int i=0; required_keys[i]; i++) {
		replace_tclobj(&key, Tcl_NewStringObj(required_keys[i], -1));
		TEST_OK_LABEL(finally, code, Tcl_DictObjGet(interp, dict, key, &value));
		if (value == NULL) {
			Tcl_SetErrorCode(interp, "TOMCRYPT", "ECC", "CURVE", "MISSING_FIELD", NULL);
			THROW_PRINTF_LABEL(finally, code, "Missing required field '%s' in custom curve dict", required_keys[i]);
		}

		const char* str_value = Tcl_GetString(value);
		char* allocated_str = ckalloc(strlen(str_value) + 1);
		strcpy(allocated_str, str_value);
		*field_ptrs[i] = allocated_str;
	}

	// Extract optional cofactor (default to 1)
	replace_tclobj(&key, Tcl_NewStringObj("cofactor", -1));
	TEST_OK_LABEL(finally, code, Tcl_DictObjGet(interp, dict, key, &value));
	if (value != NULL) {
		Tcl_WideInt cofactor_val;
		TEST_OK_LABEL(finally, code, Tcl_GetWideIntFromObj(interp, value, &cofactor_val));
		curve->cofactor = (unsigned long)cofactor_val;
	} else {
		curve->cofactor = 1;
	}

	// Extract optional OID
	replace_tclobj(&key, Tcl_NewStringObj("OID", -1));
	TEST_OK_LABEL(finally, code, Tcl_DictObjGet(interp, dict, key, &value));
	if (value != NULL) {
		const char* oid_str = Tcl_GetString(value);
		char* allocated_oid = ckalloc(strlen(oid_str) + 1);
		strcpy(allocated_oid, oid_str);
		curve->OID = allocated_oid;
	} else {
		curve->OID = NULL;
	}

	*curve_out = curve;
	curve = NULL;  // Transfer ownership

finally:
	if (curve) {
		// Cleanup on error
		if (curve->prime) {ckfree((char*)curve->prime); curve->prime = NULL;}
		if (curve->A)     {ckfree((char*)curve->A);     curve->A = NULL;}
		if (curve->B)     {ckfree((char*)curve->B);     curve->B = NULL;}
		if (curve->order) {ckfree((char*)curve->order); curve->order = NULL;}
		if (curve->Gx)    {ckfree((char*)curve->Gx);    curve->Gx = NULL;}
		if (curve->Gy)    {ckfree((char*)curve->Gy);    curve->Gy = NULL;}
		if (curve->OID)   {ckfree((char*)curve->OID);   curve->OID = NULL;}
		ckfree(curve);
	}
	replace_tclobj(&key, NULL);
	return code;
}

//>>>
int GetECCCurveFromObj(Tcl_Interp* interp, Tcl_Obj* obj, const ltc_ecc_curve** curve) //<<<
{
	int						code = TCL_OK;
	Tcl_ObjInternalRep*		ir = Tcl_FetchInternalRep(obj, &ecc_curve_objtype);
	const ltc_ecc_curve*	newcurve = NULL;
	ltc_ecc_curve*			custom_curve = NULL;

	if (ir == NULL) {
		// Try to look up the curve by name or OID first
		const char* name_or_oid = Tcl_GetString(obj);
		const int find_rc = ecc_find_curve(name_or_oid, &newcurve);

		if (find_rc == CRYPT_OK && newcurve != NULL) {
			// Found a built-in curve
			Tcl_StoreInternalRep(obj, &ecc_curve_objtype, &(Tcl_ObjInternalRep){
				.ptrAndLongRep.ptr		= (void*)newcurve,
				.ptrAndLongRep.value	= 0
			});
		} else {
			// Try to parse as a custom curve dictionary
			TEST_OK_LABEL(finally, code, parse_custom_curve_dict(interp, obj, &custom_curve));

			// Store the custom curve
			Tcl_StoreInternalRep(obj, &ecc_curve_objtype, &(Tcl_ObjInternalRep){
				.ptrAndLongRep.ptr		= custom_curve,
				.ptrAndLongRep.value	= CURVE_IS_CUSTOM
			});
			custom_curve = NULL;  // Transfer ownership
		}

		register_intrep(obj);
		ir = Tcl_FetchInternalRep(obj, &ecc_curve_objtype);
	}

	*curve = (const ltc_ecc_curve*)ir->ptrAndLongRep.ptr;

finally:
	if (custom_curve) {
		// Cleanup on error
		if (custom_curve->prime) {ckfree((char*)custom_curve->prime);   custom_curve->prime = NULL;}
		if (custom_curve->A)     {ckfree((char*)custom_curve->A);       custom_curve->A = NULL;}
		if (custom_curve->B)     {ckfree((char*)custom_curve->B);       custom_curve->B = NULL;}
		if (custom_curve->order) {ckfree((char*)custom_curve->order);   custom_curve->order = NULL;}
		if (custom_curve->Gx)    {ckfree((char*)custom_curve->Gx);      custom_curve->Gx = NULL;}
		if (custom_curve->Gy)    {ckfree((char*)custom_curve->Gy);      custom_curve->Gy = NULL;}
		if (custom_curve->OID)   {ckfree((char*)custom_curve->OID);     custom_curve->OID = NULL;}
		ckfree(custom_curve);
	}
	return code;
}

//>>>
// Internal API >>>


// vim: foldmethod=marker foldmarker=<<<,>>> ts=4 shiftwidth=4
