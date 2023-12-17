#include "tomcryptInt.h"

// Must be kept in sync with the enum in tomcryptInt.tcl
static const char* lit_str[L_size] = {
	"",				// L_EMPTY
	"",				// L_NOBYTES
	"1",			// L_TRUE
	"0",			// L_FALSE
	NS "::prng",	// L_PRNG_CLASS
	"::oo::class create " NS "::prng {}",	// L_PRNG_CLASS_DEF
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
	size_t			bytes_len;
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
OBJCMD(ecc_verify) //<<<
{
	struct interp_cx*	l = cdata;
	int					code = TCL_OK;

	enum {A_cmd, A_SIG, A_HASH, A_KEY, A_objc};
	CHECK_ARGS_LABEL(finally, code, "sig message key");

	ecc_key*	key = NULL;
	TEST_OK_LABEL(finally, code, GetECCKeyFromObj(interp, objv[A_KEY], &key));

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
	{NS "::hash",							hash_cmd,			NULL},
	{NS "::ecc_verify",						ecc_verify,			NULL},
	{NS "::rng_bytes",						rng_bytes,			NULL},
#if TESTMODE
	{NS "::_testmode_hasGetBytesFromObj",	hasGetBytesFromObj,	NULL},
	{NS "::_testmode_isByteArray",			isByteArray,		NULL},
	{NS "::_testmode_leakObj",				leakObj,			NULL},
	{NS "::_testmode_dupObj",				dupObj,				NULL},
	{NS "::_testmode_refCount",				refCount,			NULL},
	{NS "::_testmode_doubleMantissaHist",	doubleMatissaHist,	NULL},
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
#endif
//#if USE_TCLOO_STUBS
	if (Tcl_OOInitStubs(interp) == NULL) return TCL_ERROR;
//#endif

	Tcl_MutexLock(&g_register_mutex);
	if (!g_register_init) {
		register_all_ciphers();
		register_all_hashes();
		register_all_prngs();
		g_register_init = 1;
	}
	Tcl_MutexUnlock(&g_register_mutex);

#ifdef USE_LTM
	ltc_mp = ltm_desc;
#elif defined(USE_TFM)
	ltc_mp = tfm_desc;
#elif defined(USE_GMP)
	ltc_mp = gmp_desc;
#endif

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

	code = Tcl_PkgProvide(interp, PACKAGE_NAME, PACKAGE_VERSION);
	if (code != TCL_OK) goto finally;

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
