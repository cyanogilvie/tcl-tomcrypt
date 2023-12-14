#include "tomcryptInt.h"

static const char* lit_str[L_size] = {
	"",
	"1",
	"0"
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
	const uint8_t*	msg = Tcl_GetBytesFromObj(interp, objv[A_HASH], &msglen);
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
static struct cmd {
	char*			name;
	Tcl_ObjCmdProc*	proc;
	Tcl_ObjCmdProc*	nrproc;
} cmds[] = {
	{NS "::hash",			hash_cmd,			NULL},
	{NS "::ecc_verify",		ecc_verify,			NULL},
	{NULL,					NULL,				NULL}
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
	if (Tcl_InitStubs(interp, TCL_VERSION, 0) == NULL)
		return TCL_ERROR;
#endif

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
				Tcl_FreeInternalRep(obj);
				Tcl_DeleteHashEntry(he);
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
#ifdef __cplusplus
}
#endif

// vim: foldmethod=marker foldmarker=<<<,>>> ts=4 shiftwidth=4
