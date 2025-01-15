#ifndef _TOMCRYPTINT_H
#define _TOMCRYPTINT_H
#include <tommath.h>
#include <tcl.h>
#include <tclOO.h>
#include "tclstuff.h"
#include <tomcrypt.h>
#include <stdint.h>
#include <inttypes.h>
#include <math.h>
#include "tip445.h"

// Must match with lit_str[] in tomcrypt.c
enum {
	L_EMPTY,
	L_NOBYTES,
	L_TRUE,
	L_FALSE,
	L_PRNG_CLASS,
	L_PRNG_CLASS_DEF,
	L_size
};

struct interp_cx {
	Tcl_Obj*	lit[L_size];
};

#ifdef __cplusplus
extern "C" {
#endif

#ifdef BUILD_tomcrypt
#undef TCL_STORAGE_CLASS
#define TCL_STORAGE_CLASS DLLEXPORT
#endif

#define NS	"::tomcrypt"

// tomcrypt.c internal interface <<<
void register_intrep(Tcl_Obj* obj);
void forget_intrep(Tcl_Obj* obj);
// tomcrypt.c internal interface >>>
// type_ecc_key.c interface <<<
int GetECCKeyFromObj(Tcl_Interp* interp, Tcl_Obj* obj, ecc_key** key);
// type_ecc_key.c interface >>>
// type_cipher_spec.c interface <<<
#define CIPHER_MODES_MAP_REGULAR \
		X(cbc,	CBC) \
		X(cfb,	CFB) \
		X(ofb,	OFB)
#define CIPHER_MODES_MAP_SPECIAL \
		X(ctr,	CTR) \
	/*	X(ecr,	ECR) */ \
		X(lrw,	LRW) \
		X(f8,	F8)
#define CIPHER_MODES_MAP \
		CIPHER_MODES_MAP_REGULAR \
		CIPHER_MODES_MAP_SPECIAL
enum cipher_mode {
#define X(lower, upper) CM_##upper,
	CIPHER_MODES_MAP
#undef X
	CM_size
};
typedef struct cipher_spec {
	int					cipher_idx;		// Index into cipher_descriptor
	int					key_size;		// Size in bytes
	enum cipher_mode	mode;			// CTR, CBC, etc
	union {
		int					ctr_mode;		// mode flags if mode is CTR
		Tcl_Obj*			tweak;			// if mode is LRW
		Tcl_Obj*			salt;			// if mode is F8
	};
} cipher_spec;

int GetCipherSpecFromObj(Tcl_Interp* interp, Tcl_Obj* obj, cipher_spec** spec);
// type_cipher_spec.c interface >>>
extern const char* cipher_mode_strs[];
// prng_class.c internal interface <<<
int GetPrngFromObj(Tcl_Interp* interp, Tcl_Obj* prng, prng_state* state, int* desc_idx);
int prng_class_init(Tcl_Interp* interp, struct interp_cx* l);
// prng_class.c internal interface >>>
// cipher.c internal interface <<<
OBJCMD(cipher_encrypt_cmd);
OBJCMD(cipher_decrypt_cmd);
// cipher.c internal interface >>>

EXTERN int Tomcrypt_Init _ANSI_ARGS_((Tcl_Interp * interp));

#ifdef __cplusplus
}
#endif

#endif // _TOMCRYPTINT_H

// vim: foldmethod=marker foldmarker=<<<,>>> ts=4 shiftwidth=4
