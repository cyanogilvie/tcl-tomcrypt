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
// prng_class.c internal interface <<<
int prng_class_init(Tcl_Interp* interp, struct interp_cx* l);
// prng_class.c internal interface >>>

EXTERN int Tomcrypt_Init _ANSI_ARGS_((Tcl_Interp * interp));

#ifdef __cplusplus
}
#endif

#endif // _TOMCRYPTINT_H
// vim: foldmethod=marker foldmarker=<<<,>>> ts=4 shiftwidth=4
