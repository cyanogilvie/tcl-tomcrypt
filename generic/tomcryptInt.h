#ifndef _TOMCRYPTINT_H
#define _TOMCRYPTINT_H
#include <hedley.h>
#if defined(__has_c_attribute)
#	if __has_c_attribute(clang::suppress)
#		define SUPPRESS_DEADSTORE [[clang::suppress]]
#	endif
#endif
#ifndef SUPPRESS_DEADSTORE
#	define SUPPRESS_DEADSTORE
#endif
#include <config.h>
#include <tcl.h>
#include <tclOO.h>
#include <tclstuff.h>
#include <stdint.h>
#include <inttypes.h>
#include <math.h>
#include <string.h>
#include <tip445.h>
#include <getbytes.h>
#include <libtomcrypt/tomcrypt.h>

/* Tcl_Size compat for Tcl 8.  config.h may provide it as a #define. */
#ifndef TCL_SIZE_MAX
# ifndef Tcl_Size
typedef int Tcl_Size;
# endif
# define Tcl_GetSizeIntFromObj Tcl_GetIntFromObj
# define TCL_SIZE_MAX      INT_MAX
# define TCL_SIZE_MODIFIER ""
#endif

#define NS	"::tomcrypt"

#define BUF_BIGVAL_STATIC_BYTES 512

#define LITSTRS \
	X(L_EMPTY,			"") \
	X(L_NOBYTES,		"") \
	X(L_TRUE,			"1") \
	X(L_FALSE,			"0") \
	X(L_PRNG_CLASS,		NS "::prng") \
	X(L_PRNG_CLASS_DEF,	"::oo::class create " NS "::prng {}") \
// Line intentionally left blank
enum {
#define X(name, str) name,
	LITSTRS
#undef X
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

// tomcrypt.c internal interface <<<
void register_intrep(Tcl_Obj* obj);
void forget_intrep(Tcl_Obj* obj);
// tomcrypt.c internal interface >>>
// pem.re interface <<<
int pem_load_first_key(Tcl_Interp* interp, Tcl_Obj* obj, uint8_t** der_buf, unsigned long* der_len, int* is_private_key, const char** type);
// pem.re interface >>>
// type_ecc_key.c interface <<<
// Add an enum for key type expectation
typedef enum {
    ECC_EXPECT_PUBLIC,
    ECC_EXPECT_PRIVATE
} ecc_key_type_t;

int GetECCKeyFromObj(Tcl_Interp* interp, Tcl_Obj* obj, ecc_key_type_t expect_type, ecc_key** key);
Tcl_Obj* NewECCKeyObj(ecc_key** key);
// type_ecc_key.c interface >>>
// type_ecc_curve.c interface <<<
int GetECCCurveFromObj(Tcl_Interp* interp, Tcl_Obj* obj, const ltc_ecc_curve** curve);
// type_ecc_curve.c interface >>>
// type_rsa_key.c interface <<<
typedef enum {
    RSA_EXPECT_PUBLIC,
    RSA_EXPECT_PRIVATE
} rsa_key_type_t;

int GetRSAKeyFromObj(Tcl_Interp* interp, Tcl_Obj* obj, rsa_key_type_t expect_type, rsa_key** key);
Tcl_Obj* NewRSAKeyObj(rsa_key** key);
// type_rsa_key.c interface >>>
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
int GetPrngFromObj(Tcl_Interp* interp, Tcl_Obj* prng, prng_state** state, int* desc_idx);
int prng_class_init(Tcl_Interp* interp, struct interp_cx* l);
// prng_class.c internal interface >>>
// cipher.c internal interface <<<
OBJCMD(cipher_encrypt_cmd);
OBJCMD(cipher_decrypt_cmd);
// cipher.c internal interface >>>
// aead.c internal interface <<<
OBJCMD(aead_cmd);
// aead.c internal interface >>>
// rsa functions <<<
OBJCMD(rsa_make_key_cmd);
OBJCMD(rsa_sign_hash_cmd);
OBJCMD(rsa_verify_hash_cmd);
OBJCMD(rsa_encrypt_key_cmd);
OBJCMD(rsa_decrypt_key_cmd);
// rsa functions >>>

#ifdef __cplusplus
}
#endif

#endif // _TOMCRYPTINT_H

// vim: ft=c foldmethod=marker foldmarker=<<<,>>> ts=4 shiftwidth=4
