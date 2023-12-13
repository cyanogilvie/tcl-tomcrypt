#include <tcl.h>
#include <tomcrypt.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef BUILD_tomcrypt
#undef TCL_STORAGE_CLASS
#define TCL_STORAGE_CLASS DLLEXPORT
#endif

#define NS	"::tomcrypt"

EXTERN int Tomcrypt_Init _ANSI_ARGS_((Tcl_Interp * interp));

#ifdef __cplusplus
}
#endif

// vim: foldmethod=marker foldmarker=<<<,>>> ts=4 shiftwidth=4
