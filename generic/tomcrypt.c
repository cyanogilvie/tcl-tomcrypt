#include "tomcryptInt.h"


#ifdef __cplusplus
extern "C" {
#endif
DLLEXPORT int Tomcrypt_Init(Tcl_Interp* interp) //<<<
{
	int		code = TCL_OK;

#if USE_TCL_STUBS
	if (Tcl_InitStubs(interp, TCL_VERSION, 0) == NULL)
		return TCL_ERROR;
#endif

	code = Tcl_PkgProvide(interp, PACKAGE_NAME, PACKAGE_VERSION);
	if (code != TCL_OK) goto finally;

finally:
	return code;
}

//>>>
#ifdef __cplusplus
}
#endif

// vim: foldmethod=marker foldmarker=<<<,>>> ts=4 shiftwidth=4
