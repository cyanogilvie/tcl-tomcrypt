#
# Include the TEA standard macro set
#

builtin(include,tclconfig/tcl.m4)

#
# Add here whatever m4 macros you want to define for your package
#

builtin(include,teabase/teabase.m4)

AC_DEFUN([ENABLE_DEFAULT_UNLOAD], [
	#trap 'echo "val: (${enable_unload+set}), unload_ok: ($unload_ok), UNLOAD: ($UNLOAD)"' DEBUG
	AC_MSG_CHECKING([whether to support unloading])
	AC_ARG_ENABLE(unload,
		AS_HELP_STRING([--enable-unload],[Add support for unloading this shared library (default: yes)]),
		[unload_ok=$enableval], [unload_ok=yes])

	if test "$unload_ok" = "yes" -o "${UNLOAD}" = 1; then
		UNLOAD=1
		AC_MSG_RESULT([yes])
	else
		UNLOAD=0
		AC_MSG_RESULT([no])
	fi

	AC_DEFINE_UNQUOTED([UNLOAD], [$UNLOAD], [Unload enabled?])
	#trap '' DEBUG
])

