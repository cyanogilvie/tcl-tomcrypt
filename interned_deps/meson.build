# Interned libtomcrypt + libtommath (static, built from submodules).  These
# are used internally by libtomcrypt; extension C code talks to Tcl's own
# libtommath (via <tclTomMath.h> and the TclBN stubs), not to this one.

py = import('python').find_installation()

interned_prefix = meson.current_build_dir() / 'prefix'
interned_build  = meson.current_build_dir() / 'build'

interned = custom_target('interned-deps',
  output: [
    'libtomcrypt.a',
    'libtommath.a',
    'interned-deps.stamp',
  ],
  command: [py,
    meson.project_source_root() / 'teabase/tools/interned_deps.py',
    '--manifest',    meson.project_source_root() / 'tools/interned_deps.json',
    '--source-root', meson.project_source_root(),
    '--prefix',      interned_prefix,
    '--build',       interned_build,
    '--copy-artifact', 'lib/libtomcrypt.a:' + meson.current_build_dir() / 'libtomcrypt.a',
    '--copy-artifact', 'lib/libtommath.a:'  + meson.current_build_dir() / 'libtommath.a',
    '--stamp',       meson.current_build_dir() / 'interned-deps.stamp',
  ],
  depend_files: files(
    meson.project_source_root() / 'tools/interned_deps.json',
    meson.project_source_root() / 'teabase/tools/interned_deps.py',
  ),
  console:          true,
  build_by_default: true,
)

# Hide the interned libtomcrypt/libtommath symbols from the final shared
# module's dynamic symbol table.  Without this, symbols like mp_prime_is_prime
# collide with the copy that Tcl's own bundled libtommath exports from
# libtcl9.0.so, and the dynamic loader can resolve libtomcrypt-internal
# calls to Tcl's older libtommath-1.3.0, which (at least in the version
# pinned by the Tcl 9.0.3 wrap) has an alignment bug in mp_prime_is_prime
# that trips the stack protector on rsa_make_key.  We only need these
# libraries for internal use -- nothing in our public C API exposes them.
#
# --exclude-libs is a GNU ld / lld / gold extension; skip gracefully on
# linkers that don't support it (e.g. macOS ld64).
interned_hide_args = cc.get_supported_link_arguments([
  # GNU ld requires colon (or repeated flag) to delimit multiple archive
  # names here -- comma gets split into separate linker inputs and the
  # second archive is treated as a file to link, which fails to find it.
  '-Wl,--exclude-libs=libtomcrypt.a:libtommath.a',
])

interned_deps_dep = declare_dependency(
  sources:      interned,
  compile_args: [
    '-I' + interned_prefix / 'include',
    '-DUSE_LTM', '-DLTM_DESC',
  ],
  link_args: [
    interned[0].full_path(),   # libtomcrypt.a
    interned[1].full_path(),   # libtommath.a
  ] + interned_hide_args,
)

run_target('deps-clean',
  command: [py, '-c',
    'import os, shutil, sys\n' +
    'for p in sys.argv[1:]:\n' +
    '    if os.path.isdir(p): shutil.rmtree(p, ignore_errors=True)\n' +
    '    else:\n' +
    '        try: os.remove(p)\n' +
    '        except FileNotFoundError: pass',
    interned_prefix,
    interned_build,
    meson.current_build_dir() / 'interned-deps.stamp',
    meson.current_build_dir() / 'libtomcrypt.a',
    meson.current_build_dir() / 'libtommath.a',
  ],
)

deps += interned_deps_dep
