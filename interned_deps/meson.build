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

# The interned libtomcrypt and libtommath are built via their CMake builds
# with CMAKE_C_VISIBILITY_PRESET=hidden + CMAKE_VISIBILITY_INLINES_HIDDEN=ON
# (see tools/interned_deps.json), so every symbol from the two archives
# carries STV_HIDDEN into the final shared module and never enters its
# dynamic symbol table.  That keeps libtomcrypt's internal mp_* calls
# bound to its own bundled libtommath at static-link time and makes ELF
# symbol interposition impossible at load time -- so an older libtommath
# living in libtcl9.0.so (e.g. the 1.3.0 copy in the Tcl wrap-fallback
# build, which differs from the newer copy interned here) can't hijack
# libtomcrypt's internal arithmetic.  No linker-level symbol hiding
# needed, which keeps us portable to linkers without --exclude-libs
# (macOS ld64, etc.).
interned_deps_dep = declare_dependency(
  sources:      interned,
  compile_args: [
    '-I' + interned_prefix / 'include',
    '-DUSE_LTM', '-DLTM_DESC',
  ],
  link_args: [
    interned[0].full_path(),   # libtomcrypt.a
    interned[1].full_path(),   # libtommath.a
  ],
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
