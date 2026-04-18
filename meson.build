project('tomcrypt', 'c',
  version:          '0.9.2',
  default_options:  ['c_std=c11', 'warning_level=3', 'werror=true'],
  meson_version:    '>=1.3.0',
)

cc = meson.get_compiler('c')
fs = import('fs')

# re2c lexer generation (fallback wrap available)
re2c_prog = find_program('re2c', version: '>=4.3', native: true, required: true)
re2c_args = [re2c_prog, '--case-ranges', '-W', '-Wno-nondeterministic-tags', '-o', '@OUTPUT@', '@INPUT@']

add_project_arguments('-D_POSIX_C_SOURCE=200809L', language: 'c')
add_project_arguments('-DBUILD_tomcrypt', language: 'c')
add_project_arguments(cc.get_supported_arguments([
    '-Wno-missing-field-initializers',
  ]), language: 'c')

if get_option('debug')
  add_project_arguments(cc.get_supported_arguments(['-ggdb3']), language: 'c')
endif

conf = configuration_data()
conf.set10('UNLOAD',   get_option('unload'))
conf.set10('TESTMODE', get_option('testmode'))
conf.set10('DEBUG',    get_option('debugmode'))

tea_want_shims = ['tip445', 'Tcl_GetBytesFromObj']

add_project_arguments('-DHAVE_CONFIG_H', language: 'c')

deps = []
inc  = []

subdir('interned_deps')
subdir('generic')
subdir('teabase')
subdir('doc')

meson.add_dist_script('tools/dist_fixup.sh')

# vim: foldmethod=marker foldmarker=<<<,>>> ts=2 shiftwidth=2 expandtab
