inc += include_directories('.')

pkg_sources = files(
  'aead.c',
  'cipher.c',
  'prng_class.c',
  'tomcrypt.c',
  'type_cipher_spec.c',
  'type_ecc_curve.c',
  'type_ecc_key.c',
  'type_rsa_key.c',
)

lexer_pem = custom_target('lexer_pem',
  input:   'pem.re',
  output:  'pem.c',
  command: re2c_args,
)

pkg_sources += [lexer_pem]
