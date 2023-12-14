# TOMCRYPT

libtomcrypt Tcl wrapper - use cryptographic primitives in Tcl scripts

## SYNOPSIS

**package require tomcrypt** ?0.1?

**tomcrypt::hash** *algorithm* *bytes*  
**tomcrypt::ecc\_verify** *sig* *message* *pbkey*

## DESCRIPTION

This package provides a thin wrapper around a subset of libtomcrypt’s
functionality.

## COMMANDS

  - **tomcrypt::hash** *algorithm* *bytes*  
    Return the hash of *bytes*, using the *algorithm*. The values
    available for *algorithm* are those that are known by libtomcrypt.
    The returned value is the raw bytearray.
  - **tomcrypt::ecc\_verify** *sig* *message* *pbkey*  
    Verify the signature *sig* over the message *message* with public
    key *pbkey*. *sig* is in ANSI X9.62 format, *pbkey* is in ANSI X9.63
    section 4.3.6 format or the native libtomcrypt format, and message
    is the raw bytearray (typically a hash result) that was signed.
    Returns true if the signature is valid, false if not, and throws an
    error if it couldn’t parse *sig* or *pbkey*.

## EXAMPLES

Print out the hex-encoded md5 of “hello, tomcrypt” (normally, when
hashing strings, they should be converted to an encoding like utf-8
first, but this example leaves that out for simplicity’s sake):

``` tcl
puts [binary encode hex [tomcrypt::hash md5 "hello, tomcrypt"]]
```

Verify an ECC signature:

``` tcl
set verified    [tomcrypt::ecc_verify \
    [binary decode base64 MEUCIQDr/iC/fbEVKDydJ6/Jw95f53b6SGOXo7dMQtVGR48lMQIgeSKKZOph5MMqqj1p/e8NIgIghAe6AoNXir8D6NVwMOo=] \
    [binary decode hex 41091b1b32c6cd42f06b36f72801e01915bd99115f120c119ef7b781f7140dda] \
    [binary decode hex 046ddc90ba0fd79c53bd70060192211631d11ec581302e91c3559df4b20cdf747dbd8785a28c30b766e6b43325749ef70a923d0077fbc53cbcbb210de147c540e0] \
]
if {$verified} {
    puts "signature is valid"
} else {
    puts "signature is not valid"
}
```

## BUILDING

This package requires Tcl and the libtomcrypt, libtommath and
tomsfastmath libraries, those will need to be available (in the shared
library forms, or static libraries compiled with **-fPIC**) before
building this.

Fetch the code and submodules recursively:

``` sh
git clone --recurse-submodules https://github.com/cyanogilvie/tcl-tomcrypt
```

Then just the normal autoconf / TEA dance:

``` sh
autoconf
./configure
make
sudo make install
```

You may need extra args for `configure` if your Tcl install or the
libtomcrypt libraries are somewhere nonstandard.

## SEE ALSO

This package is built on the libtomcrypt library:
https://github.com/libtom/libtomcrypt, the libtommath library:
https://github.com/libtom/libtommath, and tomsfastmath:
https://github.com/libtom/tomsfastmath.

## PROJECT STATUS

This is a very early work in progress. Currently all that is implemented
and tested is the **hash** and **ecc\_verify** commands. More to come
soon.

With the nature of this package a lot of care is taken with memory
handling and test coverage. There are no known memory leaks or errors,
and the package is routinely tested by running its test suite (which
aims at full coverage) through valgrind. The `make valgrind`, `make
test` and `make coverage` build targets support these goals.

## LICENSE

This package is placed in the public domain, the author disclaims
copyright to the extent allowed by law. For those jurisdictions that
limit an author’s ability to disclaim copyright, then this package can
be used under the terms of the CC0, BSD, or MIT licenses. No
attribution, permission or fees are required to use this for whatever
you like, commercial or otherwise, though I would urge its users to do
good and not evil to the world.
