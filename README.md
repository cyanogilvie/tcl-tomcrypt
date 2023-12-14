# TOMCRYPT

libtomcrypt Tcl wrapper - use cryptographic primitives in Tcl scripts

## SYNOPSIS

**package require tomcrypt** ?0.1?

**tomcrypt::hash** *algorithm* *bytes*

## DESCRIPTION

This package provides a thin wrapper around a subset of libtomcrypt’s
functionality.

## COMMANDS

  - **tomcrypt::hash** *algorithm* *bytes*  
    Return the hash of *bytes*, using the *algorithm*. The values
    available for *algorithm* are those that are known by libtomcrypt.
    The returned value is the raw bytearray.

## EXAMPLES

Print out the hex-encoded md5 of “hello, tomcrypt” (normally, when
hashing strings, they should be converted to an encoding like utf-8
first, but this example leaves that out for simplicity’s sake):

``` tcl
package require tomcrypt

puts [binary encode hex [tomcrypt::hash md5 "hello, tomcrypt"]]
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
and tested is the **hash** command. More to come soon.

## LICENSE

This package is placed in the public domain, the author disclaims
copyright to the extent allowed by law. For those jurisdictions that
limit an author’s ability to disclaim copyright, then this package can
be used under the terms of the CC0, BSD, or MIT licenses. No
attribution, permission or fees are required to use this for whatever
you like, commercial or otherwise, though I would urge its users to do
good and not evil to the world.
