% tomcrypt(3) 0.2 | libtomcrypt Tcl wrapper
% Cyan Ogilvie
% 0.2

# TOMCRYPT

libtomcrypt Tcl wrapper - use cryptographic primitives in Tcl scripts


## SYNOPSIS

**package require tomcrypt** ?0.2?

**tomcrypt::hash** *algorithm* *bytes*\
**tomcrypt::ecc_verify** *sig* *message* *pbkey*\
**tomcrypt::rng_bytes** *count*\
**tomcrypt::prng** **create** *prngInstance* *type* ?*entropy*?\
**tomcrypt::prng** **new** *type* ?*entropy*?

PRNG instance methods:

*prngInstance* **bytes** *count*\
*prngInstance* **add_entropy** *entropy*\
*prngInstance* **integer** *lower* *upper*\
*prngInstance* **double**\
*prngInstance* **export**\
*prngInstance* **destroy**


## DESCRIPTION

This package provides a thin wrapper around a subset of libtomcrypt's functionality.


## COMMANDS

**tomcrypt::hash** *algorithm* *bytes*
:   Return the hash of *bytes*, using the *algorithm*.  The values available for *algorithm* are
    those that are known by libtomcrypt.  The returned value is the raw bytearray.

**tomcrypt::ecc_verify** *sig* *message* *pbkey*
:   Verify the signature *sig* over the message *message* with public key *pbkey*.  *sig* is
    in ANSI X9.62 format, *pbkey* is in ANSI X9.63 section 4.3.6 format or the native libtomcrypt
    format, and message is the raw bytearray (typically a hash result) that was signed.
    Returns true if the signature is valid, false if not, and throws an error if it
    couldn't parse *sig* or *pbkey*.

**tomcrypt::prng** **create** *prngInstance* *type* ?*entropy*?
:   Create a PRNG instance accessed by the command name *prngInstance*, using the *type*,
    such as **fortuna** or **chacha20** (as known to libtomcrypt), or "" (an empty
    string) to select the recommended default which may change between releases,
    and bootstrapped with *entropy*, which must be a bytearray of high entropy
    bytes.  If *entropy* is omitted the PRNG will be bootstrapped with at least 256
    bits of entropy from the platform's default cryptographic RNG.  Returns the
    *prngInstance* command name.

**tomcrypt::prng** **new** *type* ?*entropy*?
:   As above, but the *prngInstance* command name is picked automatically.


## PRNG INSTANCE METHODS

*prngInstance* **bytes** *count*
:   Retrieve *count* random bytes from the PRNG

*prngInstance* **add_entropy** *entropy*
:   Add entropy to the PRNG, given as a bytearray *entropy*.  *entropy* should come from a high
    quality source of random bytes such as the platform's secure RNG or a previously exported
    state by *prngInstance* **export**.

*prngInstance* **integer** *lower* *upper*
:   Generate a random integer between *lower* and *upper*, inclusive, with uniform distribution.

*prngInstance* **double**
:   Generate a double precision floating point value in the range [0.0, 1.0) (inclusive of the
    lower bound but not the upper).  The result has 53 bits of entropy, uniform distribution
    and equal resolution across the range.

*prngInstance* **export**
:   Export entropy, returning the random bytearray.  Intended to preserve entropy across PRNG
    instances and reduce the demands on scarce platform entropy.  To do that, supply the
    result of this command to the *entropy* argument when creating a new PRNG instance.

*prngInstance* **destroy**
:   Destroy the instance.  After returning, the *prngInstance* command no longer exists and
    all resources are released.


## EXAMPLES

Print out the hex-encoded md5 of "hello, tomcrypt" (normally, when hashing strings, they should
be converted to an encoding like utf-8 first, but this example leaves that out for simplicity's sake):

~~~tcl
puts [binary encode hex [tomcrypt::hash md5 "hello, tomcrypt"]]
~~~

Verify an ECC signature:

~~~tcl
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
~~~

Create a Fortuna PRNG with automatic entropy bootstrapping
and use it to generate 10 random bytearrays:

~~~tcl
tomcrypt::prng create csprng fortuna
for {set i 0} {$i < 10} {incr i} {
    puts "random bytes $i: [binary encode hex [csprng bytes 8]]
}
csprng destroy
~~~

Preserve scarce platform entropy between runs, and leave the choice of the PRNG implementation
up to the library, and mix in 8 bytes of entropy from the platform RNG every 10 minutes:

~~~tcl
proc readbin filename {
    set h [open $filename rb]
    try {read $h} finally {close $h}
}

proc writebin {filename bytes} {
    set h [open $filename wb]
    try {puts -nonewline $h $bytes} finally {close $h}
}

# Bootstrap using saved entropy if we have it
set saved_entropy_filename  somefile.bin
if {[file exists $saved_entropy_filename]} {
    tomcrypt::prng create csprng {} [readbin $saved_entropy_filename]
} else {
    tomcrypt::prng create csprng {}
}

# Save entropy for next time
writebin $saved_entropy_filename [csprng export]

# Mix in entropy periodically
coroutine background_add_entropy eval {
    trace add command csprng delete [list [info coroutine] done]
    while 1 {
        after [expr {10 * 60 * 1000}] [list [info coroutine] stir]
        switch -- [lindex [yield] 0] {
            stir    { csprng add_entropy [tomcrypt::rng_bytes 8] }
            done    { break }
            default { error "expecting stir or done" }
        }
    }
}

# Generate a random 256 bit integer
set key [csprng integer 0 [expr {2**256-1}]]

# Enter the event loop
if {![info exists exit]} {
    vwait exit
}
exit $exit
~~~


## BUILDING

This package has no external dependencies other than Tcl.  The libtom libraries
it depends on are included as submodules (or baked into the release tarball)
and are built and statically linked as part of the package build process.

Currently Tcl 8.7 is required, but if needed polyfills could be built to support 8.6.

### From a Release Tarball
Download and extract the release, then:

~~~sh
./configure
make
sudo make install
~~~

### From the Git Sources
Fetch the code and submodules recursively:

~~~sh
git clone --recurse-submodules https://github.com/cyanogilvie/tcl-tomcrypt
~~~

Then just the normal autoconf / TEA dance:

~~~sh
autoconf
./configure
make
sudo make install
~~~

### In a Docker Build
Build from a specified release version, avoiding layer pollution and only
adding the installed package without documentation to the image, and strip
debug symbols, minimising image size:

~~~Dockerfile
WORKDIR /tmp/tcl-tomcrypt
RUN wget https://github.com/cyanogilvie/tcl-tomcrypt/releases/download/v0.2/tcl-tomcrypt-v0.2.tar.gz -O - | tar xz --strip-components=1 && \
    ./configure; make test install-binaries install-libraries && \
    strip /usr/local/lib/libtomcrypt*.so && \
    cd .. && rm -rf tcl-tomcrypt
~~~

For any of the build methods you may need to pass `--with-tcl` to `configure`
if your Tcl install is somewhere nonstandard.

### Testing
Since this package deals with security sensitive code, it's a good idea to
run the test suite after building (especially in any automated build or CI/CD
pipeline):

~~~sh
make test
~~~

And maybe also the memory checker `valgrind`:

~~~sh
make valgrind
~~~


## SECURITY

Given the limitations of a scripting language environment, this package's code
does not have sufficient control over freed memory contents (or memory paged to
disk) to guarantee that key material or other sensitive material (like
decrypted messages) can't leak in a way that could be exploited by other code
running on the shared memory (or disk) machine.  For this reason, careful
consideration should be given to the security requirements of the application
as a whole when using this package in a shared execution context, or in a
virtual machine.  That said, operations that do not rely on secret values
(like verifying cryptographic signatures) safe in these shared environments.


## FUZZING

TODO


## AVAILABLE IN

The most recent release of this package is available by default in the
`alpine-tcl` container image: docker.io/cyanogilvie/alpine-tcl and the
`cftcl` Tcl runtime snap: https://github.com/cyanogilvie/cftcl.


## SEE ALSO

This package is built on the libtomcrypt library: https://github.com/libtom/libtomcrypt, the
libtommath library: https://github.com/libtom/libtommath, and tomsfastmath: https://github.com/libtom/tomsfastmath.


## PROJECT STATUS

This is a very early work in progress.  Currently all that is implemented and
tested are the **hash** and **ecc_verify** commands.  More to come soon.

With the nature of this package a lot of care is taken with memory handling
and test coverage.  There are no known memory leaks or errors, and the
package is routinely tested by running its test suite (which aims at full
coverage) through valgrind.  The `make valgrind`, `make test` and `make coverage`
build targets support these goals.


## LICENSE

This package is placed in the public domain: the author disclaims copyright and
liability to the extent allowed by law.  For those jurisdictions that limit an
author's ability to disclaim copyright, then this package can be used under the
terms of the CC0, BSD, or MIT licenses.  No attribution, permission or fees are
required to use this for whatever you like, commercial or otherwise, though I
would urge its users to do good and not evil to the world.

