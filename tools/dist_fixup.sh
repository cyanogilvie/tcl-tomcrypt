#!/bin/sh
# Called by meson.add_dist_script() during "meson dist".
set -e

dist="$MESON_DIST_ROOT"
build="$MESON_BUILD_ROOT"

if [ -f "$build/doc/README.md" ]; then
    cp "$build/doc/README.md" "$dist/README.md"
fi

if [ -f "$build/doc/tomcrypt.n" ]; then
    mkdir -p "$dist/doc"
    cp "$build/doc/tomcrypt.n" "$dist/doc/tomcrypt.n"
fi

# .github dirs (top-level and inside dep submodules) aren't useful in
# a release tarball.
find "$dist" -type d -name .github -exec rm -rf {} +

# Replace symlinks with copies of their targets so the tarball works
# on Windows (which doesn't support symlinks without special permissions).
find "$dist" -type l | while read -r link; do
    target=$(readlink -f "$link")
    if [ -e "$target" ]; then
        rm "$link"
        if [ -d "$target" ]; then
            cp -a "$target" "$link"
        else
            cp "$target" "$link"
        fi
    fi
done
