#!/bin/sh
# Runs INSIDE the pinned container, which has no network. Started by
# build_nsis_toolchain.py as `sh -eu build-inside.sh <scons arguments>`; this
# file is read from the checkout, never from the source archive.
#
#   /debs                         the locked packages, read-only
#   /src                          the unpacked source, read-only
#   /work/expected-packages.txt   what dpkg must list when the install is done
#   /out                          the only writable mount; the compiler tree goes to /out/nsis
#
# Environment: NSIS_SRC_ROOT (the archive's one root folder) and
# NSIS_VERSION_OUTPUT (what `makensis -VERSION` must print). The five folders
# above can be moved with NSIS_DEBS, NSIS_SRC, NSIS_WORK, NSIS_OUT and
# NSIS_BUILD; the tests do that, the container does not.
set -eu
umask 022

DEBS="${NSIS_DEBS:-/debs}"
SRC="${NSIS_SRC:-/src}"
WORK="${NSIS_WORK:-/work}"
OUT="${NSIS_OUT:-/out}"
BUILD="${NSIS_BUILD:-/build}"

[ "$(id -u)" = 0 ] || { echo "build-inside.sh must run as root in the container" >&2; exit 1; }
: "${NSIS_SRC_ROOT:?}" "${NSIS_VERSION_OUTPUT:?}"

# What dpkg lists as installed, one `name architecture version` line each, in
# byte order: the form expected-packages.txt is written in.
installed_list() {
  dpkg-query -W -f '${Package} ${Architecture} ${Version} ${db:Status-Abbrev}\n' \
    | awk '$4 == "ii" { print $1, $2, $3 }' | LC_ALL=C sort
}

# The locked files are installed with dpkg alone: apt cannot install a set of
# local files when it is also asked for one of them by name as a dependency
# ("Pathname to install is not absolute"), and it is not needed, since the lock
# is already the whole closure. dpkg refuses to unpack a package whose
# Pre-Depends is unpacked but not yet configured, so a round unpacks every file
# not yet installed, configures what it can, and the next round takes what the
# last one refused. Whatever is left after the last round is caught by the
# comparison below, which is the check that matters.
echo "== install the locked packages with dpkg, offline, from the lock's files"
export DEBCONF_NONINTERACTIVE_SEEN=true
round=0
while [ "$round" -lt 6 ]; do
  round=$((round + 1))
  installed_list > "$BUILD.have"
  todo=""
  for file in "$DEBS"/*.deb; do
    line="$(dpkg-deb -W --showformat='${Package} ${Architecture} ${Version}\n' "$file")"
    grep -qxF -- "$line" "$BUILD.have" || todo="$todo $file"
  done
  [ -n "$todo" ] || break
  echo "round $round: $(echo $todo | wc -w) files to install"
  # shellcheck disable=SC2086
  dpkg --force-confold --unpack $todo || true
  dpkg --force-confold --configure --pending || true
done

echo "== the installed set must be the locked set, and nothing else"
installed_list > "$BUILD.installed"
if ! cmp -s "$BUILD.installed" "$WORK/expected-packages.txt"; then
  diff "$WORK/expected-packages.txt" "$BUILD.installed" >&2 || true
  echo "the installed packages are not the locked set" >&2
  exit 1
fi

echo "== build, as an unprivileged user with no capabilities"
# The scripts in the source archive are not trusted. They run as an ordinary user
# (nobody) that holds no capability and cannot gain one, so they can write the
# source copy, their own home and the output tree, and nothing the installed
# tools or the checks below live in. Root only prepares the folders.
BUILDER=65534
mkdir "$BUILD"
cp -R --preserve=timestamps "$SRC/$NSIS_SRC_ROOT" "$BUILD/$NSIS_SRC_ROOT"
mkdir "$BUILD/home" "$OUT/nsis"
chown -R "$BUILDER:$BUILDER" "$BUILD" "$OUT/nsis"
unprivileged() {
  setpriv --reuid="$BUILDER" --regid="$BUILDER" --clear-groups --bounding-set=-all \
    --inh-caps=-all --no-new-privs env HOME="$BUILD/home" "$@"
}
cd "$BUILD/$NSIS_SRC_ROOT"
unprivileged scons "$@"

echo "== check what was built (the built programs run as the same unprivileged user)"
[ -x "$OUT/nsis/Bin/makensis" ] || { echo "no $OUT/nsis/Bin/makensis" >&2; exit 1; }
reported="$(unprivileged "$OUT/nsis/Bin/makensis" -VERSION)"
[ "$reported" = "$NSIS_VERSION_OUTPUT" ] || {
  echo "makensis reports '$reported', not '$NSIS_VERSION_OUTPUT'" >&2
  exit 1
}
unprivileged "$OUT/nsis/Bin/makensis" -HDRINFO || true

# No Windows binary (stub, plug-in, resource file) may import libwinpthread: the
# win32 thread model links none, and a posix-thread build would pull it into every
# plug-in the installer extracts. Imports of libgcc_s or libstdc++ are printed, not
# refused: the resource-only UI files under Contrib/UIs import libgcc_s and are
# never run. objdump's own failure stops the build (the listing goes to a file
# first, since a pipe's status is its last command's and dash has no pipefail).
find "$OUT/nsis" -type f -exec sh -ec '
  listing="$(mktemp)"
  for file in "$@"; do
    [ "$(head -c 2 "$file")" = MZ ] || continue
    i686-w64-mingw32-objdump -p "$file" > "$listing"
    names="$(grep -i "DLL Name:" "$listing" || true)"
    if echo "$names" | grep -qi "libwinpthread"; then
      echo "$file imports a MinGW runtime DLL" >&2
      exit 1
    fi
    if echo "$names" | grep -qiE "libgcc_s|libstdc\+\+"; then
      echo "note: $file imports a GCC runtime DLL"
    fi
  done
  rm -f "$listing"' sh {} +
echo "built $(find "$OUT/nsis" -type f | wc -l) files"
