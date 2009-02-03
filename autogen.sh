#!/bin/sh
# Run this to generate all the initial makefiles, etc.
set -e

PACKAGE=freeipa

LIBTOOLIZE=${LIBTOOLIZE-libtoolize}
LIBTOOLIZE_FLAGS="--copy --force"
AUTOHEADER=${AUTOHEADER-autoheader}
AUTOMAKE_FLAGS="--add-missing --gnu"
AUTOCONF=${AUTOCONF-autoconf}

# automake 1.8 requires autoconf 2.58
# automake 1.7 requires autoconf 2.54
automake_min_vers=1.7
aclocal_min_vers=$automake_min_vers
autoconf_min_vers=2.54
libtoolize_min_vers=1.4

# The awk-based string->number conversion we use needs a C locale to work 
# as expected. Setting LC_ALL overrides whether the user set LC_ALL,
# LC_NUMERIC, or LANG.
LC_ALL=C

ARGV0=$0

# Allow invocation from a separate build directory; in that case, we change
# to the source directory to run the auto*, then change back before running configure
#srcdir=`dirname $ARGV0`
#test -z "$srcdir" && srcdir=.
srcdir="."

#ORIGDIR=`pwd`

#cd $srcdir

# Usage:
#     compare_versions MIN_VERSION ACTUAL_VERSION
# returns true if ACTUAL_VERSION >= MIN_VERSION
compare_versions() {
    ch_min_version=$1
    ch_actual_version=$2
    ch_status=0
    IFS="${IFS=         }"; ch_save_IFS="$IFS"; IFS="."
    set $ch_actual_version
    for ch_min in $ch_min_version; do
        ch_cur=`echo $1 | sed 's/[^0-9].*$//'`; shift # remove letter suffixes
        if [ -z "$ch_min" ]; then break; fi
        if [ -z "$ch_cur" ]; then ch_status=1; break; fi
        if [ $ch_cur -gt $ch_min ]; then break; fi
        if [ $ch_cur -lt $ch_min ]; then ch_status=1; break; fi
    done
    IFS="$ch_save_IFS"
    return $ch_status
}

if ($AUTOCONF --version) < /dev/null > /dev/null 2>&1 ; then
    if ($AUTOCONF --version | head -n 1 | awk 'NR==1 { if( $(NF) >= '$autoconf_min_vers') \
			       exit 1; exit 0; }');
    then
       echo "$ARGV0: ERROR: \`$AUTOCONF' is too old."
       $AUTOCONF --version
       echo "           (version $autoconf_min_vers or newer is required)"
       DIE="yes"
    fi
else
    echo $AUTOCONF: command not found
    echo
    echo "$ARGV0: ERROR: You must have \`autoconf' installed to compile $PACKAGE."
    echo "           (version $autoconf_min_vers or newer is required)"
    DIE="yes"
fi

#
# Hunt for an appropriate version of automake and aclocal; we can't
# assume that 'automake' is necessarily the most recent installed version
#
# We check automake first to allow it to be a newer version than we know about.
#
if test x"$AUTOMAKE" = x || test x"$ACLOCAL" = x ; then
  am_ver=""
  for ver in "" "-1.9" "-1.8" "-1.7" ; do
    am="automake$ver"
    if ($am --version) < /dev/null > /dev/null 2>&1 ; then
      if ($am --version | head -n 1 | awk 'NR==1 { if( $(NF) >= '$automake_min_vers') \
	  		 exit 1; exit 0; }'); then : ; else
         am_ver=$ver
         break;
      fi
    fi
  done

  AUTOMAKE=${AUTOMAKE-automake$am_ver}
  ACLOCAL=${ACLOCAL-aclocal$am_ver}
fi

#
# Now repeat the tests with the copies we decided upon and error out if they
# aren't sufficiently new.
#
if ($AUTOMAKE --version) < /dev/null > /dev/null 2>&1 ; then
      automake_actual_version=`$AUTOMAKE --version | head -n 1 | \
                               sed 's/^.*[ 	]\([0-9.]*[a-z]*\).*$/\1/'`
      if ! compare_versions $automake_min_vers $automake_actual_version; then
	  echo "$ARGV0: ERROR: \`$AUTOMAKE' is too old."
	  $AUTOMAKE --version
	  echo "           (version $automake_min_vers or newer is required)"
	  DIE="yes"
      fi
  if ($ACLOCAL --version) < /dev/null > /dev/null 2>&1; then
      aclocal_actual_version=`$ACLOCAL --version | head -n 1 | \
                               sed 's/^.*[ 	]\([0-9.]*[a-z]*\).*$/\1/'`

      if ! compare_versions $aclocal_min_vers $aclocal_actual_version; then
	  echo "$ARGV0: ERROR: \`$ACLOCAL' is too old."
	  $ACLOCAL --version
	  echo "           (version $aclocal_min_vers or newer is required)"
	  DIE="yes"
      fi
  else
    echo $ACLOCAL: command not found
    echo
    echo "$ARGV0: ERROR: Missing \`$ACLOCAL'"
    echo "           The version of $AUTOMAKE installed doesn't appear recent enough."
    DIE="yes"
  fi
else
    echo $AUTOMAKE: command not found
    echo
    echo "$ARGV0: ERROR: You must have \`automake' installed to compile $PACKAGE."
    echo "           (version $automake_min_vers or newer is required)"
    DIE="yes"
fi

if ($LIBTOOLIZE --version) < /dev/null > /dev/null 2>&1 ; then
    if ($LIBTOOLIZE --version | awk 'NR==1 { if( $4 >= '$libtoolize_min_vers') \
			       exit 1; exit 0; }');
    then
       echo "$ARGV0: ERROR: \`$LIBTOOLIZE' is too old."
       echo "           (version $libtoolize_min_vers or newer is required)"
       DIE="yes"
    fi
else
    echo $LIBTOOLIZE: command not found
    echo
    echo "$ARGV0: ERROR: You must have \`libtoolize' installed to compile $PACKAGE."
    echo "           (version $libtoolize_min_vers or newer is required)"
    DIE="yes"
fi

if test -z "$ACLOCAL_FLAGS"; then
    acdir=`$ACLOCAL --print-ac-dir`
    if [ ! -f $acdir/pkg.m4 ]; then
	echo "$ARGV0: Error: Could not find pkg-config macros."
	echo "        (Looked in $acdir/pkg.m4)"
	echo "        If pkg.m4 is available in /another/directory, please set"
	echo "        ACLOCAL_FLAGS=\"-I /another/directory\""
	echo "        Otherwise, please install pkg-config."
	echo ""
	echo "pkg-config is available from:"
	echo "http://www.freedesktop.org/software/pkgconfig/"
	DIE=yes
    fi
fi

if test "X$DIE" != X; then
  exit 1
fi


if test -z "$*"; then
  echo "$ARGV0:	Note: \`./configure' will be run with no arguments."
  echo "		If you wish to pass any to it, please specify them on the"
  echo "		\`$0' command line."
  echo
fi

do_cmd() {
    echo "$ARGV0: running \`$@'"
    $@
}

# I don't want a tool telling me what files I need to have
remauto=0
if [ ! -e AUTHORS ]; then
    touch AUTHORS ChangeLog NEWS README
    remauto=1
fi

do_cmd $LIBTOOLIZE $LIBTOOLIZE_FLAGS

do_cmd $ACLOCAL $ACLOCAL_FLAGS

do_cmd $AUTOHEADER

do_cmd $AUTOMAKE $AUTOMAKE_FLAGS

do_cmd $AUTOCONF

if [ $remauto -eq 1 ]; then
    rm -f AUTHORS ChangeLog NEWS README
fi

#cd $ORIGDIR || exit 1

rm -f config.cache

do_cmd $srcdir/configure --cache-file=config.cache --disable-static --enable-maintainer-mode --enable-gtk-doc ${1+"$@"} && echo "Now type \`make' to compile" || exit 1
