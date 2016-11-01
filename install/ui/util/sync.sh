#!/bin/bash

# Authors:
#    Petr Vobornik <pvoborni@redhat.com>
#
#  Copyright (C) 2012 Red Hat
#  see file 'COPYING' for use and warranty information
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.
set -o errexit

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
RDIR=$DIR/../release

usage() {
cat <<-__EOF__;
NAME
    sync.sh - Sync development files with installed FreeIPA

SYNOPSIS
    path/to/sync.sh [--help] [--host login@host.name] [--freeipa]

DESCRIPTION
    Sync UI development files from 'install' dir to '/usr/share/ipa' dir.

OPTIONS
    --help      print the help message

    -h
    --host
                host login in format login@hostname
    -f
    --freeipa
                files from ui/src/freeipa to ui/js/freeipa
    --libs
                files from ui/src/libs to ui/js/libs
    -d
    --dojo
                files from ui/src/dojo to ui/js/dojo
    --misc
                files from ui/ non-recursive
    --images
                files from ui/images
    --css
                files from ui/css
    --data
                files from ui/test/data
    --migration
                files from migration/
    --config
                files from html/
    --strings
                ipaserver/plugins/internal.py
    -C
    --compiled
                changes source dir of --freeipa and --dojo to /src/build/freeipa
                and /src/built/dojo
    -c
    --clean
                removes all files from from target dir
    -e
    --existing
                updates only existing files. Don't transfer new files.
    -r
    --restart
                restart httpd
    --create-dir
                create target dir
    --no-sync
                don't copy files
__EOF__
}

args=`getopt -u -l help,ui,host:,freeipa,libs,dojo,misc,images,css,data,\
migration,config,strings,compiled,clean,restart,create-dir,no-sync h:fdcCer $*`

if test $? != 0
then
    usage
    exit 1
fi

set -- $args
for i
do
    case "$i" in
        --help)
            shift
            HELP=1
            ;;
        --host | -h)
            shift
            HOST=$1
            shift
            ;;
        --freeipa | -f)
            shift
            FREEIPA=1
            ;;
        --libs)
            shift
            LIBS=1
            ;;
        --dojo)
            shift
            DOJO=1
            ;;
        --misc)
            shift
            MISC=1
            ;;
        --images)
            shift
            IMAGES=1
            ;;
        --css)
            shift
            CSS=1
            ;;
        --data)
            shift
            DATA=1
            ;;
        --migration)
            shift
            MIGRATION=1
            ;;
        --config)
            shift
            CONFIG=1
            ;;
        --strings)
            shift
            STRINGS=1
            ;;
        --compiled | -C)
            shift
            COMPILED=1
            ;;
        --clean | -c)
            shift
            CLEAN=1
            ;;
        --restart | -r)
            shift
            RESTART=1
            ;;
        --existing | -e)
            shift
            EXISTING=1
            ;;
        --create-dir)
            shift
            CREATE_DIR=1
            ;;
        --no-sync)
            shift
            NO_SYNC=1
            ;;
        *)
            ;;
    esac
done

set -- $args

if [[ $HELP ]] ; then
    usage
    exit 0
fi

sync-files() {
    # global vars: (SOURCE, TARGET, HOST,  RECURSIVE, EXISTING, CLEAN)
    # local vars: OPTIONS
    # TARGET: absolute path or relative to account home
    # SOURCE: file expression
    # HOST: in format username@host.name


    if [[ $HOST ]] ; then
        #remote sync

        if [[ $CREATE_DIR ]] ; then
            echo "$HOST \"mkdir $TARGET\""
            ssh $HOST "mkdir -p $TARGET"
        fi

        if [[ $CLEAN = 1 ]] ; then
            if [[ $RECURSIVE = 1 ]] ; then
                echo "ssh $HOST \"rm -rf $TARGET/*\""
                ssh $HOST "rm -rfv $TARGET/*"
            else
                echo "ssh $HOST \"rm -fv $TARGET/*\""
                ssh $HOST "rm -fv $TARGET/*"
            fi
        fi

        if [[ ! $NO_SYNC ]] ; then
            # options for rsync
            # archvive, verbose, compress, update
            # archive: rlptgoD - recursive, links, permissions, times, groups,
            #          owner, specials

            OPTIONS='-avzu'
            if [[ $EXISTING = 1 ]] ; then
                OPTIONS="$OPTIONS --existing"
            fi
            if [[ $RECURSIVE = 0 ]] ; then
                OPTIONS="$OPTIONS --no-r"
            fi

            echo "rsync $OPTIONS $EXCEPTIONS $SOURCE $HOST:$TARGET/"
            rsync $OPTIONS $EXCEPTIONS $SOURCE $HOST:$TARGET/
        fi
    else
        #local sync

        if [[ $CLEAN = 1 ]] ; then
            if [[ $RECURSIVE = 1 ]] ; then
                rm -rf $TARGET/*
            else
                rm -f $TARGET/*
            fi
        fi

        if [[ ! $NO_SYNC ]] ; then
            #--existing is ignored
            OPTIONS=''
            if [[ $RECURSIVE = 1 ]] ; then
                OPTIONS="$OPTIONS -r"
            fi
            cp $OPTIONS $SOURCE $TARGET/
        fi
    fi
}


pushd $DIR/../../ #freeipa/install
    TARGET_BASE='/usr/share/ipa'
    LOGIN=$HOST

    if [[ $FREEIPA ]] ; then
        SOURCE=ui/src/freeipa/*
        if [[ $COMPILED ]] ; then
            SOURCE=ui/build/freeipa/*
        fi
        TARGET=$TARGET_BASE/ui/js/freeipa
        RECURSIVE=1
        EXCEPTIONS="--exclude /Makefile*"
        sync-files
    fi

    if [[ $LIBS ]] ; then
        SOURCE=ui/src/libs/*
        TARGET=$TARGET_BASE/ui/js/libs
        RECURSIVE=1
        EXCEPTIONS="--exclude /Makefile* --exclude .in"
        sync-files
    fi

    if [[ $DOJO ]] ; then
        SOURCE=ui/src/dojo/*
        if [[ $COMPILED ]] ; then
            SOURCE=ui/build/dojo/*
        fi
        TARGET=$TARGET_BASE/ui/js/dojo
        RECURSIVE=1
        EXCEPTIONS="--exclude tests --exclude .git"
        sync-files
    fi

    if [[ $MISC ]] ; then
        SOURCE=ui/*
        TARGET=$TARGET_BASE/ui
        RECURSIVE=0
        EXCEPTIONS="--exclude /Makefile*"
        sync-files
    fi

    if [[ $IMAGES ]] ; then
        SOURCE=ui/images/*
        TARGET=$TARGET_BASE/ui/images
        RECURSIVE=1
        EXCEPTIONS="--exclude /Makefile*"
        sync-files

        SOURCE=ui/img/*
        TARGET=$TARGET_BASE/ui/img
        RECURSIVE=1
        EXCEPTIONS="--exclude /Makefile*"
        sync-files
    fi

    if [[ $CSS ]] ; then
        SOURCE=ui/*.css
        TARGET=$TARGET_BASE/ui
        RECURSIVE=0
        EXCEPTIONS="--exclude /Makefile*"
        sync-files

        SOURCE=ui/css/*.css
        TARGET=$TARGET_BASE/ui/css
        RECURSIVE=0
        EXCEPTIONS="--exclude /Makefile*"
        sync-files
    fi

    if [[ $DATA ]] ; then
        SOURCE=ui/test/data/*
        TARGET=$TARGET_BASE/ui/test/data
        RECURSIVE=1
        sync-files
    fi

    if [[ $MIGRATION ]] ; then
        SOURCE=migration/*
        TARGET=$TARGET_BASE/migration
        RECURSIVE=1
        EXCEPTIONS="--exclude /Makefile*"
        sync-files
    fi

    if [[ $CONFIG ]] ; then
        SOURCE=html/*
        TARGET=/etc/ipa/html
        RECURSIVE=1
        EXCEPTIONS="--exclude /Makefile*"
        sync-files
    fi
popd

if [[ $STRINGS ]] ; then
    SOURCE=ipaserver/plugins/internal.py
    TARGET=/usr/lib/python2.7/site-packages/ipaserver/plugins
    RECURSIVE=0
    CLEAN=0 # don't clean entire folder
    pushd $DIR/../../../
        sync-files
    popd
fi

if [[ $RESTART ]] ; then
    if [[ ! $HOST ]] ; then
        echo "Restarting httpd"
        sudo systemctl restart httpd.service
    else
        echo "Restarting httpd: $HOST"
        ssh $HOST "systemctl restart httpd.service"
    fi
fi
