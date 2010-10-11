/* Authors: Rob Crittenden <rcritten@redhat.com>
 *
 * Copyright (C) 2009  Red Hat
 * see file 'COPYING' for use and warranty information
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; version 2 only
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

/* Simple and INI-style file reader.
 *
 * usage is:
 * char * data = read_config_file("/path/to/something.conf")
 * char * entry = get_config_entry(data, "section", "mykey")
 *
 * caller must free data and entry.
 */

#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include <errno.h>
#include "config.h"
#include <libintl.h>
#define _(STRING) gettext(STRING)

char *
read_config_file(const char *filename)
{
    int fd;
    struct stat st;
    char *data, *dest;
    size_t left;

    fd = open(filename, O_RDONLY);
    if (fd == -1) {
        fprintf(stderr, _("cannot open configuration file %s\n"), filename);
        return NULL;
    }

    /* stat() the file so we know the size and can pre-allocate the right
     * amount of memory. */
    if (fstat(fd, &st) == -1) {
        fprintf(stderr, _("cannot stat() configuration file %s\n"), filename);
        return NULL;
    }
    left = st.st_size;
    data = malloc(st.st_size + 1);
    dest = data;
    while (left != 0) {
        ssize_t res;

        res = read(fd, dest, left);
        if (res == 0)
            break;
        if (res < 0) {
            fprintf(stderr, _("read error\n"));
            close(fd);
            free(dest);
            return NULL;
        }
        dest += res;
        left -= res;
    }
    close(fd);
    *dest = 0;
    return data;
}

char *
get_config_entry(char * in_data, const char *section, const char *key)
{
    char *ptr, *p, *tmp;
    char *line;
    int in_section = 0;
    char * data;

    if (NULL == in_data)
        return NULL;
    else
        data = strdup(in_data);

    for (line = strtok_r(data, "\n", &ptr); line != NULL;
         line = strtok_r(NULL, "\n", &ptr)) {
        /* Skip initial whitespace. */
        while (isspace((unsigned char)*line) && (*line != '\0'))
            line++;

        /* If it's a comment, bail. */
        if (*line == '#') {
            continue;
        }

        /* If it's the beginning of a section, process it and clear the key
         * and value values. */
        if (*line == '[') {
            line++;
            p = strchr(line, ']');
            if (p) {
                tmp = strndup(line, p - line);
                if (in_section) {
                    /* We exited the matching section without a match */
                    free(data);
                    return NULL;
                }
                if (strcmp(section, tmp) == 0) {
                    free(tmp);
                    in_section = 1;
                    continue;
                }
            }
        } /* [ */

        p = strchr(line, '=');
        if (p != NULL && in_section) {
            /* Trim any trailing whitespace off the key name. */
            while (p != line && isspace((unsigned char)p[-1]))
                p--;

            /* Save the key. */
            tmp = strndup(line, p - line);
            if (strcmp(key, tmp) != 0) {
                free(tmp);
            } else {
                free(tmp);

                /* Skip over any whitespace after the equal sign. */
                line = strchr(line, '=');
                line++;
                while (isspace((unsigned char)*line) && (*line != '\0'))
                    line++;

                /* Trim off any trailing whitespace. */
                p = strchr(line, '\0');
                while (p != line && isspace((unsigned char)p[-1]))
                    p--;

                /* Save the value. */
                tmp = strndup(line, p - line);

                free(data);
                return tmp;
            }
        }
    }
    free(data);
    return NULL;
}

int init_gettext(void)
{
    char *c;

    c = setlocale(LC_ALL, "");
    if (!c) {
        return EIO;
    }

    errno = 0;
    c = bindtextdomain(PACKAGE, LOCALEDIR);
    if (c == NULL) {
        return errno;
    }

    errno = 0;
    c = textdomain(PACKAGE);
    if (c == NULL) {
        return errno;
    }

    return 0;
}
