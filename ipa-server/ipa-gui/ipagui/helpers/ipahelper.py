# Copyright (C) 2007  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 only
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

import re
import logging
import turbogears
import kid
from turbokid import kidsupport
from pkg_resources import resource_filename

def javascript_string_escape(input):
    """Escapes the ' " and \ characters in a string so
       it can be embedded inside a dynamically generated string."""

    return re.sub(r'[\'\"\\]',
            lambda match: "\\%s" % match.group(),
            input)

def setup_mv_fields(field, fieldname):
    """Given a field (must be a list) and field name, convert that
       field into a list of dictionaries of the form:
          [ { fieldname : v1}, { fieldname : v2 }, .. ]

   This is how we pre-fill values for multi-valued fields.
    """
    mvlist = []
    if field:
        for v in field:
            if v:
                mvlist.append({ fieldname : v } )
    if len(mvlist) == 0:
        # We need to return an empty value so something can be
        # displayed on the edit page. Otherwise only an Add link
        # will show, not an empty field.
        mvlist.append({ fieldname : '' } )
    return mvlist

def fix_incoming_fields(fields, fieldname, multifieldname):
    """This is called by the update() function. It takes the incoming
       list of dictionaries and converts it into back into the original
       field, then removes the multiple field.
    """
    fields[fieldname] = []
    try:
        for i in range(len(fields[multifieldname])):
            if fields[multifieldname][i][fieldname] is not None and len(fields[multifieldname][i][fieldname]) > 0:
                fields[fieldname].append(fields[multifieldname][i][fieldname])
        del(fields[multifieldname])
    except Exception, e:
        logging.warn("fix_incoming_fields error: " + str(e))

    return fields

def load_template(classname, encoding=None):
    """
    Loads the given template. This only handles .kid files.
    Returns a tuple (compiled_tmpl, None) to emulate
    turbogears.meta.load_kid_template() which ends up not properly handling
    encoding.
    """
    if not encoding:
        encoding = turbogears.config.get('kid.encoding', kidsupport.KidSupport.assume_encoding)
    divider = classname.rfind(".")
    package, basename = classname[:divider], classname[divider+1:]
    file_path = resource_filename(package, basename + ".kid")

    tclass = kid.load_template(
        file_path,
        name = classname,
        ).Template
    tclass.serializer = kid.HTMLSerializer(encoding=encoding)
    tclass.assume_encoding=encoding

    return (tclass, None)
