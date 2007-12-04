import re

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
    for i in range(len(fields[multifieldname])):
        fields[fieldname].append(fields[multifieldname][i][fieldname])
    del(fields[multifieldname])

    return fields
