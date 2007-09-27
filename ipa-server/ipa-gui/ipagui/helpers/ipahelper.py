import re

def javascript_string_escape(input):
    """Escapes the ' " and \ characters in a string so
       it can be embedded inside a dynamically generated string."""

    return re.sub(r'[\'\"\\]',
            lambda match: "\\%s" % match.group(),
            input)
