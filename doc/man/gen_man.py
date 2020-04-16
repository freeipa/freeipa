#!/usr/bin/python3
"""Convert man pages to RST
"""
import os
import fnmatch
import re
import subprocess

HERE = os.path.abspath(os.path.dirname(__file__))
ROOT = os.path.abspath(os.path.join(HERE, os.pardir, os.pardir))
CLIENT_MAN = os.path.join(ROOT, "client", "man")
TOOLS_MAN = os.path.join(ROOT, "install", "tools", "man")


def get_man_pages():
    for basedir in CLIENT_MAN, TOOLS_MAN:
        for filename in os.listdir(basedir):
            if fnmatch.fnmatch(filename, "*.[1-9]"):
                name, sec = filename.rsplit(".", 1)
                sec = int(sec)
                yield os.path.join(basedir, filename), name, sec


def convert(filename, name, sec):
    out = subprocess.check_output(
        ["pandoc", "-f", "man", "-t", "rst", filename]
    )
    lines = out.decode("utf-8").split("\n")
    title = None
    deprecated = False
    uninstall = False
    codeblock = False
    for line in lines:
        if "DEPRECATED OPTIONS" in line:
            deprecated = True
        if "UNINSTALL OPTIONS" in line:
            uninstall = True
        if line == "::":
            codeblock = True
        if line and line[0].isalnum():
            codeblock = False
        if title is None:
            if line.startswith(name):
                title = line.split(" - ", 1)[1]
                title_line = f"{name}({sec}) -- {title}"
                yield ".. AUTO-GENERATED FILE, DO NOT EDIT!"
                yield ""
                yield "=" * len(title_line)
                yield title_line
                yield "=" * len(title_line)
            else:
                continue
        elif line.startswith("**-") and line.endswith("*"):
            # option line but not synopsis
            # option lines starts with "**-" and end with "**" or "*"
            line = line.replace("**", "")
            line = re.sub(r"\\ =\\ \*(.*?)\*", r"=<\1>", line)
            line = re.sub(r"\*(.*?)\*", r"<\1>", line)
            if deprecated:
                # hack for duplicated deprecated options
                yield "``" + line + "``"
            elif uninstall and "-U" in line:
                # hack for duplicate -U option in uninstall section
                yield "``" + line + "``"
            else:
                yield f".. option:: {line}"
                yield ""
        else:
            if not codeblock:
                line = re.sub(r"(\*\*--[\w][\w\-=]+?\*\*)", r"``\1``", line)
            yield line


def main():
    for filename, name, sec in get_man_pages():
        rst = convert(filename, name, sec)
        dest = os.path.join(HERE, f"{name}.{sec}.rst")
        with open(dest, "w") as f:
            f.write("\n".join(rst))


if __name__ == "__main__":
    main()
