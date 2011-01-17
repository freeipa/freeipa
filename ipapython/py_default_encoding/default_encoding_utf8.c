/*
 * Authors:
 *   John Dennis <jdennis@redhat.com>
 *
 * Copyright (C) 2009  Red Hat
 * see file 'COPYING' for use and warranty information
 *
 * This program is free software you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <Python.h>

PyDoc_STRVAR(setdefaultencoding_doc,
"setdefaultencoding(encoding='utf-8')\n\
\n\
Set the current default string encoding used by the Unicode implementation.\n\
Defaults to utf-8."
);

static PyObject *
setdefaultencoding(PyObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"utf-8", NULL};
    char *encoding;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "s:setdefaultencoding", kwlist, &encoding))
        return NULL;

    if (PyUnicode_SetDefaultEncoding(encoding))
        return NULL;

    Py_RETURN_NONE;
}

static PyMethodDef methods[] = {
    {"setdefaultencoding", (PyCFunction)setdefaultencoding, METH_VARARGS|METH_KEYWORDS, setdefaultencoding_doc},
	{NULL,		NULL}		/* sentinel */
};


PyMODINIT_FUNC
initdefault_encoding_utf8(void) 
{
    PyUnicode_SetDefaultEncoding("utf-8");
    Py_InitModule3("default_encoding_utf8", methods, "Forces the default encoding to utf-8");
}
