/*
 * Copyright (C) 2014  FreeIPA Contributors see COPYING for license
 *
 * This code is based on PKCS#11 code from SoftHSM project:
 * https://github.com/opendnssec/SoftHSMv2/
 * Original license follows:
 */
/*
 * Copyright (c) 2010 .SE (The Internet Infrastructure Foundation)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*****************************************************************************
 library.c

 Support function for handling PKCS#11 libraries
 *****************************************************************************/

#include "library.h"

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

// Load the PKCS#11 library
CK_C_GetFunctionList loadLibrary(const char* module, void** moduleHandle)
{
	CK_C_GetFunctionList pGetFunctionList = NULL;

	void* pDynLib = NULL;

	// Load PKCS #11 library
	if (module)
	{
		pDynLib = dlopen(module, RTLD_NOW | RTLD_LOCAL);
	} else {
		return NULL;
	}

	if (pDynLib == NULL)
	{
		// Failed to load the PKCS #11 library
		return NULL;
	}

	// Retrieve the entry point for C_GetFunctionList
	pGetFunctionList = (CK_C_GetFunctionList) dlsym(pDynLib, "C_GetFunctionList");
	if (pGetFunctionList == NULL)
	{
		dlclose(pDynLib);
		return NULL;
	}

	// Store the handle so we can dlclose it later
	*moduleHandle = pDynLib;

	return pGetFunctionList;
}

void unloadLibrary(void* moduleHandle)
{
	if (moduleHandle)
	{
		dlclose(moduleHandle);
	}
}
