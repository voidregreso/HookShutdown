// header.h : include file for standard system include files,
// or project specific include files
//

#pragma once

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files

#include <Windows.h>
#include <Psapi.h>
#include <Tlhelp32.h>

#include <Shlwapi.h>
#include <stdlib.h>
#include <tchar.h>
#include <sddl.h>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma warning(disable:4996)
