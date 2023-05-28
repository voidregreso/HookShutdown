// dllmain.cpp : Defines the entry point for the DLL application.
#include "framework.h"

LPVOID _copyNtShutdownSystem = NULL;
LPVOID _ExitWindowsExAddTwoByte = NULL;
HMODULE _gDll = NULL;

/*__declspec(naked)*/ void MyExitWindowsEx() {
	/*__asm
	{
	    call testMsgBox;
	    jmp _ExitWindowsExAddTwoByte
	}*/
}

typedef BOOL(WINAPI* FuncExitWindowsEx)(_In_ UINT uFlags, _In_ DWORD dwReason);
FuncExitWindowsEx _OldExitWindowsEx = NULL;


HANDLE gloCreateProcessHandle = NULL;

BOOL WINAPI IATHookedFun(_In_ UINT uFlags, _In_ DWORD dwReason) {
	BOOL bRet = FALSE;
	static BOOL bNeedWarning = FALSE;

	if (bNeedWarning) {
		MessageBox(NULL, _TEXT("Se ha activado la interceptación de mensajes de apagado."), _TEXT("Tips"), MB_ICONINFORMATION | MB_OK);
	}

	bRet = _OldExitWindowsEx(uFlags, dwReason);
	if (bRet) {
		bNeedWarning = TRUE;
	}
	return bRet;
}

// Inline hook adecuado para plataformas superiores de Win7
void hook_ExitWindowsEx() {
	HMODULE hUser32 = GetModuleHandle(L"user32.dll");
	char* pOldExitWindowsEx = reinterpret_cast<char*>(GetProcAddress(hUser32, "ExitWindowsEx"));

	// 5 bytes de NOP
	const int iLengthCopy = 7;
	if (pOldExitWindowsEx != nullptr) {
		_copyNtShutdownSystem = VirtualAlloc(0, 1024, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		char* pNewAddr = reinterpret_cast<char*>(_copyNtShutdownSystem);

		char* pnop = pOldExitWindowsEx - 5;
		char aa = *pOldExitWindowsEx;
		char bb = *(pOldExitWindowsEx + 1);

		if (static_cast<char>(0x8b) == *pOldExitWindowsEx && static_cast<char>(0xff) == *(pOldExitWindowsEx + 1)) {
			DWORD oldshutdownProtect = 0;
			if (VirtualProtect(pOldExitWindowsEx - 5, iLengthCopy, PAGE_EXECUTE_READWRITE, &oldshutdownProtect)) {
				*pOldExitWindowsEx = static_cast<char>(0xeB); // jmp short
				*reinterpret_cast<USHORT*>(pOldExitWindowsEx + 1) = static_cast<USHORT>(-0x7); // addr
				*pnop = static_cast<char>(0xe9); // jmp
				*reinterpret_cast<int*>(pnop + 1) = reinterpret_cast<int>(MyExitWindowsEx) - reinterpret_cast<int>(pnop + 5); // addr
				_ExitWindowsExAddTwoByte = pOldExitWindowsEx + 2;
				VirtualProtect(pOldExitWindowsEx - 5, iLengthCopy, oldshutdownProtect, nullptr);
			}
		}
	}
	return;
}

BYTE* getNtHdrs(BYTE* pe_buffer) {
	if (pe_buffer == NULL) return NULL;

	// Convierte el búfer PE en una estructura de encabezado DOS
	IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)pe_buffer;

	// Verifica la firma del encabezado DOS para asegurarse de que es un archivo PE válido
	if (idh->e_magic != IMAGE_DOS_SIGNATURE) {
		return NULL;
	}

	// Definición del desplazamiento máximo permitido para el encabezado PE
	const LONG kMaxOffset = 1024;

	// Obtiene el desplazamiento al encabezado PE desde el encabezado DOS
	LONG pe_offset = idh->e_lfanew;

	// Verifica si el desplazamiento al encabezado PE está dentro del rango permitido
	if (pe_offset > kMaxOffset) return NULL;

	// Convierte el búfer PE desplazado al encabezado PE
	IMAGE_NT_HEADERS32* inh = (IMAGE_NT_HEADERS32*)((BYTE*)pe_buffer + pe_offset);
	if (inh->Signature != IMAGE_NT_SIGNATURE) return NULL;
	return (BYTE*)inh;
}

IMAGE_DATA_DIRECTORY* getPeDir(PVOID pe_buffer, size_t dir_id) {
	if (dir_id >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES) return NULL;

	// Obtiene el encabezado NT desde el búfer PE
	BYTE* nt_headers = getNtHdrs((BYTE*)pe_buffer);

	// Verifica si se pudo obtener el encabezado NT
	if (nt_headers == NULL) return NULL;

	// Puntero al directorio PE
	IMAGE_DATA_DIRECTORY* peDir = NULL;

	// Convierte el encabezado NT a la estructura adecuada
	IMAGE_NT_HEADERS* nt_header = (IMAGE_NT_HEADERS*)nt_headers;

	// Obtiene el directorio PE con el ID especificado
	peDir = &(nt_header->OptionalHeader.DataDirectory[dir_id]);
	if (peDir->VirtualAddress == NULL) {
		return NULL;
	}
	return peDir;
}

bool FixDelayIATHook(PVOID modulePtr) {
	IMAGE_DATA_DIRECTORY* importsDir = getPeDir(modulePtr, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT);
	if (importsDir == nullptr)
		return false;

	size_t maxSize = importsDir->Size;
	size_t impAddr = importsDir->VirtualAddress;

	// Obtener la dirección de la función ExitWindowsEx de la librería User32.dll
	size_t addrExitWindowsEx = reinterpret_cast<size_t>(GetProcAddress(GetModuleHandle(L"User32"), "ExitWindowsEx"));

	// Iterar a través de los descriptores de importación retardada
	for (size_t parsedSize = 0; parsedSize < maxSize; parsedSize += sizeof(IMAGE_DELAYLOAD_DESCRIPTOR)) {
		IMAGE_DELAYLOAD_DESCRIPTOR* lib_desc = reinterpret_cast<IMAGE_DELAYLOAD_DESCRIPTOR*>
			(impAddr + parsedSize + reinterpret_cast<ULONG_PTR>(modulePtr));

		// Comprobar si el descriptor de importación retardada es nulo
		if (lib_desc->ImportAddressTableRVA == 0 && lib_desc->ImportNameTableRVA == 0)
			break;

		// Obtener el nombre de la librería
		LPSTR lib_name = reinterpret_cast<LPSTR>(reinterpret_cast<ULONGLONG>(modulePtr) + lib_desc->DllNameRVA);

		size_t call_via = lib_desc->ImportAddressTableRVA;
		size_t thunk_addr = lib_desc->ImportNameTableRVA;

		// Si el desplazamiento de la tabla de nombres es 0, usar la tabla de direcciones
		if (thunk_addr == 0)
			thunk_addr = lib_desc->ImportAddressTableRVA;

		// Iterar a través de los campos de la tabla de importación
		for (size_t offsetField = 0, offsetThunk = 0;; offsetField += sizeof(IMAGE_THUNK_DATA), offsetThunk += sizeof(IMAGE_THUNK_DATA)) {
			IMAGE_THUNK_DATA* fieldThunk = reinterpret_cast<IMAGE_THUNK_DATA*>(reinterpret_cast<size_t>(modulePtr) + offsetField + call_via);
			IMAGE_THUNK_DATA* orginThunk = reinterpret_cast<IMAGE_THUNK_DATA*>(reinterpret_cast<size_t>(modulePtr) + offsetThunk + thunk_addr);

			// Comprobar si ambos campos están vacíos para salir del bucle
			if (fieldThunk->u1.Function == 0 && orginThunk->u1.Function == 0)
				break;

			// Comprobar si se utiliza un ordinal para obtener la dirección de la función
			if (orginThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32 || orginThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
				// La dirección de la función también se puede obtener obteniendo los dos bytes inferiores del número de serie
				size_t addrOld = reinterpret_cast<size_t>(GetProcAddress(LoadLibraryA(lib_name),
					reinterpret_cast<char*>(orginThunk->u1.Ordinal & 0xFFFF)));
				continue;
			}
			else { // Utilizar el nombre de la función para obtener la dirección de la función
				PIMAGE_IMPORT_BY_NAME by_name = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
					reinterpret_cast<size_t>(modulePtr) + orginThunk->u1.AddressOfData);
				LPSTR func_name = reinterpret_cast<LPSTR>(by_name->Name);
				size_t addrOld = reinterpret_cast<size_t>(GetProcAddress(LoadLibraryA(lib_name), func_name));

				// Si la función es "ExitWindowsEx", realizar el hook y restaurar la protección de memoria
				if (_stricmp(func_name, "ExitWindowsEx") == 0) {
					DWORD dOldProtect = 0;
					size_t* pFuncAddr = reinterpret_cast<size_t*>(&fieldThunk->u1.Function);
					if (VirtualProtect(pFuncAddr, sizeof(size_t), PAGE_EXECUTE_READWRITE, &dOldProtect)) {
						fieldThunk->u1.Function = reinterpret_cast<size_t>(IATHookedFun);
						VirtualProtect(pFuncAddr, sizeof(size_t), dOldProtect, &dOldProtect);
						_OldExitWindowsEx = reinterpret_cast<FuncExitWindowsEx>(addrExitWindowsEx);
						return true;
					}
					break;
				}
			}
		}
	}

	return true;
}



bool FixIATHook(PVOID modulePtr) {
	// Obtener la dirección de la tabla de importación del módulo
	IMAGE_DATA_DIRECTORY* importsDir = getPeDir(modulePtr, IMAGE_DIRECTORY_ENTRY_IMPORT);
	if (importsDir == NULL)
		return false;

	// Obtener el tamaño y la dirección virtual de la tabla de importación
	size_t maxSize = importsDir->Size;
	size_t impAddr = importsDir->VirtualAddress;

	// Obtener la dirección de la función "ExitWindowsEx" de la biblioteca User32
	size_t addrExitWindowsEx = (size_t)GetProcAddress(GetModuleHandle(L"User32"), "ExitWindowsEx");

	// Iterar sobre las descripciones de importación en la tabla de importación
	for (size_t parsedSize = 0; parsedSize < maxSize; parsedSize += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
		// Obtener la descripción de importación actual
		IMAGE_IMPORT_DESCRIPTOR* lib_desc = (IMAGE_IMPORT_DESCRIPTOR*)(impAddr + parsedSize + (ULONG_PTR)modulePtr);
		if (lib_desc->OriginalFirstThunk == NULL && lib_desc->FirstThunk == NULL)
			break;

		// Obtener el nombre de la biblioteca importada
		LPSTR lib_name = (LPSTR)((size_t)modulePtr + lib_desc->Name);

		// Obtener las direcciones de llamada y los punteros de función para los thunks
		size_t call_via = lib_desc->FirstThunk;
		size_t thunk_addr = lib_desc->OriginalFirstThunk;
		if (thunk_addr == NULL)
			thunk_addr = lib_desc->FirstThunk;

		// Iterar sobre los campos de thunk y thunk originales
		for (size_t offsetField = 0, offsetThunk = 0;; offsetField += sizeof(IMAGE_THUNK_DATA), offsetThunk += sizeof(IMAGE_THUNK_DATA)) {
			// Obtener los thunks actuales
			IMAGE_THUNK_DATA* fieldThunk = (IMAGE_THUNK_DATA*)(size_t(modulePtr) + offsetField + call_via);
			IMAGE_THUNK_DATA* orginThunk = (IMAGE_THUNK_DATA*)(size_t(modulePtr) + offsetThunk + thunk_addr);

			// Verificar si se ha llegado al final de los thunks
			if (fieldThunk->u1.Function == 0 && orginThunk->u1.Function == 0)
				break;

			PIMAGE_IMPORT_BY_NAME by_name = nullptr;
			LPSTR func_name = nullptr;
			size_t addrOld = NULL;

			// Verificar si se está importando una función por ordinal o por nombre
			if (orginThunk->u1.Ordinal & (IMAGE_ORDINAL_FLAG32 | IMAGE_ORDINAL_FLAG64)) {
				// Importación por ordinal
				addrOld = (size_t)GetProcAddress(LoadLibraryA(lib_name), (char*)(orginThunk->u1.Ordinal & 0xFFFF));
				continue;
			}
			else {
				// Importación por nombre
				by_name = (PIMAGE_IMPORT_BY_NAME)(size_t(modulePtr) + orginThunk->u1.AddressOfData);
				func_name = (LPSTR)by_name->Name;
				addrOld = (size_t)GetProcAddress(LoadLibraryA(lib_name), func_name);
			}

			// HOOK
			if (strcmpi(func_name, "ExitWindowsEx") == 0) {
				// Cambiar la función importada por una función hook
				DWORD dOldProtect = 0;
				size_t* pFuncAddr = (size_t*)&fieldThunk->u1.Function;
				if (VirtualProtect(pFuncAddr, sizeof(size_t), PAGE_EXECUTE_READWRITE, &dOldProtect)) {
					fieldThunk->u1.Function = (size_t)IATHookedFun;
					VirtualProtect(pFuncAddr, sizeof(size_t), dOldProtect, &dOldProtect);
					_OldExitWindowsEx = (FuncExitWindowsEx)addrExitWindowsEx;
					return true;
				}
			}
		}
	}

	return true;
}


//CreateIntegritySidProcess(L"S-1-16-4096");// proceso de baja autoridad
//CreateIntegritySidProcess(L"S-1-16-8192");// proceso de media autoridad
//CreateIntegritySidProcess(L"S-1-16-12288");// proceso de alta autoridad
//CreateIntegritySidProcess(L"S-1-16-16384");// proceso de más alta autoridad, i.e. system
HANDLE getMediumProcessToken() {
	HANDLE mediumToken = NULL; // almacenar el token de proceso de integridad media
	HANDLE hToken = NULL;
	HANDLE hNewToken = NULL; // almacenar el nuevo token duplicado
	PSID pIntegritySid = NULL;
	TOKEN_MANDATORY_LABEL TIL = { 0 }; // almacenar la etiqueta de integridad del token

	// Abre el token del proceso actual con los permisos MAXIMUM_ALLOWED
	// y almacena el token en la variable hToken
	if (OpenProcessToken(GetCurrentProcess(), MAXIMUM_ALLOWED, &hToken)) {

		// Duplica el token del proceso actual con los permisos MAXIMUM_ALLOWED
		// y almacena el nuevo token duplicado en la variable hNewToken
		if (DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hNewToken)) {

			// Convierte una cadena SID en un SID real y lo almacena en la variable pIntegritySid
			if (ConvertStringSidToSid(L"S-1-16-8192", &pIntegritySid)) {

				// Establece los atributos y el SID de integridad en la estructura TOKEN_MANDATORY_LABEL
				TIL.Label.Attributes = SE_GROUP_INTEGRITY;
				TIL.Label.Sid = pIntegritySid;

				// Establece la información del token para cambiar el nivel de integridad del proceso
				// utilizando el nuevo token y la estructura TOKEN_MANDATORY_LABEL
				if (SetTokenInformation(hNewToken, TokenIntegrityLevel, &TIL,
					sizeof(TOKEN_MANDATORY_LABEL) + GetLengthSid(pIntegritySid))) {
					// Asigna el nuevo token a la variable mediumToken si la operación tiene éxito
					mediumToken = hNewToken;
				}
			}
		}
	}

	if (pIntegritySid) {
		LocalFree(pIntegritySid);
	}
	if (hToken) {
		CloseHandle(hToken);
	}
	return mediumToken;
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     ) {
	switch (ul_reason_for_call) {
	case DLL_PROCESS_ATTACH: {
		_gDll = hModule;
		gloCreateProcessHandle = getMediumProcessToken();
		HMODULE exeModule = GetModuleHandle(NULL);
		FixIATHook(exeModule);
		FixDelayIATHook(exeModule);
		break;
	}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH: {
		if (gloCreateProcessHandle != NULL) {
			CloseHandle(gloCreateProcessHandle);
			gloCreateProcessHandle = NULL;
		}
	}
	}
	return TRUE;
}

