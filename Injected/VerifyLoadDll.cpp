// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <stdio.h>
#include <psapi.h>
#include <iostream>


int hook(PCSTR func_to_hook, PCSTR DLL_to_hook, UINT_PTR new_func_address);
HMODULE WINAPI LoadLibraryAndCheckDll(LPCSTR lpLibFileName);
bool RelocateImageBase(LPVOID newBase, ULONG_PTR delta);
bool ResolveImports(LPVOID newBase);
LPVOID ConvertDatafileDllToExecutable(HMODULE hDataFile);
BOOL GetModuleInformationManual(HMODULE hModule, LPMODULEINFO lpmodinfo, DWORD cb);
FARPROC ManualGetProcAddress(HMODULE hModule, LPCSTR lpProcName);
HMODULE LoadDllManually(HMODULE hModule);


// Original LoadLibraryA function pointer
typedef HMODULE(WINAPI* pLoadLibraryA)(LPCSTR);
pLoadLibraryA original_LoadLibraryA = NULL;

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		PCSTR func_to_hook = "LoadLibraryA";
		PCSTR DLL_to_hook = "KERNEL32.dll";
		UINT_PTR new_func_address = (UINT_PTR)&LoadLibraryAndCheckDll;
		hook(func_to_hook, DLL_to_hook, new_func_address);
	}
	break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

HMODULE WINAPI LoadLibraryAndCheckDll(LPCSTR lpLibFileName)
{
	printf("LoadLibraryAndCheckDll called with: %s\n", lpLibFileName);
	std::cin.get();

	HMODULE hDataFile = LoadLibraryExA(lpLibFileName, NULL, DONT_RESOLVE_DLL_REFERENCES);

	if (hDataFile)
	{
		// if verify
		LPVOID executableDll = LoadDllManually(hDataFile);

		return (HMODULE)executableDll;
	}

	return NULL;
}

int hook(PCSTR func_to_hook, PCSTR DLL_to_hook, UINT_PTR new_func_address)
{
	PIMAGE_DOS_HEADER dosHeader;
	PIMAGE_NT_HEADERS NTHeader;
	PIMAGE_OPTIONAL_HEADER optionalHeader;
	IMAGE_DATA_DIRECTORY importDirectory;
	UINT_PTR descriptorStartRVA;
	PIMAGE_IMPORT_DESCRIPTOR importDescriptor;
	int index;

	// Get base address of currently running .exe
	UINT_PTR baseAddress = (UINT_PTR)GetModuleHandle(NULL);

	// Get the import directory address
	dosHeader = (PIMAGE_DOS_HEADER)(baseAddress);
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return 0;
	}

	// Locate NT header
	NTHeader = (PIMAGE_NT_HEADERS)(baseAddress + dosHeader->e_lfanew);
	if (NTHeader->Signature != IMAGE_NT_SIGNATURE) {
		return 0;
	}

	// Locate optional header
	optionalHeader = &NTHeader->OptionalHeader;

#ifdef _WIN64
	if (optionalHeader->Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		return 0;
	}
#else
	if (optionalHeader->Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		return 0;
	}
#endif

	importDirectory = optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	descriptorStartRVA = importDirectory.VirtualAddress;
	importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(baseAddress + descriptorStartRVA);

	index = 0;
	char* DLL_name;

	// Look for the DLL which includes the function for hooking
	while (importDescriptor->Characteristics != 0) {
		DLL_name = (char*)(baseAddress + importDescriptor->Name);
		printf("DLL name: %s\n", DLL_name);
		if (!strcmp(DLL_to_hook, DLL_name))
			break;
		importDescriptor++;
	}

	// exit if the DLL is not found in import directory
	if (importDescriptor->Characteristics == 0) {
		printf("DLL was not found");
		return 0;
	}

	// Search for requested function in the DLL
	PIMAGE_THUNK_DATA thunkILT; // Import Lookup Table - names
	PIMAGE_THUNK_DATA thunkIAT; // Import Address Table - addresses
	PIMAGE_IMPORT_BY_NAME nameData;

	thunkILT = (PIMAGE_THUNK_DATA)(baseAddress + importDescriptor->OriginalFirstThunk);
	thunkIAT = (PIMAGE_THUNK_DATA)(baseAddress + importDescriptor->FirstThunk);

	if (thunkIAT == NULL || thunkILT == NULL) {
		return 0;
	}

	while (thunkILT->u1.AddressOfData != 0 && !(thunkILT->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
		nameData = (PIMAGE_IMPORT_BY_NAME)(baseAddress + thunkILT->u1.AddressOfData);
		if (!strcmp(func_to_hook, (char*)nameData->Name))
			break;
		thunkIAT++;
		thunkILT++;
	}

	// Hook IAT: Write over function pointer
	DWORD dwOld = NULL;
	original_LoadLibraryA = (pLoadLibraryA)thunkIAT->u1.Function;
	VirtualProtect((LPVOID) & (thunkIAT->u1.Function), sizeof(UINT_PTR), PAGE_READWRITE, &dwOld);
	thunkIAT->u1.Function = new_func_address;
	VirtualProtect((LPVOID) & (thunkIAT->u1.Function), sizeof(UINT_PTR), dwOld, NULL);

	return 1;
}

HMODULE LoadDllManually(HMODULE hModule)
{
	printf("shit0\n");
	// Get the DOS and NT headers
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((LPBYTE)hModule + dosHeader->e_lfanew);
	printf("shit1\n");


	// Calculate the delta between the preferred load address and the actual load address
	ULONG_PTR delta = (ULONG_PTR)hModule - ntHeader->OptionalHeader.ImageBase;
	printf("shit2\n");

	// Perform base relocation if necessary
	if (delta != 0) 
	{
		if (!RelocateImageBase(hModule, delta)) 
		{
			FreeLibrary(hModule);
			return NULL;
		}
	}

	// Resolve imports
	if (!ResolveImports(hModule)) 
	{
		FreeLibrary(hModule);
		return NULL;
	}

	printf("hello1\n");

	// Get the address of DllMain
	LPVOID dllMainAddress = (LPVOID)((LPBYTE)hModule + ntHeader->OptionalHeader.AddressOfEntryPoint);

	//// Change memory protection to allow execution
	//DWORD oldProtect;
	//if (!VirtualProtect(dllMainAddress, ntHeader->OptionalHeader.SizeOfCode, PAGE_EXECUTE_READ, &oldProtect)) {
	//	printf("Failed to change memory protection. Error: %d\n", GetLastError());
	//	FreeLibrary(hModule);
	//	return NULL;
	//}
	//
	//printf("%x\n", oldProtect);

	// Call DllMain with DLL_PROCESS_ATTACH
	typedef BOOL(WINAPI* DllMain_t)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
	DllMain_t dllMain = (DllMain_t)dllMainAddress;

	printf("%p\n", dllMain);

	if (dllMain != NULL) {
		printf("hello3\n");
		BOOL result = FALSE;
		__try {
			result = dllMain((HINSTANCE)hModule, DLL_PROCESS_ATTACH, NULL);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			printf("Exception in DllMain: 0x%x\n", GetExceptionCode());
			FreeLibrary(hModule);
			return NULL;
		}
		printf("hello4\n");
		if (!result) {
			FreeLibrary(hModule);
			return NULL;
		}
	}

	//// Restore the original memory protection
	//DWORD temp;
	//VirtualProtect(dllMainAddress, ntHeader->OptionalHeader.SizeOfCode, oldProtect, &temp);

	return hModule;
}

bool RelocateImageBase(LPVOID newBase, ULONG_PTR delta)
{
	printf("bye0\n");

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)newBase;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((LPBYTE)newBase + dosHeader->e_lfanew);

	printf("bye1\n");

	// Check if there's a relocation directory
	if (ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress == 0)
	{
		// No relocations needed
		return true;
	}
	printf("bye2\n");

	PIMAGE_BASE_RELOCATION relocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)newBase +
		ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	printf("bye3\n");

	while (relocation->VirtualAddress)
	{
		DWORD count = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		PWORD typeOffset = (PWORD)(relocation + 1);

		for (DWORD i = 0; i < count; i++)
		{
			if (typeOffset[i] >> 12 == IMAGE_REL_BASED_HIGHLOW)
			{
				PDWORD address = (PDWORD)((LPBYTE)newBase + relocation->VirtualAddress + (typeOffset[i] & 0xFFF));

				// Change protection to allow writing
				DWORD oldProtect;
				if (VirtualProtect(address, sizeof(DWORD), PAGE_READWRITE, &oldProtect))
				{
					*address += (DWORD)delta;

					// Restore original protection
					DWORD temp;
					VirtualProtect(address, sizeof(DWORD), oldProtect, &temp);
				}
				else
				{
					// Handle error
					return false;
				}
			}
#ifdef _WIN64
			else if (typeOffset[i] >> 12 == IMAGE_REL_BASED_DIR64)
			{
				PULONGLONG address = (PULONGLONG)((LPBYTE)newBase + relocation->VirtualAddress + (typeOffset[i] & 0xFFF));


				// Change protection to allow writing
				DWORD oldProtect;
				if (VirtualProtect(address, sizeof(ULONGLONG), PAGE_READWRITE, &oldProtect))
				{
					*address += delta;

					// Restore original protection
					DWORD temp;
					VirtualProtect(address, sizeof(ULONGLONG), oldProtect, &temp);
				}
				else
				{
					// Handle error
					return false;
				}
			}
#endif
		}

		relocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)relocation + relocation->SizeOfBlock);
	}

	return true;
}

bool ResolveImports(LPVOID newBase)
{
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)newBase;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((LPBYTE)newBase + dosHeader->e_lfanew);

	PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)newBase +
		ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	if (importDesc == (PIMAGE_IMPORT_DESCRIPTOR)newBase) {
		// No import directory
		return true;
	}

	while (importDesc->Name)
	{
		PSTR libName = (PSTR)((LPBYTE)newBase + importDesc->Name);
		HMODULE hModule = original_LoadLibraryA(libName);

		if (!hModule)
			return false;

		PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((LPBYTE)newBase + importDesc->FirstThunk);
		PIMAGE_THUNK_DATA originalThunk = (PIMAGE_THUNK_DATA)((LPBYTE)newBase + importDesc->OriginalFirstThunk);

		// Change memory protection to allow writing
		DWORD oldProtect;
		if (!VirtualProtect(thunk, sizeof(IMAGE_THUNK_DATA) * 100, PAGE_READWRITE, &oldProtect))
		{
			return false;
		}

		while (originalThunk->u1.AddressOfData)
		{
			FARPROC func;

			if (IMAGE_SNAP_BY_ORDINAL(originalThunk->u1.Ordinal))
			{
				func = ManualGetProcAddress(hModule, (LPCSTR)(originalThunk->u1.Ordinal & 0xFFFF));
			}
			else
			{
				PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)newBase + originalThunk->u1.AddressOfData);
				func = ManualGetProcAddress(hModule, (LPCSTR)importByName->Name);
			}

			if (!func)
				return false;

			thunk->u1.Function = (ULONGLONG)func;

			originalThunk++;
			thunk++;
		}

		DWORD temp;
		VirtualProtect((LPVOID)((LPBYTE)newBase + importDesc->FirstThunk), sizeof(IMAGE_THUNK_DATA) * 100, oldProtect, &temp);

		importDesc++;
	}

	return true;
}

LPVOID ConvertDatafileDllToExecutable(HMODULE hDataFile)
{
	if (!hDataFile)
	{
		printf("Invalid hDataFile\n");
		return NULL;
	}

	// Adjust the base address
	LPVOID baseAddress = (LPVOID)((ULONG_PTR)hDataFile & ~(ULONG_PTR)3);
	printf("Adjusted base address: 0x%p\n", baseAddress);

	// Verify DOS header
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)baseAddress;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("Invalid DOS signature: 0x%X\n", dosHeader->e_magic);
		return NULL;
	}

	// Verify NT headers
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((LPBYTE)baseAddress + dosHeader->e_lfanew);
	if (ntHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("Invalid NT signature: 0x%X\n", ntHeader->Signature);
		return NULL;
	}

	printf("DOS header e_lfanew: 0x%X\n", dosHeader->e_lfanew);
	printf("NT headers ImageBase: 0x%p, SizeOfImage: %u\n",
		(LPVOID)ntHeader->OptionalHeader.ImageBase, ntHeader->OptionalHeader.SizeOfImage);

	// Calculate the delta for relocation
	ULONG_PTR delta = (ULONG_PTR)baseAddress - ntHeader->OptionalHeader.ImageBase;
	printf("Relocation delta: 0x%p\n", (LPVOID)delta);

	// Instead of trying to change protection, let's analyze the DLL structure
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeader);
	for (WORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++)
	{
		printf("Section %d: Name=%s, VirtualAddress=0x%X, SizeOfRawData=0x%X, Characteristics=0x%X\n",
			i, section->Name, section->VirtualAddress, section->SizeOfRawData, section->Characteristics);
		section++;
	}

	// Perform relocations (if necessary)
	if (delta != 0)
	{
		if (!RelocateImageBase(baseAddress, delta))
		{
			printf("RelocateImageBase failed\n");
			return NULL;
		}
	}
	printf("hello\n");

	// Resolve imports
	if (!ResolveImports(baseAddress))
	{
		printf("ResolveImports failed\n");
		return NULL;
	}

	printf("DLL analysis complete. Base address: 0x%p\n", baseAddress);
	return baseAddress;
}

BOOL GetModuleInformationManual(HMODULE hModule, LPMODULEINFO lpmodinfo, DWORD cb)
{
	if (!hModule || !lpmodinfo || cb < sizeof(MODULEINFO))
	{
		SetLastError(ERROR_INVALID_PARAMETER);
		printf("Invalid parameters passed to GetModuleInformationManual\n");
		return FALSE;
	}

	// For LOAD_LIBRARY_AS_DATAFILE, the returned handle is the base address + 1
	LPVOID baseAddress = (LPVOID)((ULONG_PTR)hModule & ~(ULONG_PTR)3);

	printf("Base address: 0x%p\n", baseAddress);

	// Try to read the DOS header without changing protection
	__try
	{
		PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)baseAddress;
		if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		{
			SetLastError(ERROR_BAD_EXE_FORMAT);
			printf("Invalid DOS signature: 0x%X\n", dosHeader->e_magic);
			return FALSE;
		}

		PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)baseAddress + dosHeader->e_lfanew);
		if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
		{
			SetLastError(ERROR_BAD_EXE_FORMAT);
			printf("Invalid NT signature: 0x%X\n", ntHeaders->Signature);
			return FALSE;
		}

		// Fill in the MODULEINFO structure
		lpmodinfo->lpBaseOfDll = baseAddress;
		lpmodinfo->SizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
		lpmodinfo->EntryPoint = (LPVOID)((BYTE*)baseAddress + ntHeaders->OptionalHeader.AddressOfEntryPoint);

		printf("Module information retrieved successfully:\n");
		printf("Base address: 0x%p\n", lpmodinfo->lpBaseOfDll);
		printf("Size of image: %u bytes\n", lpmodinfo->SizeOfImage);
		printf("Entry point: 0x%p\n", lpmodinfo->EntryPoint);

		return TRUE;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DWORD exceptionCode = GetExceptionCode();
		printf("Exception occurred while accessing memory: 0x%X\n", exceptionCode);

		// If we get here, we couldn't read the memory directly. Let's try to use ReadProcessMemory.
		IMAGE_DOS_HEADER dosHeader;
		SIZE_T bytesRead;
		if (!ReadProcessMemory(GetCurrentProcess(), baseAddress, &dosHeader, sizeof(IMAGE_DOS_HEADER), &bytesRead))
		{
			printf("ReadProcessMemory failed for DOS header. Error: %d\n", GetLastError());
			return FALSE;
		}

		if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
		{
			SetLastError(ERROR_BAD_EXE_FORMAT);
			printf("Invalid DOS signature: 0x%X\n", dosHeader.e_magic);
			return FALSE;
		}

		IMAGE_NT_HEADERS ntHeaders;
		if (!ReadProcessMemory(GetCurrentProcess(), (BYTE*)baseAddress + dosHeader.e_lfanew, &ntHeaders, sizeof(IMAGE_NT_HEADERS), &bytesRead))
		{
			printf("ReadProcessMemory failed for NT headers. Error: %d\n", GetLastError());
			return FALSE;
		}

		if (ntHeaders.Signature != IMAGE_NT_SIGNATURE)
		{
			SetLastError(ERROR_BAD_EXE_FORMAT);
			printf("Invalid NT signature: 0x%X\n", ntHeaders.Signature);
			return FALSE;
		}

		// Fill in the MODULEINFO structure
		lpmodinfo->lpBaseOfDll = baseAddress;
		lpmodinfo->SizeOfImage = ntHeaders.OptionalHeader.SizeOfImage;
		lpmodinfo->EntryPoint = (LPVOID)((BYTE*)baseAddress + ntHeaders.OptionalHeader.AddressOfEntryPoint);

		printf("Module information retrieved successfully (via ReadProcessMemory):\n");
		printf("Base address: 0x%p\n", lpmodinfo->lpBaseOfDll);
		printf("Size of image: %u bytes\n", lpmodinfo->SizeOfImage);
		printf("Entry point: 0x%p\n", lpmodinfo->EntryPoint);

		return TRUE;
	}
}

FARPROC ManualGetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
	// Get the DOS header
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("Invalid DOS signature\n");
		return NULL;
	}

	// Get the NT headers
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((LPBYTE)hModule + dosHeader->e_lfanew);
	if (ntHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("Invalid NT signature\n");
		return NULL;
	}

	// Get the export directory
	PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)hModule +
		ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	DWORD* addressOfFunctions = (DWORD*)((LPBYTE)hModule + exportDir->AddressOfFunctions);
	DWORD* addressOfNames = (DWORD*)((LPBYTE)hModule + exportDir->AddressOfNames);
	WORD* addressOfNameOrdinals = (WORD*)((LPBYTE)hModule + exportDir->AddressOfNameOrdinals);

	// Check if we're looking up by ordinal
	if ((DWORD_PTR)lpProcName >> 16 == 0)
	{
		WORD ordinal = (WORD)((DWORD_PTR)lpProcName & 0xFFFF);
		if (ordinal < exportDir->Base || ordinal >= exportDir->Base + exportDir->NumberOfFunctions)
		{
			printf("Ordinal out of range\n");
			return NULL;
		}
		DWORD functionRVA = addressOfFunctions[ordinal - exportDir->Base];
		return (FARPROC)((LPBYTE)hModule + functionRVA);
	}

	// Look up by name
	for (DWORD i = 0; i < exportDir->NumberOfNames; i++)
	{
		char* name = (char*)((LPBYTE)hModule + addressOfNames[i]);
		if (strcmp(name, lpProcName) == 0)
		{
			WORD ordinal = addressOfNameOrdinals[i];
			DWORD functionRVA = addressOfFunctions[ordinal];
			return (FARPROC)((LPBYTE)hModule + functionRVA);
		}
	}

	printf("Function %s not found\n", lpProcName);
	return NULL;
}