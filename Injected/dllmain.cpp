// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <stdio.h>
#include <windows.h>
#include <psapi.h>


int hook(PCSTR func_to_hook, PCSTR DLL_to_hook, UINT_PTR new_func_address);
HMODULE WINAPI LoadLibraryAndCheckDll(LPCSTR lpLibFileName);
bool RelocateImageBase(LPVOID newBase, ULONG_PTR delta);
bool ResolveImports(LPVOID newBase);
LPVOID ConvertDatafileDllToExecutable(HMODULE hDataFile);



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
		DWORD new_func_address = (DWORD)&LoadLibraryAndCheckDll;
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
	// Your custom logic here
	printf("LoadLibraryAndCheckDll called with: %s\n", lpLibFileName);
	HMODULE hDataFile = LoadLibraryEx((LPCWSTR)lpLibFileName, NULL, LOAD_LIBRARY_AS_DATAFILE);

	if (hDataFile)
	{
		// if verify
		LPVOID executableDll = ConvertDatafileDllToExecutable(hDataFile);

		// where to free it???

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

bool RelocateImageBase(LPVOID newBase, ULONG_PTR delta)
{
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)newBase;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((LPBYTE)newBase + dosHeader->e_lfanew);

	PIMAGE_BASE_RELOCATION relocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)newBase +
		ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	while (relocation->VirtualAddress)
	{
		DWORD count = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		PWORD typeOffset = (PWORD)(relocation + 1);

		for (DWORD i = 0; i < count; i++)
		{
			if (typeOffset[i] >> 12 == IMAGE_REL_BASED_HIGHLOW)
			{
				PDWORD address = (PDWORD)((LPBYTE)newBase + relocation->VirtualAddress + (typeOffset[i] & 0xFFF));
				*address += (DWORD)delta;
			}
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

	while (importDesc->Name)
	{
		PSTR libName = (PSTR)((LPBYTE)newBase + importDesc->Name);
		HMODULE hModule = original_LoadLibraryA(libName);

		if (!hModule)
			return false;

		PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((LPBYTE)newBase + importDesc->FirstThunk);

		while (thunk->u1.AddressOfData)
		{
			if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				// Import by ordinal
				FARPROC func = GetProcAddress(hModule, (LPCSTR)(thunk->u1.Ordinal & 0xFFFF));
				if (!func)
					return false;

				thunk->u1.Function = (ULONGLONG)func;
			}
			else
			{
				// Import by name
				PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)newBase + thunk->u1.AddressOfData);
				FARPROC func = GetProcAddress(hModule, (LPCSTR)importByName->Name);
				if (!func)
					return false;

				thunk->u1.Function = (ULONGLONG)func;
			}

			thunk++;
		}

		importDesc++;
	}

	return true;
}

LPVOID ConvertDatafileDllToExecutable(HMODULE hDataFile)
{
	if (!hDataFile)
		return NULL;

	// Get the size of the loaded module
	MODULEINFO moduleInfo;
	if (!GetModuleInformation(GetCurrentProcess(), hDataFile, &moduleInfo, sizeof(moduleInfo)))
		return NULL;

	SIZE_T dllSize = moduleInfo.SizeOfImage;

	// Allocate new memory with execute permissions
	LPVOID newBase = VirtualAlloc(NULL, dllSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!newBase)
		return NULL;

	// Copy the DLL content to the new memory location
	memcpy(newBase, (LPVOID)hDataFile, dllSize);

	// Get the DOS header
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)newBase;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		VirtualFree(newBase, 0, MEM_RELEASE);
		return NULL;
	}

	// Get the NT headers
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((LPBYTE)newBase + dosHeader->e_lfanew);
	if (ntHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		VirtualFree(newBase, 0, MEM_RELEASE);
		return NULL;
	}

	// Perform relocation if necessary
	if (ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress)
	{
		ULONG_PTR delta = (ULONG_PTR)newBase - ntHeader->OptionalHeader.ImageBase;
		if (delta != 0)
		{
			if (!RelocateImageBase(newBase, delta))
			{
				VirtualFree(newBase, 0, MEM_RELEASE);
				return NULL;
			}
		}
	}

	// Resolve imports
	if (!ResolveImports(newBase))
	{
		VirtualFree(newBase, 0, MEM_RELEASE);
		return NULL;
	}

	// Call the DLL entry point if it exists
	BOOL(WINAPI * DllMain)(HINSTANCE, DWORD, LPVOID);
	DllMain = (BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID))((LPBYTE)newBase + ntHeader->OptionalHeader.AddressOfEntryPoint);
	if (DllMain)
	{
		if (!DllMain((HINSTANCE)newBase, DLL_PROCESS_ATTACH, NULL))
		{
			VirtualFree(newBase, 0, MEM_RELEASE);
			return NULL;
		}
	}

	return newBase;
}