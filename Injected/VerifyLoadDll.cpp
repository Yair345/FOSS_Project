// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <stdio.h>
#include <psapi.h>
#include <iostream>
#include "verify.h"


int hook(PCSTR func_to_hook, PCSTR DLL_to_hook, UINT_PTR new_func_address, bool load);
HMODULE WINAPI LoadLibraryAndCheckDll(LPCSTR lpLibFileName);
bool RelocateImageBase(LPVOID newBase, ULONG_PTR delta);
bool ResolveImports(LPVOID newBase);
HMODULE LoadDllManually(HMODULE hModule);
bool ProcessExports(LPVOID baseAddress);
bool IsDLLInUse(LPVOID baseAddress);
void TrackAndFreeDLLs();
FARPROC GetExportedFunction(LPVOID baseAddress, const char* functionName);

// Add these structure definitions
typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;


// Global variables
LPVOID loadedModule;
std::atomic<bool> shouldExit(false);


// Original LoadLibraryA function pointer
typedef HMODULE(WINAPI* pLoadLibraryA)(LPCSTR);
pLoadLibraryA original_LoadLibraryA = NULL;

typedef HMODULE(WINAPI* pGetProcAddress)(HMODULE, LPCSTR);
pGetProcAddress original_GetProcAddress = NULL;

/*
 * Entry point for the DLL
 * Hooks the LoadLibraryA and GetProcAddress functions when the DLL is attached to a process
 *
 * @param hModule Handle to the DLL module
 * @param ul_reason_for_call Reason for calling the function
 * @param lpReserved Reserved parameter
 * @return TRUE if the initialization succeeds, FALSE otherwise
 */
BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		PCSTR func_to_hook_load = "LoadLibraryA";
		PCSTR DLL_to_hook = "KERNEL32.dll";
		UINT_PTR new_func_address_load = (UINT_PTR)&LoadLibraryAndCheckDll;
		hook(func_to_hook_load, DLL_to_hook, new_func_address_load, true);

		PCSTR func_to_hook_func = "GetProcAddress";
		UINT_PTR new_func_address_func = (UINT_PTR)&GetExportedFunction;
		hook(func_to_hook_func, DLL_to_hook, new_func_address_func, false);
	}
	break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

/*
 * Custom implementation of LoadLibraryA
 * Loads the DLL manually using LoadDllManually and starts a thread to track and free DLLs
 *
 * @param lpLibFileName Name of the library to load
 * @return Handle to the loaded module, or NULL if the operation fails
 */
HMODULE WINAPI LoadLibraryAndCheckDll(LPCSTR lpLibFileName)
{
	HMODULE hDataFile = LoadLibraryExA(lpLibFileName, NULL, LOAD_LIBRARY_AS_DATAFILE);

	// Fixing the pointer to point to the 'M' instead of 'Z'
	hDataFile = (HMODULE)((ULONG_PTR)hDataFile & ~((ULONG_PTR)0xffff));

	if (hDataFile)
	{
		if (VerifyDllFromHModule(hDataFile))
		{
			// if verify
			LPVOID executableDll = LoadDllManually(hDataFile);

			std::thread trackingThread(TrackAndFreeDLLs);
			trackingThread.detach();

			return (HMODULE)executableDll;
		}

		printf("The file %s is not verified\n", lpLibFileName);
		return NULL;
	}

	return NULL;
}

/*
 * Implements function hooking by modifying the Import Address Table (IAT)
 *
 * @param func_to_hook Name of the function to hook
 * @param DLL_to_hook Name of the DLL containing the function to hook
 * @param new_func_address Address of the new function to replace the original
 * @param load True if hooking LoadLibraryA, false if hooking GetProcAddress
 * @return 1 if successful, 0 if failed
 */
int hook(PCSTR func_to_hook, PCSTR DLL_to_hook, UINT_PTR new_func_address, bool load)
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
		// printf("DLL name: %s\n", DLL_name);
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

	while (thunkILT->u1.AddressOfData != 0 && !(thunkILT->u1.Ordinal & IMAGE_ORDINAL_FLAG)) 
	{
		nameData = (PIMAGE_IMPORT_BY_NAME)(baseAddress + thunkILT->u1.AddressOfData);
		if (!strcmp(func_to_hook, (char*)nameData->Name))
			break;
		thunkIAT++;
		thunkILT++;
	}

	if (load && !original_LoadLibraryA)
	{
		original_LoadLibraryA = (pLoadLibraryA)thunkIAT->u1.Function;
	}
	else if (!original_GetProcAddress)
	{
		original_GetProcAddress = (pGetProcAddress)thunkIAT->u1.Function;
	}

	// Hook IAT: Write over function pointer
	DWORD dwOld = NULL;
	VirtualProtect((LPVOID) & (thunkIAT->u1.Function), sizeof(UINT_PTR), PAGE_READWRITE, &dwOld);
	thunkIAT->u1.Function = new_func_address;
	VirtualProtect((LPVOID) & (thunkIAT->u1.Function), sizeof(UINT_PTR), dwOld, NULL);

	return 1;
}

/*
 * Manually loads a DLL into memory
 * Performs necessary relocations, resolves imports, and calls the DLL's entry point
 *
 * @param hModule Handle to the module to load
 * @return Handle to the manually loaded module, or NULL if the operation fails
 */
HMODULE LoadDllManually(HMODULE hModule)
{
	// Get the DOS and NT headers
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((LPBYTE)hModule + dosHeader->e_lfanew);

	// Calculate the size of the image
	SIZE_T imageSize = ntHeader->OptionalHeader.SizeOfImage;

	// Allocate new memory for the DLL
	LPVOID newBase = VirtualAlloc(NULL, imageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (newBase == NULL)
	{
		printf("Failed to allocate memory for the DLL\n");
		return NULL;
	}

	// Copy the headers
	memcpy(newBase, hModule, ntHeader->OptionalHeader.SizeOfHeaders);

	// Copy the sections
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeader);
	for (UINT i = 0; i < ntHeader->FileHeader.NumberOfSections; i++, section++)
	{
		if (section->SizeOfRawData > 0)
		{
			LPVOID dest = (LPVOID)((LPBYTE)newBase + section->VirtualAddress);
			LPVOID src = (LPVOID)((LPBYTE)hModule + section->PointerToRawData);
			memcpy(dest, src, section->SizeOfRawData);
		}
	}

	// Calculate the delta between the preferred load address and the actual load address
	ULONG_PTR delta = (ULONG_PTR)newBase - ntHeader->OptionalHeader.ImageBase;

	// Perform base relocation if necessary
	if (delta != 0)
	{
		if (!RelocateImageBase(newBase, delta))
		{
			VirtualFree(newBase, 0, MEM_RELEASE);
			return NULL;
		}
	}

	// Resolve imports
	if (!ResolveImports(newBase))
	{
		VirtualFree(newBase, 0, MEM_RELEASE);
		return NULL;
	}

	if (!ProcessExports(newBase))
	{
		VirtualFree(newBase, 0, MEM_RELEASE);
		return NULL;
	}

	// Get the address of DllMain
	LPVOID dllMainAddress = (LPVOID)((LPBYTE)newBase + ntHeader->OptionalHeader.AddressOfEntryPoint);

	// Call DllMain with DLL_PROCESS_ATTACH
	typedef BOOL(WINAPI* DllMain_t)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
	DllMain_t dllMain = (DllMain_t)dllMainAddress;

	if (dllMain != NULL) {
		BOOL result = FALSE;
		__try {
			result = dllMain((HINSTANCE)newBase, DLL_PROCESS_ATTACH, NULL);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			printf("Exception in DllMain: 0x%x\n", GetExceptionCode());
			VirtualFree(newBase, 0, MEM_RELEASE);
			return NULL;
		}
		if (!result) {
			VirtualFree(newBase, 0, MEM_RELEASE);
			return NULL;
		}
	}

	loadedModule = newBase;

	return (HMODULE)newBase;
}

/*
 * Performs base relocations if the DLL is loaded at a different address than its preferred base address
 *
 * @param newBase New base address of the loaded DLL
 * @param delta Difference between the preferred and actual load addresses
 * @return true if successful, false otherwise
 */
bool RelocateImageBase(LPVOID newBase, ULONG_PTR delta)
{
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)newBase;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((LPBYTE)newBase + dosHeader->e_lfanew);

	IMAGE_DATA_DIRECTORY relocations = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	DWORD_PTR relocationTable = relocations.VirtualAddress + (DWORD_PTR)newBase;
	DWORD relocationsProcessed = 0;

	while (relocationsProcessed < relocations.Size)
	{
		PBASE_RELOCATION_BLOCK relocationBlock = (PBASE_RELOCATION_BLOCK)(relocationTable + relocationsProcessed);
		relocationsProcessed += sizeof(BASE_RELOCATION_BLOCK);
		DWORD relocationsCount = (relocationBlock->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);

		PBASE_RELOCATION_ENTRY relocationEntries = (PBASE_RELOCATION_ENTRY)(relocationTable + relocationsProcessed);

		for (DWORD i = 0; i < relocationsCount; i++)
		{
			relocationsProcessed += sizeof(BASE_RELOCATION_ENTRY);

			if (relocationEntries[i].Type == 0)
			{
				continue;
			}

			DWORD_PTR relocationRVA = relocationBlock->PageAddress + relocationEntries[i].Offset;
			DWORD_PTR addressToPatch = 0;
			ReadProcessMemory(GetCurrentProcess(), (LPCVOID)((DWORD_PTR)newBase + relocationRVA), &addressToPatch, sizeof(DWORD_PTR), NULL);
			addressToPatch += delta;
			std::memcpy((PVOID)((DWORD_PTR)newBase + relocationRVA), &addressToPatch, sizeof(DWORD_PTR));
			
		}
	}

	return true;
}

/*
 * Resolves the imported functions for the manually loaded DLL
 *
 * @param newBase Base address of the manually loaded DLL
 * @return true if successful, false otherwise
 */
bool ResolveImports(LPVOID newBase)
{
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)newBase;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((LPBYTE)newBase + dosHeader->e_lfanew);

	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL;
	IMAGE_DATA_DIRECTORY importsDirectory = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (DWORD_PTR)newBase);
	LPCSTR libraryName = "";
	HMODULE library = NULL;

	while (importDescriptor->Name != NULL)
	{
		libraryName = (LPCSTR)importDescriptor->Name + (DWORD_PTR)newBase;
		library = LoadLibraryA(libraryName);

		if (library)
		{
			PIMAGE_THUNK_DATA thunk = NULL;
			thunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)newBase + importDescriptor->FirstThunk);

			while (thunk->u1.AddressOfData != NULL)
			{
				if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal))
				{
					LPCSTR functionOrdinal = (LPCSTR)IMAGE_ORDINAL(thunk->u1.Ordinal);
					thunk->u1.Function = (DWORD_PTR)GetProcAddress(library, functionOrdinal);
				}
				else
				{
					PIMAGE_IMPORT_BY_NAME functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)newBase + thunk->u1.AddressOfData);
					DWORD_PTR functionAddress = (DWORD_PTR)GetProcAddress(library, functionName->Name);
					thunk->u1.Function = functionAddress;
				}
				++thunk;
			}
		}
		else
		{
			return false;
		}

		importDescriptor++;
	}

	return true;
}

/*
 * Processes the export table of the manually loaded DLL
 *
 * @param baseAddress Base address of the manually loaded DLL
 * @return true if successful, false otherwise
 */
bool ProcessExports(LPVOID baseAddress)
{
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)baseAddress;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((LPBYTE)baseAddress + dosHeader->e_lfanew);

	IMAGE_DATA_DIRECTORY exportDirectory = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (exportDirectory.Size == 0)
		return true; // No exports

	PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)baseAddress + exportDirectory.VirtualAddress);

	PDWORD functions = (PDWORD)((LPBYTE)baseAddress + exportDir->AddressOfFunctions);
	PDWORD names = (PDWORD)((LPBYTE)baseAddress + exportDir->AddressOfNames);
	PWORD ordinals = (PWORD)((LPBYTE)baseAddress + exportDir->AddressOfNameOrdinals);

	for (DWORD i = 0; i < exportDir->NumberOfNames; i++)
	{
		const char* name = (const char*)((LPBYTE)baseAddress + names[i]);
		DWORD functionRVA = functions[ordinals[i]];

		FARPROC functionAddress = (FARPROC)((LPBYTE)baseAddress + functionRVA);

		// Store the function address in the IAT
		*(FARPROC*)((LPBYTE)baseAddress + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress + i * sizeof(FARPROC)) = functionAddress;
	}

	return true;
}

/*
 * Runs in a separate thread to monitor DLL usage and free unused DLLs
 */
void TrackAndFreeDLLs()
{
	while (!shouldExit)
	{
		LPVOID baseAddress = loadedModule;

		if (!IsDLLInUse(baseAddress))
		{
			// Call DllMain with DLL_PROCESS_DETACH
			PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)baseAddress;
			PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((BYTE*)baseAddress + dosHeader->e_lfanew);
			typedef BOOL(WINAPI* DllMain_t)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);
			DllMain_t dllMain = (DllMain_t)((BYTE*)baseAddress + ntHeader->OptionalHeader.AddressOfEntryPoint);
			dllMain((HINSTANCE)baseAddress, DLL_PROCESS_DETACH, NULL);

			// Free the virtual memory
			VirtualFree(baseAddress, 0, MEM_RELEASE);
		}		

		Sleep(1000); // Check every second
	}
}

/*
 * Checks if a DLL is currently in use
 *
 * @param baseAddress Base address of the DLL to check
 * @return true if the DLL is in use, false otherwise
 */
bool IsDLLInUse(LPVOID baseAddress)
{
	DWORD handleCount = 0;

	// Check if there are any open handles to the DLL
	if (GetHandleInformation((HANDLE)baseAddress, &handleCount))
	{
		// If handleCount is greater than 0, the DLL is still in use
		return handleCount > 0;
	}

	// If GetHandleInformation fails, we assume the DLL is in use to be safe
	return true;
}

/*
 * Custom implementation of GetProcAddress
 * Retrieves the address of an exported function from the manually loaded DLL
 *
 * @param baseAddress Base address of the manually loaded DLL
 * @param functionName Name of the function to retrieve
 * @return Address of the exported function, or NULL if not found
 */
FARPROC GetExportedFunction(LPVOID baseAddress, const char* functionName)
{
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)baseAddress;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((LPBYTE)baseAddress + dosHeader->e_lfanew);

	IMAGE_DATA_DIRECTORY exportDirectory = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)baseAddress + exportDirectory.VirtualAddress);

	PDWORD functions = (PDWORD)((LPBYTE)baseAddress + exportDir->AddressOfFunctions);
	PDWORD names = (PDWORD)((LPBYTE)baseAddress + exportDir->AddressOfNames);
	PWORD ordinals = (PWORD)((LPBYTE)baseAddress + exportDir->AddressOfNameOrdinals);

	for (DWORD i = 0; i < exportDir->NumberOfNames; i++)
	{
		const char* name = (const char*)((LPBYTE)baseAddress + names[i]);
		if (strcmp(name, functionName) == 0)
		{
			DWORD functionRVA = functions[ordinals[i]];
			return (FARPROC)((LPBYTE)baseAddress + functionRVA);
		}
	}

	return NULL;
}