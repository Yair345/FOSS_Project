// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <stdio.h>
#include <windows.h>

int hook(PCSTR func_to_hook, PCSTR DLL_to_hook, DWORD new_func_addres);
LPVOID LoadLibraryAndCheckDll()


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
	PCSTR func_to_hook = "CreateFileW";
	PCSTR DLL_to_hook = "KERNEL32.dll";
	DWORD new_func_address = (DWORD)&activateClient;


    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		hook(func_to_hook, DLL_to_hook, new_func_address);
		break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


int hook(PCSTR func_to_hook, PCSTR DLL_to_hook, DWORD new_func_addres)
{
	//Initializing parameters
	PIMAGE_DOS_HEADER dosHeader;
	PIMAGE_NT_HEADERS NTHeader;
	PIMAGE_OPTIONAL_HEADER64 optionalHeader;
	IMAGE_DATA_DIRECTORY importDirectory;
	DWORD descriptorStartRVA;
	PIMAGE_IMPORT_DESCRIPTOR importDescriptor;
	int index;

	// We need to get inside the IAT and hook createFile over there

	// Get base address of currently running .exe
	DWORD baseAddress = (DWORD)GetModuleHandle(NULL);

	// Get the import directory address
	dosHeader = (PIMAGE_DOS_HEADER)(baseAddress);

	if (((*dosHeader).e_magic) != IMAGE_DOS_SIGNATURE) {
		return 0;
	}

	// Locate NT header
	NTHeader = (PIMAGE_NT_HEADERS)(baseAddress + (*dosHeader).e_lfanew);
	if (((*NTHeader).Signature) != IMAGE_NT_SIGNATURE) {
		return 0;
	}

	// Locate optional header
	optionalHeader = &(*NTHeader).OptionalHeader;
	if (((*optionalHeader).Magic) != 0x10B) {
		return 0;
	}

	importDirectory = (*optionalHeader).DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	descriptorStartRVA = importDirectory.VirtualAddress;

	importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(descriptorStartRVA + (*optionalHeader).ImageBase);

	index = 0;
	char* DLL_name;
	// Look for the DLL which includes the function for hooking
	while (importDescriptor->Characteristics != 0) {
		DLL_name = (char*)(baseAddress + importDescriptor->Name);
		printf("DLL name: %s\n", DLL_name);
		if (!strcmp(DLL_to_hook, DLL_name))
			break;
		index++;
	}

	// exit if the DLL is not found in import directory
	if (importDescriptor[index].Characteristics == 0) {
		printf("DLL was not found");
		return 0;
	}

	// Search for requested function in the DLL
	PIMAGE_THUNK_DATA thunkILT; // Import Lookup Table - names
	PIMAGE_THUNK_DATA thunkIAT; // Import Address Table - addresses
	PIMAGE_IMPORT_BY_NAME nameData;

	thunkILT = (PIMAGE_THUNK_DATA)(optionalHeader->ImageBase + importDescriptor[index].OriginalFirstThunk);
	thunkIAT = (PIMAGE_THUNK_DATA)(importDescriptor[index].FirstThunk + optionalHeader->ImageBase);
	if ((thunkIAT == NULL) or (thunkILT == NULL)) {
		return 0;
	}

	while (((*thunkILT).u1.AddressOfData != 0) & (!((*thunkILT).u1.Ordinal & IMAGE_ORDINAL_FLAG))) {
		nameData = (PIMAGE_IMPORT_BY_NAME)(baseAddress + (*thunkILT).u1.AddressOfData);
		if (!strcmp(func_to_hook, (char*)(*nameData).Name))
			break;
		thunkIAT++;
		thunkILT++;
	}

	// Hook IAT: Write over function pointer
	DWORD dwOld = NULL;
	saved_hooked_func_addr = (*thunkIAT).u1.Function;
	VirtualProtect((LPVOID) & ((*thunkIAT).u1.Function), sizeof(DWORD), PAGE_READWRITE, &dwOld);
	DWORD new_func_add = (DWORD)&activateClient; //put activateClient instead
	(*thunkIAT).u1.Function = new_func_add;
	VirtualProtect((LPVOID) & ((*thunkIAT).u1.Function), sizeof(DWORD), dwOld, NULL);
	return 1;
}