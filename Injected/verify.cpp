#include "pch.h"
#include <iostream>
#include <string>
#include <windows.h>
#include <winnt.h>
#include <softpub.h>
#include <Psapi.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <Wintrust.h>

#pragma comment(lib, "wintrust.lib")

// Function to verify a file signature
BOOL verifyFileSignature(LPCWSTR oldfilePath)
{
	WCHAR fullPath[MAX_PATH];
	DWORD result = GetFullPathName(oldfilePath, MAX_PATH, fullPath, nullptr);
	std::wstring filePath = fullPath;
	WINTRUST_FILE_INFO fileData = {};
	fileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
	fileData.pcwszFilePath = filePath.c_str();


	// Initialize the WINTRUST_DATA structure
	WINTRUST_DATA winTrustData = {};
	winTrustData.cbStruct = sizeof(WINTRUST_DATA);
	winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
	winTrustData.pFile = &fileData;
	winTrustData.dwUIChoice = WTD_UI_NONE;
	winTrustData.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
	winTrustData.dwProvFlags = WTD_SAFER_FLAG;
	winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
	GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

	// Verify the file
	LONG status = WinVerifyTrust(NULL, &policyGUID, &winTrustData);

	// Clean up
	winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
	WinVerifyTrust(NULL, &policyGUID, &winTrustData);

	return (status == ERROR_SUCCESS);
}


// Function to write a buffer to a file
BOOL WriteDllToFile(HMODULE hModule, const WCHAR* outputFilePath) 
{
	if (hModule == NULL || outputFilePath == NULL) 
	{
		return FALSE;
	}

	// Get the DOS header
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) 
	{
		return FALSE;
	}

	// Get the NT headers
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) 
	{
		return FALSE;
	}

	// Calculate the size of the file
	DWORD fileSize = 0;
	PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
	for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) 
	{
		DWORD endOfSection = sectionHeader[i].PointerToRawData + sectionHeader[i].SizeOfRawData;
		if (endOfSection > fileSize) 
		{
			fileSize = endOfSection;
		}

	}

	// Add the size of the certificate data
	if (ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size > 0) 
	{
		DWORD certOffset = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
		DWORD certSize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;

		// The certificate data is stored at the end of the file
		if (certOffset + certSize > fileSize) 
		{
			fileSize = certOffset + certSize;
		}
	}

	// Allocate a buffer for the entire file
	BYTE* fileBuffer = (BYTE*)VirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (fileBuffer == NULL) 
	{
		return FALSE;
	}

	// Copy the headers
	memcpy(fileBuffer, hModule, fileSize);

	// Write the buffer to file
	HANDLE hFile = CreateFile(outputFilePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) 
	{
		VirtualFree(fileBuffer, 0, MEM_RELEASE);
		return FALSE;
	}

	DWORD bytesWritten;
	BOOL result = WriteFile(hFile, fileBuffer, fileSize, &bytesWritten, NULL);

	// Clean up
	CloseHandle(hFile);
	VirtualFree(fileBuffer, 0, MEM_RELEASE);

	return result && (bytesWritten == fileSize);
}


// Function to read a DLL from an HMODULE and write to a file for verification
BOOL VerifyDllFromHModule(HMODULE hModule) 
{
	// Write the DLL content to a temporary file
	WCHAR tempFilePath[MAX_PATH];

	if (GetTempFileName(L".", L"DLL", 0, tempFilePath) == 0) 
	{
		return FALSE;
	}

	BOOL is = WriteDllToFile(hModule, (const WCHAR*)tempFilePath);
	
	// Verify the temporary file
	BOOL verifyResult = verifyFileSignature(tempFilePath);

	DeleteFile(tempFilePath);

	return verifyResult;
}