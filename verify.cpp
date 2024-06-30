#include <iostream>
#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <mssip.h>
#include <Psapi.h>
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
const wchar_t* dll_path = L"C:\\Windows\\System32\\wintrust.dll";
bool verify_loaded_module_signature(HMODULE hModule) {
    BYTE* moduleBase = reinterpret_cast<BYTE*>(hModule);

    // Set up WINTRUST_DATA structure
    WINTRUST_DATA trustData = {};
    memset(&trustData, 0, sizeof(trustData));
    trustData.cbStruct = sizeof(WINTRUST_DATA);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_BLOB;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.hWVTStateData = NULL;
    trustData.dwProvFlags = WTD_LIFETIME_SIGNING_FLAG;
    trustData.dwUIContext = WTD_UICONTEXT_EXECUTE;


    // Set up WINTRUST_BLOB_INFO structure
    WINTRUST_BLOB_INFO blobInfo = {};
    memset(&blobInfo, 0, sizeof(blobInfo));
    blobInfo.cbStruct = sizeof(WINTRUST_BLOB_INFO);

    // Call CryptSIPRetrieveSubjectGuid to retrieve the subject GUID
    if (!CryptSIPRetrieveSubjectGuid(dll_path, NULL, &blobInfo.gSubject)) {
        DWORD dwError = GetLastError();
        std::cerr << "Error retrieving subject GUID. Error code: " << dwError << std::endl;
        return 1;
    }


    MODULEINFO moduleInfo = {};
    // Retrieve module information
    if (!GetModuleInformation(GetCurrentProcess(), hModule, &moduleInfo, sizeof(MODULEINFO))) {
        // Error handling: Failed to get module information
        return 0;
    }
    blobInfo.cbMemObject = moduleInfo.SizeOfImage;
    blobInfo.pbMemObject = moduleBase;

    trustData.pBlob = &blobInfo;

    // Set up GUID for WinVerifyTrust
    GUID actionGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    // Verify trust
    LONG trustResult = WinVerifyTrust(NULL, &actionGuid, &trustData);

    // Clean up
    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &actionGuid, &trustData);

    if (trustResult == ERROR_SUCCESS) {
        std::cout << "Signature verified successfully for loaded module" << std::endl;
        return true;
    }
    else {
        std::cerr << "Signature verification failed for loaded module. Error code: 0x" << std::dec << trustResult << std::endl;

        // Additional error information
        switch (trustResult) {
        case TRUST_E_NOSIGNATURE:
            std::cerr << "The file is not signed or the signature is not valid." << std::endl;
            break;
        case CERT_E_EXPIRED:
            std::cerr << "The signature is time-stamped but the timestamp's certificate has expired." << std::endl;
            break;
        case TRUST_E_BAD_DIGEST:
            std::cerr << "The file's digest doesn't match the one specified in the signature." << std::endl;
            break;
        case CERT_E_UNTRUSTEDROOT:
            std::cerr << "The certificate chain terminated in an untrusted root certificate." << std::endl;
            break;
        case CRYPT_E_SECURITY_SETTINGS:
            std::cerr << "The verification operation failed due to security settings for the cryptographic service provider." << std::endl;
            break;
        case TRUST_E_PROVIDER_UNKNOWN:
            std::cerr << "Unknown trust provider." << std::endl;
            break;
        default:
            std::cerr << "Unknown error occurred." << std::endl;
        }

        return false;
    }
}

int main() {
   

    // Load the DLL
    HMODULE hModule = LoadLibraryW(dll_path);
    if (hModule == NULL) {
        std::wcerr << L"Failed to load the DLL. Error: " << GetLastError() << std::endl;
        return 1;
    }

    std::wcout << L"DLL loaded successfully." << std::endl;

    // Verify the loaded module's signature
    bool result = verify_loaded_module_signature(hModule);

    // Unload the DLL
    FreeLibrary(hModule);

    return result ? 0 : 1;
}