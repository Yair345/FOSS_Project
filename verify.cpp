#include <iostream>
#include <string>
#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

bool verify_file_signature(const std::wstring& file_path) {
    WINTRUST_FILE_INFO file_info = {};
    file_info.cbStruct = sizeof(WINTRUST_FILE_INFO);
    file_info.pcwszFilePath = file_path.c_str();

    WINTRUST_DATA trust_data = {};
    trust_data.cbStruct = sizeof(WINTRUST_DATA);
    trust_data.dwUIChoice = WTD_UI_NONE;
    trust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
    trust_data.dwUnionChoice = WTD_CHOICE_FILE;
    trust_data.pFile = &file_info;
    trust_data.dwStateAction = WTD_STATEACTION_VERIFY;
    trust_data.dwProvFlags = WTD_SAFER_FLAG;

    GUID policy_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    LONG result = WinVerifyTrust(NULL, &policy_guid, &trust_data);

    trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policy_guid, &trust_data);

    if (result == ERROR_SUCCESS) {
        std::wcout << L"Signature verified successfully for " << file_path << std::endl;
        return true;
    }
    else {
        std::wcerr << L"Signature verification failed for " << file_path << std::endl;
        if (result == TRUST_E_NOSIGNATURE) {
            std::wcerr << L"The file is not signed or the signature is not present." << std::endl;
        }
        else if (result == TRUST_E_BAD_DIGEST) {
            std::wcerr << L"The file has been modified after it was signed." << std::endl;
        }
        else if (result == TRUST_E_EXPLICIT_DISTRUST) {
            std::wcerr << L"The signature is present, but specifically disallowed." << std::endl;
        }
        else if (result == CRYPT_E_SECURITY_SETTINGS) {
            std::wcerr << L"The signature is present, but not trusted based on system security settings." << std::endl;
        }
        else {
            std::wcerr << L"An unknown error occurred. Error code: " << result << std::endl;
        }
        return false;
    }
}