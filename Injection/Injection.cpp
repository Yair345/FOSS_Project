#include "pch.h"
#include <TlHelp32.h>
#include <tlhelp32.h>
#include <string>


#define WIN32_LEAN_AND_MEAN
#define BUFSIZE 4096

DWORD PIDFind(const std::wstring& processName);
std::wstring ConvertToWideString(const std::string& str);

int main(int argc, char **argv)
{
	if (argc < 2) 
	{
		std::cout << "Usage: " << argv[0] << " <process_name>" << std::endl;
		return 1;
	}

	// Convert argv[1] to string
	std::string processName = argv[1];

	LPCSTR dllname = "Injected.dll"; //the dll is in the injector project file
	CHAR  dllPath[BUFSIZE];
	LPSTR* pPath = NULL;

	DWORD pathlen = GetFullPathNameA(dllname, BUFSIZE, dllPath, pPath); // get injected dll path
	if (!pathlen)
	{
		cout << "error in GetFullPathNameA: " << GetLastError();
		return -1;
	}

	DWORD targetPID = PIDFind(ConvertToWideString(processName)); // Find target process PID
	DWORD err; // for errors

	HMODULE moduleHandle = GetModuleHandleA("KERNEL32.dll"); // get KERNEL32.dll handle (where LoadLibraryA at)

	LPVOID addrLoadLibrary = (LPVOID)GetProcAddress(moduleHandle, "LoadLibraryA"); // get LoadLibraryA address

	HANDLE targetProcess = OpenProcess(PROCESS_ALL_ACCESS, false, targetPID);
	if (!targetProcess)
	{
		err = GetLastError();
		cout << "error in OpenProcess: " << err << " probably the process is not open";
		return -1;
	}

	// Get a pointer to memory location in remote process,
	// big enough to store DLL path
	LPVOID memAddr = (LPVOID)VirtualAllocEx(targetProcess, NULL, pathlen + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!memAddr) 
	{
		err = GetLastError();
		cout << "error in VirtualAllocEx: " << err;
		return -1;
	}

	// Write DLL name to remote process memory
	bool check = WriteProcessMemory(targetProcess, (LPVOID)memAddr, dllPath, pathlen + 1, NULL);
	if (!check) 
	{
		err = GetLastError();
		cout << "error in WriteProcessMemory: " << err;
		return -1;
	}

	// Open remote thread, while executing LoadLibrary
	// with parameter DLL name, will trigger DLLMain
	DWORD threadId;
	HANDLE hRemote = CreateRemoteThread(targetProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)addrLoadLibrary, (LPVOID)memAddr, NULL, &threadId);
	if (!hRemote) 
	{
		int err = GetLastError();
		cout << "error in CreateRemoteThread: " << err;
		return -1;
	}

	WaitForSingleObject(hRemote, INFINITE);
	check = CloseHandle(hRemote);
	return 0;
}

DWORD PIDFind(const std::wstring& processName) // Finds the PID by his name
{
	PROCESSENTRY32 processInfo;
	processInfo.dwSize = sizeof(processInfo);

	HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (processesSnapshot == INVALID_HANDLE_VALUE)
		return 0;

	Process32First(processesSnapshot, &processInfo);
	if (!processName.compare(processInfo.szExeFile))
	{
		CloseHandle(processesSnapshot);
		return processInfo.th32ProcessID;
	}

	while (Process32Next(processesSnapshot, &processInfo))
	{
		if (!processName.compare(processInfo.szExeFile))
		{
			CloseHandle(processesSnapshot);
			return processInfo.th32ProcessID;
		}
	}
	CloseHandle(processesSnapshot);
	return 0;
}

std::wstring ConvertToWideString(const std::string& str)
{
	if (str.empty()) return std::wstring();
	int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
	std::wstring wstrTo(size_needed, 0);
	MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
	return wstrTo;
}