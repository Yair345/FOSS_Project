We have four files:

test_exe.exe

test_dll.dll - unverified

test_dll_verified.dll - verified version of test_dll.dll

Injection.exe

First, we demonstrate that the test_exe.exe runs and loads its DLL succesfully. It loads test_dll.dll.

Second, we run test_exe.exe with an unverified DLL (test_dll.dll) and run Injection.exe. We can see that it doesn't load it, and closes the process, because its unverified.

Third, we changed test_dll.dll to test_dll_unverified and the test_dll_verified.dll became test_dll.dll, we run test_exe.exe (now we'll run the signed version) with a verified DLL and run Injection.exe. We can see that it loads succesfully.
