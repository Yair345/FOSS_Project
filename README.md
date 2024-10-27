# DLL Safe Loader
DLLs are critical components that enable executables to extend their functionality by loading additional code at runtime. 

Sometimes a trusted high-authorization EXE can load DLLs without adequately verifying their signatures.

**An attacker can exploit this weakness by replacing legitimate DLLs with malicious ones, compromising the integrity of the signed EXE.**

**To counter this threat, we develop a robust framework for signing DLLs and ensuring that an EXE validates these signatures at run time, before any library code is executed.**

Our solution involves a signer program and a validating program. The signer program signs the DLLs. The validating program uses **IAT hooking** to intercept the EXE's DLLs loading proccess, verify the DLL's signature, and load only trusted DLLs by **Refelctive DLL loading**.


You can find further information by reading Roles.txt and watching the demo video.
