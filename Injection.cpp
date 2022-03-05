BOOL SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege){

	TOKEN_PRIVILEGES tp;
	HANDLE hToken;
	LUID luid;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)){
		_tprintf(L"Proceso del toke fallo: %u\n", GetLastError());
		return false;
	}

	if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid)){
		_tprintf(L"Permisos del localsytem fallaron %u\n", GetLastError());
		return false;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege){
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	}
	else{
		tp.Privileges[0].Attributes = 0;
	}

	if (!AdjustTokenPrivileges(hToken, false, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)){
		_tprintf(L"Se ajustaron los privilegios %u\n", GetLastError());
		return false;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED){
		_tprintf(L"No ajustaron los privilegios \n");
		return false;
	}

	return true;
}

BOOL InjectDll(DWORD dwPID, LPCTSTR szDllPath){

	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	HMODULE hMod = NULL;
	LPVOID pRemoteBuf = NULL;
	DWORD dwBufSize = (DWORD)(_tcslen(szDllPath) + 1) * sizeof(TCHAR);
	LPTHREAD_START_ROUTINE pThreadProc;

	if (!(hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, dwPID))){
		_tprintf(dwPID, GetLastError());
		return false;
	}
	pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize, MEM_COMMIT, PAGE_READWRITE);

	WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)szDllPath, dwBufSize, NULL);
	hMod = GetModuleHandle(L"kernel32.dll");
	pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "LoadLibraryW");
	hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, pRemoteBuf, 0, NULL);
	WaitForSingleObject(hThread, INFINITE);

	CloseHandle(hThread);
	CloseHandle(hProcess);

	return true;
}

int _tmain(int argc, TCHAR *argv[]){
	if (argc != 3){
		_tprintf(L"Pid del proceso %s <pid> <dll_path>\n", argv[0]);
		return 1;
	}

	if (!SetPrivilege(SE_DEBUG_NAME, true)){
		return 1;
	}
	if (InjectDll((DWORD)_tstol(argv[1]), argv[2])){
		_tprintf(L"Se pudo inyectar el DLL (\"%s\") ", argv[2]);
	}
	else{
		_tprintf(L"No se pudo (\"%s\") \n", argv[2]);
	}

	return 0;
}