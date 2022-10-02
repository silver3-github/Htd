#include "Injection.h"
#include <winternl.h>
#include <WinBase.h>


//���嵥������

Htd::Injection Htd::Injection::Instance;


//����ע��

int Htd::Injection::InjectByWinHook(unsigned threadId, const char* dllFileName, int idHook)
{
	HANDLE hthread = OpenThread(THREAD_GET_CONTEXT, false, threadId);
	if (!hthread)return -1;
	CloseHandle(hthread);

	HMODULE hmod = LoadLibraryA(dllFileName);
	if (!hmod)return -2;

	HOOKPROC hookProc = (HOOKPROC)GetProcAddress(hmod, "WinHookProc");
	if (!hookProc)return -3;

	HHOOK hhook = SetWindowsHookExA(idHook, hookProc, hmod, threadId);
	if (!hhook)return -4;
}

int Htd::Injection::InjectByWinHook(const char* className, const char* windowName, const char* dllFileName, int idHook)
{
	HWND hwnd = FindWindowA(className, windowName);
	if (!hwnd)return -1;
	DWORD threadId = GetWindowThreadProcessId(hwnd, NULL);

	return InjectByWinHook(threadId, dllFileName, idHook);
}


//��ڵ�ע��

//����32λ��64λ �ƻ���ڵ������ֽ���
#ifdef _WIN64
#define HOOK_CODE 23
#else
#define HOOK_CODE 10
#endif

//����ָ�붨��
typedef HMODULE(WINAPI* _LoadLibraryA)(LPCSTR lpLibFileName);
typedef BOOL(WINAPI* _FreeLibrary)(HMODULE hLibModule);
typedef BOOL(WINAPI* _VirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
typedef LPVOID(WINAPI* _VirtualAlloc)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef BOOL(WINAPI* _VirtualFree)(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
typedef UINT(WINAPI* _SetErrorMode)(UINT uMode);
typedef void* (__cdecl* _Memcpy)(void* _Dst, void const* _Src, size_t _Size);

//Զ�����ݶ���
typedef class RemoteData
{
public:
	RemoteData(const char* dllPath, HANDLE hProcess, LPVOID entryPoint, BOOL isTraceless);
	CHAR dllPath[MAX_PATH];
	_LoadLibraryA loadLibraryA;
	_FreeLibrary freeLibrary;
	_VirtualProtect virtualProtect;
	_VirtualAlloc virtualAlloc;
	_VirtualFree virtualFree;
	_SetErrorMode setErrorMode;
	_Memcpy _memcpy;
	LPVOID entryPoint;
	UCHAR entryPointCode[HOOK_CODE];
	BOOL isTraceless;
}*LPRemoteData;

RemoteData::RemoteData(const char* dllPath, HANDLE hProcess, LPVOID entryPoint, BOOL isTraceless)
{
	memcpy(this->dllPath, dllPath, strlen(dllPath) + 1);

	HMODULE hModule = LoadLibraryA("Kernel32.dll");
	if (hModule)
	{
		this->loadLibraryA = (_LoadLibraryA)GetProcAddress(hModule, "LoadLibraryA");
		this->freeLibrary = (_FreeLibrary)GetProcAddress(hModule, "FreeLibrary");
		this->virtualProtect = (_VirtualProtect)GetProcAddress(hModule, "VirtualProtect");
		this->virtualAlloc = (_VirtualAlloc)GetProcAddress(hModule, "VirtualAlloc");
		this->virtualFree = (_VirtualFree)GetProcAddress(hModule, "VirtualFree");
		this->setErrorMode = (_SetErrorMode)GetProcAddress(hModule, "SetErrorMode");
	}
	else
	{
		this->loadLibraryA = 0;
		this->freeLibrary = 0;
		this->virtualProtect = 0;
		this->virtualAlloc = 0;
		this->virtualFree = 0;
		this->setErrorMode = 0;
	}

	hModule = LoadLibraryA("Ntdll.dll");
	if (hModule)
	{
		this->_memcpy = (_Memcpy)GetProcAddress(hModule, "memcpy");
	}
	else
	{
		this->_memcpy = 0;
	}

	this->entryPoint = entryPoint;
	ReadProcessMemory(hProcess, entryPoint, this->entryPointCode, HOOK_CODE, NULL);

	this->isTraceless = isTraceless;
}

//������Ŀ�����ִ�е�ע�����
void RemoteCode()
{
	//��ȡԶ������
	LPVOID dataAddress = (LPVOID)0xcccccccccccccccc;
	LPRemoteData remoteData = (LPRemoteData)dataAddress;
	//ע��dll
	UINT oldMode = remoteData->setErrorMode(SEM_NOALIGNMENTFAULTEXCEPT);//�Զ��޸� ����δ��������쳣
	HMODULE hModule = remoteData->loadLibraryA(remoteData->dllPath);//64λ���м��ʱ���
	remoteData->setErrorMode(oldMode);
	//�������޺۴���
	//ע������ֻ�ܻ�ԭdll���ڴ棬���dll��ȫ�ֶ����ʼ����dllmain������˶����ڴ棬�������޷���ԭ�ġ�
	//    ���dll�����з�����Щ���ڴ�ʱ���ͻ�����쳣��������
	if (remoteData->isTraceless)
	{
		PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
		PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)hModule + dosHeader->e_lfanew);
		DWORD sizeOfImage = ntHeader->OptionalHeader.SizeOfImage;
		LPVOID dllData = remoteData->virtualAlloc(NULL, sizeOfImage, MEM_COMMIT, PAGE_READWRITE);
		remoteData->_memcpy(dllData, hModule, sizeOfImage);
		remoteData->freeLibrary(hModule);
		remoteData->virtualAlloc(hModule, sizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		remoteData->_memcpy(hModule, dllData, sizeOfImage);
		remoteData->virtualFree(dllData, 0, MEM_RELEASE);
	}
	//�޸���ڵ�
	DWORD oldProtect;
	remoteData->virtualProtect(remoteData->entryPoint, HOOK_CODE, PAGE_EXECUTE_READWRITE, &oldProtect);
	UCHAR* entryPointCode = (UCHAR*)remoteData->entryPoint;
	for (int i = 0; i < HOOK_CODE; i++)
	{
		entryPointCode[i] = remoteData->entryPointCode[i];
	}
	remoteData->virtualProtect(remoteData->entryPoint, HOOK_CODE, oldProtect, &oldProtect);
	//������ڵ�
	return;
}

//ִ����ڵ�ע��
int Htd::Injection::InjectByEntryPoint(const char* exePath, char* cmdline, const char* dllPath, bool isTraceless)
{
	//��������ͣ����
	char folderPath[MAX_PATH]{};
	for (int i = strlen(exePath) - 1; i >= 0; i--)
	{
		if (exePath[i] == '\\')
		{
			memcpy(folderPath, exePath, i + 1);
			break;
		}
	}

	STARTUPINFOA si{ sizeof(STARTUPINFOA) };
	PROCESS_INFORMATION pi{};
	if (!CreateProcessA(exePath, cmdline, NULL, NULL, false,  //��Ҫ����ԱȨ��
		CREATE_SUSPENDED, NULL, folderPath, &si, &pi))
	{
		return -1;
	}

	//��ȡ������ڵ�
	CONTEXT context{};
	context.ContextFlags = CONTEXT_INTEGER;
	GetThreadContext(pi.hThread, &context);
#ifdef _WIN64
	LPVOID entryPoint = (LPVOID)context.Rcx;//64������ڵ�
#else
	LPVOID entryPoint = (LPVOID)context.Eax;//32������ڵ� 
#endif

	//����Զ�̴����ڴ�
	//0 - 500    Զ�̴���
	//500 - 1500 Զ������
	LPVOID memAddress = VirtualAllocEx(pi.hProcess,
		NULL, 0x1500, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!memAddress)
	{
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		return -2;
	}
	LPVOID dataAddress = (LPVOID)((DWORD_PTR)memAddress + 0x500);

	//����Զ�̴���
	char remoteCode[0x200]{};
	memcpy(remoteCode, RemoteCode, 0x200);
	for (int i = 0; i < 0x100; i++)
	{
		PDWORD_PTR codePtr = (PDWORD_PTR)(remoteCode + i);
		if (*codePtr == (DWORD_PTR)0xcccccccccccccccc)
		{
			*codePtr = (DWORD_PTR)dataAddress;
			break;
		}
	}
	WriteProcessMemory(pi.hProcess, memAddress, remoteCode, sizeof(remoteCode), NULL);

	//����Զ������
	RemoteData remoteData(dllPath, pi.hProcess, entryPoint, isTraceless);
	WriteProcessMemory(pi.hProcess, dataAddress, &remoteData, sizeof(remoteData), NULL);

	//������ڵ�HOOK����
#ifdef _WIN64
	char hookCode[HOOK_CODE]
	{
		(char)0x48,(char)0xB8, // mov rax,��ڵ�
		(char)0x00,(char)0x00,(char)0x00,(char)0x00,
		(char)0x00,(char)0x00,(char)0x00,(char)0x00,
		(char)0x50,  //push rax
		(char)0x48,(char)0xB8, // mov rax,Ŀ���ַ
		(char)0x00,(char)0x00,(char)0x00,(char)0x00,
		(char)0x00,(char)0x00,(char)0x00,(char)0x00,
		(char)0xFF,(char)0xE0  //jmp rax
	};
	LPVOID* adrPtr = (LPVOID*)(hookCode + 2);
	*adrPtr = entryPoint;
	adrPtr = (LPVOID*)(hookCode + 13);
	*adrPtr = memAddress;
#else
	char hookCode[HOOK_CODE]
	{
		(char)0x68, // push ��ڵ�
		(char)0x00,(char)0x00,(char)0x00,(char)0x00,
		(char)0xE9, // jmp ��ת����
		(char)0x00,(char)0x00,(char)0x00,(char)0x00
	};
	unsigned* adrPtr = (unsigned*)(hookCode + 1);
	*adrPtr = (unsigned)entryPoint;
	adrPtr = (unsigned*)(hookCode + 6);
	*adrPtr = (unsigned)memAddress - (unsigned)entryPoint - 10;
#endif
	DWORD oldProtect;
	VirtualProtectEx(pi.hProcess, entryPoint, HOOK_CODE, PAGE_EXECUTE_READWRITE, &oldProtect);
	WriteProcessMemory(pi.hProcess, entryPoint, hookCode, HOOK_CODE, NULL);
	VirtualProtectEx(pi.hProcess, entryPoint, HOOK_CODE, oldProtect, &oldProtect);

	//�������߳�
	ResumeThread(pi.hThread);

	//������
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	return 0;
}


////�޺�ע��

//PEB�޺�ע�루Ӧ�ò��޺ۣ�

//PEB�� ģ����Ϣ�ṹ��
typedef struct _LDR_DATA_TABLE_ENTRY_NEW {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	DWORD_PTR SizeOfImage;
	UNICODE_STRING FullDllName;
	BYTE Reserved4[8];
	PVOID Reserved5[3];
#pragma warning(push)
#pragma warning(disable: 4201) // we'll always use the Microsoft compiler
	union {
		ULONG CheckSum;
		PVOID Reserved6;
	} DUMMYUNIONNAME;
#pragma warning(pop)
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY_NEW, * PLDR_DATA_TABLE_ENTRY_NEW;

//NtQueryInformationProcess����ָ�붨��
typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(
	HANDLE           ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID            ProcessInformation,
	ULONG            ProcessInformationLength,
	PULONG           ReturnLength
	);

//PEB�޺۴���
int Htd::Injection::TracelessByPEB(const char* moduleName)
{
	//��ȡNtQueryInformationProcess����
	HMODULE hModule = LoadLibraryA("Ntdll.dll");
	if (!hModule)return -1;
	_NtQueryInformationProcess ntQueryInformationProcess =
		(_NtQueryInformationProcess)GetProcAddress(hModule, "NtQueryInformationProcess");

	//��ȡPEB
	PROCESS_BASIC_INFORMATION pbi;
	NTSTATUS status = ntQueryInformationProcess(
		GetCurrentProcess(),
		PROCESSINFOCLASS::ProcessBasicInformation,
		&pbi,
		sizeof(pbi),
		NULL);
	if (!NT_SUCCESS(status))return -1;
	FreeLibrary(hModule);

	//Ĩ��PEB�е�ģ����Ϣ
	PPEB_LDR_DATA ldr = pbi.PebBaseAddress->Ldr;
	PLIST_ENTRY first = &ldr->InMemoryOrderModuleList;
	PLIST_ENTRY current = first->Flink;
	PLDR_DATA_TABLE_ENTRY_NEW p{};
	DWORD offset = (DWORD)(&p->InMemoryOrderLinks);
	hModule = GetModuleHandleA(moduleName);//Ҫ�޺۵�ģ��
	while (first != current)
	{
		PLDR_DATA_TABLE_ENTRY_NEW moduleInfo =
			(PLDR_DATA_TABLE_ENTRY_NEW)((DWORD_PTR)current - offset);
		if (moduleInfo->DllBase == hModule)
		{
			if (moduleInfo->InLoadOrderLinks.Flink && moduleInfo->InLoadOrderLinks.Blink)
			{
				moduleInfo->InLoadOrderLinks.Flink->Blink = moduleInfo->InLoadOrderLinks.Blink;
				moduleInfo->InLoadOrderLinks.Blink->Flink = moduleInfo->InLoadOrderLinks.Flink;
			}
			if (moduleInfo->InMemoryOrderLinks.Flink && moduleInfo->InMemoryOrderLinks.Blink)
			{
				moduleInfo->InMemoryOrderLinks.Flink->Blink = moduleInfo->InMemoryOrderLinks.Blink;
				moduleInfo->InMemoryOrderLinks.Blink->Flink = moduleInfo->InMemoryOrderLinks.Flink;
			}
			if (moduleInfo->InInitializationOrderLinks.Flink && moduleInfo->InInitializationOrderLinks.Blink)
			{
				moduleInfo->InInitializationOrderLinks.Flink->Blink = moduleInfo->InInitializationOrderLinks.Blink;
				moduleInfo->InInitializationOrderLinks.Blink->Flink = moduleInfo->InInitializationOrderLinks.Flink;
			}
			break;
		}
		current = current->Flink;
	}
	return 0;
}


//�����ڴ��е�PE�����루��ֹ�ڴ��������ɱ��
int Htd::Injection::TracelessByMemory(const char* moduleName)
{
	//����PE�����뷶Χ
	HMODULE hModule = GetModuleHandleA(moduleName);//Ҫ�����������ģ��
	if (!hModule)return -1;
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
	DWORD clearSize = dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS);
	//����PE�����루dosͷ+�м�����+ntͷ��
	DWORD oldProtect;
	VirtualProtect(dosHeader, clearSize, PAGE_READWRITE, &oldProtect);
	memset(dosHeader, 0, clearSize);
	VirtualProtect(dosHeader, clearSize, oldProtect, &oldProtect);
	return 0;
}
