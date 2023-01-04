#include "HookEngine.h"
#include <tlhelp32.h>


//���嵥������

Htd::HookEngine Htd::HookEngine::Instance;


//HookEngine ����

Htd::HookEngine::HookEngine()
{
	memset(CPUhookPoints, 0, sizeof(CPUhookPoints));
	handler = AddVectoredExceptionHandler(1, ExceptionHandler);
}


//HookEngine ����

Htd::HookEngine::~HookEngine()
{
	//ж�� ����int3 Hook
	std::map<void*, std::shared_ptr<HookPoint>>::iterator i = hookPoints.begin();
	while (i != hookPoints.end())
	{
		UnloadHook(i++->first);
	}

	//ж�� ����CPU Hook
	for (int i = 0; i < 4; i++)
	{
		UnloadCPUHook(i);
	}

	//ж�� 1�����쳣�������
	if (handler)RemoveVectoredExceptionHandler(handler);
}


//1�� �쳣������� �ַ�����Ӧ2�������������ص�ַ

long __stdcall Htd::HookEngine::ExceptionHandler(PEXCEPTION_POINTERS Info)
{
	//��ȡ������
#ifdef _WIN64
	DWORD_PTR* pEip = &Info->ContextRecord->Rip;
#else
	DWORD_PTR* pEip = &Info->ContextRecord->Eip;
#endif

	//INT3 hook�㴦��
	if (Info->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT)
	{
		//��ȡHookPoint����
		std::map<void*, std::shared_ptr<HookPoint>>::iterator  it;
		it = Instance.hookPoints.find((void*)*pEip);

		if (it != Instance.hookPoints.end()) //��ȡ�ɹ�����
		{
			if (it->second->hookProc(Info->ContextRecord))
			{
				*pEip = (DWORD_PTR)it->second->fixCode;
				if (it->second->isOnce)*pEip = (DWORD_PTR)it->second->address;
			}
			else
				*pEip = (DWORD_PTR)it->second->retAdr;
			if (it->second->isOnce)Instance.UnloadHook(it->second->address);//һ���Դ���
			return EXCEPTION_CONTINUE_EXECUTION;
		}
		else //��ȡʧ�ܴ���
		{
			return EXCEPTION_CONTINUE_SEARCH;
		}
	}

	//CPU�ϵ� hook�㴦��
	if (Info->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
	{
		//��ȡHookPoint����
		PCPUHookPoint hookPoint = nullptr;
		for (int i = 0; i < 4; i++)
		{
			if (Instance.CPUhookPoints[i].address == (void*)*pEip)
			{
				hookPoint = &Instance.CPUhookPoints[i];
				break;
			}
		}

		//����Hook
		if (hookPoint)
		{
			if (hookPoint->hookProc(Info->ContextRecord))
			{
				Info->ContextRecord->EFlags |= 1 << 16;// RF ��1
			}
			else
			{
				if (hookPoint->retAdr == (void*)*pEip)
					Info->ContextRecord->EFlags |= 1 << 16;// RF ��1
				else
					*pEip = (DWORD_PTR)hookPoint->retAdr;
			}
			if (hookPoint->isOnce)Instance.UnloadCPUHook(hookPoint->address);//һ���Դ���
			return EXCEPTION_CONTINUE_EXECUTION;
		}
		return EXCEPTION_CONTINUE_SEARCH;
	}

	return EXCEPTION_CONTINUE_SEARCH;
}


//���� int3 Hook

void Htd::HookEngine::SetHook(void* address, unsigned len, HookProc hookProc, void* retAdr, BOOL isOnce)
{
	//����HookPoint����
	hookPoints[address] = std::shared_ptr<HookPoint>(new HookPoint(address, len, hookProc, retAdr, isOnce));

	//����Hook
	DWORD oldProtect;
	VirtualProtect(address, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
	char* order = (char*)address;
	order[0] = 0xCC;//int3
	VirtualProtect(address, 1, oldProtect, &oldProtect);
}


//ж�� int3 Hook

void Htd::HookEngine::UnloadHook(void* address)
{
	std::map<void*, std::shared_ptr<HookPoint>>::iterator it;
	it = hookPoints.find(address);
	if (it != hookPoints.end())
	{
		//ɾ��hook����ԭ����
		DWORD oldProtect;
		VirtualProtect(address, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
		char* order = (char*)address;
		order[0] = it->second->oldCode;
		VirtualProtect(address, 1, oldProtect, &oldProtect);

		//ɾ��HookPoint����
		hookPoints.erase(address);
	}
}


//���� CPU Hook

void Htd::HookEngine::SetCPUHook(unsigned index, void* address, HookProc hookProc, void* retAdr, BOOL isOnce)
{
	if (index < 4) // index 0 - 3 ��������
	{
		//����HookPoint����
		CPUhookPoints[index] = { address,hookProc,retAdr,isOnce };

		//����Hook
		HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		THREADENTRY32 te32{ sizeof(THREADENTRY32) };
		Thread32First(hThreadSnap, &te32);
		DWORD  processId = GetCurrentProcessId();
		do 
		{
			if (te32.th32OwnerProcessID == processId)
			{
				HANDLE hThread=OpenThread(THREAD_GET_CONTEXT| THREAD_SET_CONTEXT, false, te32.th32ThreadID);
				if (hThread == NULL)continue;
				CONTEXT CPU;
				CPU.ContextFlags = CONTEXT_DEBUG_REGISTERS;
				GetThreadContext(hThread, &CPU);
				switch (index)
				{
				case 0:
					CPU.Dr0 = (DWORD_PTR)address;
					CPU.Dr7 |= 1;//���� dr0
					break;
				case 1:
					CPU.Dr1 = (DWORD_PTR)address;
					CPU.Dr7 |= 4;//���� dr1
					break;
				case 2:
					CPU.Dr2 = (DWORD_PTR)address;
					CPU.Dr7 |= 16;//���� dr2
					break;
				case 3:
					CPU.Dr3 = (DWORD_PTR)address;
					CPU.Dr7 |= 64;//���� dr3
					break;
				}
				SetThreadContext(hThread, &CPU);
				CloseHandle(hThread);
				hThread = NULL;
			}
		}while(Thread32Next(hThreadSnap, &te32));
		CloseHandle(hThreadSnap);
	}
}


//ж�� CPU Hook

void Htd::HookEngine::UnloadCPUHook(unsigned index)
{
	if (index < 4) // index 0 - 3 ����ж��
	{
		//���HookPoint����
		CPUhookPoints[index] = { 0,0,0,0 };

		//ɾ��Hook
		HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		THREADENTRY32 te32{ sizeof(THREADENTRY32) };
		Thread32First(hThreadSnap, &te32);
		DWORD  processId = GetCurrentProcessId();
		do
		{
			if (te32.th32OwnerProcessID == processId)
			{
				HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, false, te32.th32ThreadID);
				if (hThread == NULL)continue;
				CONTEXT CPU;
				CPU.ContextFlags = CONTEXT_DEBUG_REGISTERS;
				GetThreadContext(hThread, &CPU);
				switch (index)
				{
				case 0:
					CPU.Dr0 = 0;
					CPU.Dr7 &= ~(DWORD_PTR)1;//���� dr0
					break;
				case 1:
					CPU.Dr1 = 0;
					CPU.Dr7 &= ~(DWORD_PTR)4;//���� dr1
					break;
				case 2:
					CPU.Dr2 = 0;
					CPU.Dr7 &= ~(DWORD_PTR)16;//���� dr2
					break;
				case 3:
					CPU.Dr3 = 0;
					CPU.Dr7 &= ~(DWORD_PTR)64;//���� dr3
					break;
				}
				SetThreadContext(hThread, &CPU);
				CloseHandle(hThread);
				hThread = NULL;
			}
		} while (Thread32Next(hThreadSnap, &te32));
		CloseHandle(hThreadSnap);
	}
}

void Htd::HookEngine::UnloadCPUHook(void* address)
{
	for (int i = 0; i < 4; i++)
	{
		if (CPUhookPoints[i].address == address)
		{
			UnloadCPUHook(i);
		}
	}
}