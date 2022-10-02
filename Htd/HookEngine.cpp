#include "HookEngine.h"
#include <tlhelp32.h>


//定义单例对象

Htd::HookEngine Htd::HookEngine::Instance;


//HookEngine 构造

Htd::HookEngine::HookEngine()
{
	memset(CPUhookPoints, 0, sizeof(CPUhookPoints));
	handler = AddVectoredExceptionHandler(1, ExceptionHandler);
}


//HookEngine 析构

Htd::HookEngine::~HookEngine()
{
	//卸载 所有int3 Hook
	std::map<void*, std::shared_ptr<HookPoint>>::iterator i = hookPoints.begin();
	while (i != hookPoints.end())
	{
		UnloadHook(i++->first);
	}

	//卸载 所有CPU Hook
	for (int i = 0; i < 4; i++)
	{
		UnloadCPUHook(i);
	}

	//卸载 1环（异常处理程序）
	if (handler)RemoveVectoredExceptionHandler(handler);
}


//1环 异常处理程序 分发到对应2环，并设置跳回地址

long __stdcall Htd::HookEngine::ExceptionHandler(PEXCEPTION_POINTERS Info)
{
	//获取触发点
#ifdef _WIN64
	DWORD_PTR* pEip = &Info->ContextRecord->Rip;
#else
	DWORD_PTR* pEip = &Info->ContextRecord->Eip;
#endif

	//INT3 hook点处理
	if (Info->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT)
	{
		//获取HookPoint数据
		std::map<void*, std::shared_ptr<HookPoint>>::iterator  it;
		it = Instance.hookPoints.find((void*)*pEip);

		if (it != Instance.hookPoints.end()) //获取成功处理
		{
			if (it->second->hookProc(Info->ContextRecord))
			{
				*pEip = (DWORD_PTR)it->second->fixCode;
				if (it->second->isOnce)*pEip = (DWORD_PTR)it->second->address;
			}
			else
				*pEip = (DWORD_PTR)it->second->retAdr;
			if (it->second->isOnce)Instance.UnloadHook(it->second->address);//一次性处理
			return EXCEPTION_CONTINUE_EXECUTION;
		}
		else //获取失败处理
		{
			return EXCEPTION_CONTINUE_SEARCH;
		}
	}

	//CPU断点 hook点处理
	if (Info->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
	{
		//获取HookPoint数据
		PCPUHookPoint hookPoint = nullptr;
		for (int i = 0; i < 4; i++)
		{
			if (Instance.CPUhookPoints[i].address == (void*)*pEip)
			{
				hookPoint = &Instance.CPUhookPoints[i];
				break;
			}
		}

		//处理Hook
		if (hookPoint)
		{
			if (hookPoint->hookProc(Info->ContextRecord))
			{
				Info->ContextRecord->EFlags |= 1 << 16;// RF 置1
			}
			else
			{
				if (hookPoint->retAdr == (void*)*pEip)
					Info->ContextRecord->EFlags |= 1 << 16;// RF 置1
				else
					*pEip = (DWORD_PTR)hookPoint->retAdr;
			}
			if (hookPoint->isOnce)Instance.UnloadCPUHook(hookPoint->address);//一次性处理
			return EXCEPTION_CONTINUE_EXECUTION;
		}
		return EXCEPTION_CONTINUE_SEARCH;
	}

	return EXCEPTION_CONTINUE_SEARCH;
}


//设置 int3 Hook

void Htd::HookEngine::SetHook(void* address, unsigned len, HookProc hookProc, void* retAdr, BOOL isOnce)
{
	//保存HookPoint数据
	hookPoints[address] = std::shared_ptr<HookPoint>(new HookPoint(address, len, hookProc, retAdr, isOnce));

	//创建Hook
	DWORD oldProtect;
	VirtualProtect(address, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
	char* order = (char*)address;
	order[0] = 0xCC;//int3
	VirtualProtect(address, 1, oldProtect, &oldProtect);
}


//卸载 int3 Hook

void Htd::HookEngine::UnloadHook(void* address)
{
	std::map<void*, std::shared_ptr<HookPoint>>::iterator it;
	it = hookPoints.find(address);
	if (it != hookPoints.end())
	{
		//删除hook，还原代码
		DWORD oldProtect;
		VirtualProtect(address, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
		char* order = (char*)address;
		order[0] = it->second->oldCode;
		VirtualProtect(address, 1, oldProtect, &oldProtect);

		//删除HookPoint数据
		hookPoints.erase(address);
	}
}


//设置 CPU Hook

void Htd::HookEngine::SetCPUHook(unsigned index, void* address, HookProc hookProc, void* retAdr, BOOL isOnce)
{
	if (index < 4) // index 0 - 3 才能设置
	{
		//保存HookPoint数据
		CPUhookPoints[index] = { address,hookProc,retAdr,isOnce };

		//创建Hook
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
					CPU.Dr7 |= 1;//启用 dr0
					break;
				case 1:
					CPU.Dr1 = (DWORD_PTR)address;
					CPU.Dr7 |= 4;//启用 dr1
					break;
				case 2:
					CPU.Dr2 = (DWORD_PTR)address;
					CPU.Dr7 |= 16;//启用 dr2
					break;
				case 3:
					CPU.Dr3 = (DWORD_PTR)address;
					CPU.Dr7 |= 64;//启用 dr3
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


//卸载 CPU Hook

void Htd::HookEngine::UnloadCPUHook(unsigned index)
{
	if (index < 4) // index 0 - 3 才能卸载
	{
		//清除HookPoint数据
		CPUhookPoints[index] = { 0,0,0,0 };

		//删除Hook
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
					CPU.Dr7 &= ~(DWORD_PTR)1;//禁用 dr0
					break;
				case 1:
					CPU.Dr1 = 0;
					CPU.Dr7 &= ~(DWORD_PTR)4;//禁用 dr1
					break;
				case 2:
					CPU.Dr2 = 0;
					CPU.Dr7 &= ~(DWORD_PTR)16;//禁用 dr2
					break;
				case 3:
					CPU.Dr3 = 0;
					CPU.Dr7 &= ~(DWORD_PTR)64;//禁用 dr3
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