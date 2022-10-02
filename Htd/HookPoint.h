#pragma once
#include <windows.h>

typedef bool(*HookProc)(PCONTEXT CPU);

//INT3 HookPoint

class HookPoint
{
public:
	HookPoint(void* address, unsigned len, HookProc hookProc, void* retAdr, BOOL  isOnce);

	void* address;
	HookProc hookProc;
	char oldCode;//旧代码
	char fixCode[0x1F];
#ifdef _WIN64
	void* fixAdr;//修复代码的跳转地址
	void* jmpAdr;//跳转回去的地址
#endif
	void* retAdr;//用户指定的返回地址
	BOOL  isOnce;//是否一次性的
};


//CPU HookPoint 

typedef struct CPUHookPoint
{
	void* address;
	HookProc hookProc;
	void* retAdr;
	BOOL  isOnce;
}*PCPUHookPoint;

