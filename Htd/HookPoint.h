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
	char oldCode;//�ɴ���
	char fixCode[0x1F];
#ifdef _WIN64
	void* fixAdr;//�޸��������ת��ַ
	void* jmpAdr;//��ת��ȥ�ĵ�ַ
#endif
	void* retAdr;//�û�ָ���ķ��ص�ַ
	BOOL  isOnce;//�Ƿ�һ���Ե�
};


//CPU HookPoint 

typedef struct CPUHookPoint
{
	void* address;
	HookProc hookProc;
	void* retAdr;
	BOOL  isOnce;
}*PCPUHookPoint;

