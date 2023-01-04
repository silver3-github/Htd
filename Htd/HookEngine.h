#pragma once
#include <map>
#include <memory>
#include "HookPoint.h"


namespace Htd {

	/// <summary>
	/// Hook�����࣬���ڿ�������Hook
	/// </summary>
	class HookEngine
	{
		//������
		HookEngine();
		~HookEngine();
	public:
		static HookEngine Instance;

		//�ڲ�ʵ�֣�
	private:
		HANDLE handler;
		static long __stdcall ExceptionHandler(PEXCEPTION_POINTERS Info);//1�� �쳣������� �ַ�����Ӧ2�������������ص�ַ
		std::map<void*, std::shared_ptr<HookPoint>> hookPoints;//int3 hook��
		CPUHookPoint CPUhookPoints[4];//CPU�ϵ㣨Ӳ���ϵ㣩 hook��

		//���ܣ�
	public:
		/// <summary>
		/// ���� �ڴ�INT3 hook
		/// </summary>
		/// <param name="address">����hook�ĵ�ַ</param>
		/// <param name="len">ָ���</param>
		/// <param name="hookProc">�û���������return true ԭ������/false ָ����ַ���أ�</param>
		/// <param name="retAdr">ָ���ķ��ص�ַ</param>
		/// <param name="isOnce">�Ƿ�Ϊ һ���Ե�hook</param>
		void SetHook(void* address, unsigned len, HookProc hookProc, void* retAdr = nullptr, BOOL isOnce = false);
		/// <summary>
		/// ж�� �ڴ�INT3 hook
		/// </summary>
		/// <param name="address">hook��ĵ�ַ</param>
		void UnloadHook(void* address);
		/// <summary>
		/// ���� CPU �޺�Hook�����4��,��ǰ�����߳����ã�
		/// </summary>
		/// <param name="index">�޺�Hook��������0 - 4����������Ч���ظ������򸲸�</param>
		/// <param name="address">����hook�ĵ�ַ</param>
		/// <param name="hookProc">�û���������return true ԭ������/false ָ����ַ���أ�</param>
		/// <param name="retAdr">ָ���ķ��ص�ַ</param>
		/// <param name="isOnce">�Ƿ�Ϊ һ���Ե�hook</param>
		void SetCPUHook(unsigned index, void* address, HookProc hookProc, void* retAdr = nullptr, BOOL isOnce = false);
		/// <summary>
		/// ж�� CPU �޺�Hook
		/// </summary>
		/// <param name="index">Ҫж�ص� �޺�Hook������</param>
		void UnloadCPUHook(unsigned index);
		/// <summary>
		/// ж�� CPU �޺�Hook
		/// </summary>
		/// <param name="address">Ҫж�ص� �޺�Hook�ĵ�ַ</param>
		void UnloadCPUHook(void* address);
	};
}

