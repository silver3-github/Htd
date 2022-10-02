#pragma once
#include <map>
#include <memory>
#include "HookPoint.h"


namespace Htd {

	/// <summary>
	/// Hook引擎类，用于快速设置Hook
	/// </summary>
	class HookEngine
	{
		//单例：
		HookEngine();
		~HookEngine();
	public:
		static HookEngine Instance;

		//内部实现：
	private:
		HANDLE handler;
		static long __stdcall ExceptionHandler(PEXCEPTION_POINTERS Info);//1环 异常处理程序 分发到对应2环，并设置跳回地址
		std::map<void*, std::shared_ptr<HookPoint>> hookPoints;//int3 hook点
		CPUHookPoint CPUhookPoints[4];//CPU断点（硬件断点） hook点

		//功能：
	public:
		/// <summary>
		/// 设置 内存INT3 hook
		/// </summary>
		/// <param name="address">设置hook的地址</param>
		/// <param name="len">指令长度</param>
		/// <param name="hookProc">用户处理函数（return true 原处返回/false 指定地址返回）</param>
		/// <param name="retAdr">指定的返回地址</param>
		/// <param name="isOnce">是否为 一次性的hook</param>
		void SetHook(void* address, unsigned len, HookProc hookProc, void* retAdr = nullptr, BOOL isOnce = false);
		/// <summary>
		/// 卸载 内存INT3 hook
		/// </summary>
		/// <param name="address">hook点的地址</param>
		void UnloadHook(void* address);
		/// <summary>
		/// 设置 CPU 无痕Hook（最多4个,当前所有线程适用）
		/// </summary>
		/// <param name="index">无痕Hook的索引（0 - 4），超出无效，重复设置则覆盖</param>
		/// <param name="address">设置hook的地址</param>
		/// <param name="hookProc">用户处理函数（return true 原处返回/false 指定地址返回）</param>
		/// <param name="retAdr">指定的返回地址</param>
		/// <param name="isOnce">是否为 一次性的hook</param>
		void SetCPUHook(unsigned index, void* address, HookProc hookProc, void* retAdr = nullptr, BOOL isOnce = false);
		/// <summary>
		/// 卸载 CPU 无痕Hook
		/// </summary>
		/// <param name="index">要卸载的 无痕Hook的索引</param>
		void UnloadCPUHook(unsigned index);
		/// <summary>
		/// 卸载 CPU 无痕Hook
		/// </summary>
		/// <param name="address">要卸载的 无痕Hook的地址</param>
		void UnloadCPUHook(void* address);
	};
}

