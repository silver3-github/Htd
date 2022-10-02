#pragma once
#include <windows.h>


namespace Htd
{
	/// <summary>
	/// 注入类，用于给指定进程注入模块
	/// </summary>
	class Injection
	{
		//单例：
		Injection() {};
		~Injection() {};
	public:
		static Injection Instance;

		//功能：
	public:
		/// <summary>
		/// 通过windows hook 注入模块
		/// </summary>
		/// <param name="threadId">目标程序 线程ID</param>
		/// <param name="dllFileName">要注入的模块，里面必须包含名为 "WinHookProc" 的钩子处理函数（要求导出）</param>
		/// <param name="idHook">给 目标程序 设置的钩子类型（默认 WH_KEYBOARD）</param>
		/// <returns>
		/// <para>成功返回 0 </para>
		/// <para>失败返回 错误代码：</para>
		/// <para>-1  未找到目标程序</para>
		/// <para>-2  未找到注入模块</para>
		/// <para>-3  未找到"WinHookProc"钩子处理函数</para>
		/// <para>-4  设置钩子失败</para>
		/// </returns>
		int InjectByWinHook(unsigned threadId, const char* dllFileName, int idHook = WH_KEYBOARD);
		/// <summary>
		/// 通过windows hook 注入模块
		/// </summary>
		/// <param name="className">目标程序 窗口类名</param>
		/// <param name="windowName">目标程序 窗口标题</param>
		/// <param name="dllFileName">要注入的模块，里面必须包含名为 "WinHookProc" 的钩子处理函数（要求导出）</param>
		/// <param name="idHook">给 目标程序 设置的钩子类型（默认 WH_KEYBOARD）</param>
		/// <returns>
		/// <para>成功返回 0 </para>
		/// <para>失败返回 错误代码：</para>
		/// <para>-1  未找到目标程序</para>
		/// <para>-2  未找到注入模块</para>
		/// <para>-3  未找到"WinHookProc"钩子处理函数</para>
		/// <para>-4  设置钩子失败</para>
		/// </returns>
		int InjectByWinHook(const char* className, const char* windowName, const char* dllFileName, int idHook = WH_KEYBOARD);
		/// <summary>
		/// 通过 程序入口点 注入模块
		/// </summary>
		/// <param name="exePath">目标程序 完整文件路径</param>
		/// <param name="cmdline">启动目标程序 传入的命令行参数</param>
		/// <param name="dllPath">要注入的模块路径</param>
		/// <param name="isTraceless">
		/// <para>是否进行驱动层无痕处理（默认 false）</para>
		/// <para>注意：如果dll在全局对象初始化或dllmain里分配了堆区内存，无痕后运行可能会奔溃</para>
		/// </param>
		/// <returns>
		/// <para>成功返回 0 </para>
		/// <para>失败返回 错误代码：</para>
		/// <para>-1  启动目标程序失败</para>
		/// <para>-2  给目标进程分配内存失败</para>
		/// </returns>
		int InjectByEntryPoint(const char* exePath, char* cmdline, const char* dllPath,bool isTraceless=false);
		/// <summary>
		/// 基于PEB（应用层）抹除 当前进程中 指定模块的信息
		/// </summary>
		/// <param name="moduleName">要无痕的模块名</param>
		/// <returns>成功返回 0 失败返回 -1（获取PEB信息失败）</returns>
		int TracelessByPEB(const char* moduleName);
		/// <summary>
		/// 基于抹除模块内存特征码 实现内存无痕
		/// </summary>
		/// <param name="moduleName">要无痕的模块名</param>
		/// <returns>成功返回 0 失败返回 -1（模块不存在）</returns>
		int TracelessByMemory(const char* moduleName);
	};
}


