#pragma once
#include <windows.h>


namespace Htd
{
	/// <summary>
	/// ע���࣬���ڸ�ָ������ע��ģ��
	/// </summary>
	class Injection
	{
		//������
		Injection() {};
		~Injection() {};
	public:
		static Injection Instance;

		//���ܣ�
	public:
		/// <summary>
		/// ͨ��windows hook ע��ģ��
		/// </summary>
		/// <param name="threadId">Ŀ����� �߳�ID</param>
		/// <param name="dllFileName">Ҫע���ģ�飬������������Ϊ "WinHookProc" �Ĺ��Ӵ�������Ҫ�󵼳���</param>
		/// <param name="idHook">�� Ŀ����� ���õĹ������ͣ�Ĭ�� WH_KEYBOARD��</param>
		/// <returns>
		/// <para>�ɹ����� 0 </para>
		/// <para>ʧ�ܷ��� ������룺</para>
		/// <para>-1  δ�ҵ�Ŀ�����</para>
		/// <para>-2  δ�ҵ�ע��ģ��</para>
		/// <para>-3  δ�ҵ�"WinHookProc"���Ӵ�����</para>
		/// <para>-4  ���ù���ʧ��</para>
		/// </returns>
		int InjectByWinHook(unsigned threadId, const char* dllFileName, int idHook = WH_KEYBOARD);
		/// <summary>
		/// ͨ��windows hook ע��ģ��
		/// </summary>
		/// <param name="className">Ŀ����� ��������</param>
		/// <param name="windowName">Ŀ����� ���ڱ���</param>
		/// <param name="dllFileName">Ҫע���ģ�飬������������Ϊ "WinHookProc" �Ĺ��Ӵ�������Ҫ�󵼳���</param>
		/// <param name="idHook">�� Ŀ����� ���õĹ������ͣ�Ĭ�� WH_KEYBOARD��</param>
		/// <returns>
		/// <para>�ɹ����� 0 </para>
		/// <para>ʧ�ܷ��� ������룺</para>
		/// <para>-1  δ�ҵ�Ŀ�����</para>
		/// <para>-2  δ�ҵ�ע��ģ��</para>
		/// <para>-3  δ�ҵ�"WinHookProc"���Ӵ�����</para>
		/// <para>-4  ���ù���ʧ��</para>
		/// </returns>
		int InjectByWinHook(const char* className, const char* windowName, const char* dllFileName, int idHook = WH_KEYBOARD);
		/// <summary>
		/// ͨ�� ������ڵ� ע��ģ��
		/// </summary>
		/// <param name="exePath">Ŀ����� �����ļ�·��</param>
		/// <param name="cmdline">����Ŀ����� ����������в���</param>
		/// <param name="dllPath">Ҫע���ģ��·��</param>
		/// <param name="isTraceless">
		/// <para>�Ƿ�����������޺۴���Ĭ�� false��</para>
		/// <para>ע�⣺���dll��ȫ�ֶ����ʼ����dllmain������˶����ڴ棬�޺ۺ����п��ܻᱼ��</para>
		/// </param>
		/// <returns>
		/// <para>�ɹ����� 0 </para>
		/// <para>ʧ�ܷ��� ������룺</para>
		/// <para>-1  ����Ŀ�����ʧ��</para>
		/// <para>-2  ��Ŀ����̷����ڴ�ʧ��</para>
		/// </returns>
		int InjectByEntryPoint(const char* exePath, char* cmdline, const char* dllPath,bool isTraceless=false);
		/// <summary>
		/// ����PEB��Ӧ�ò㣩Ĩ�� ��ǰ������ ָ��ģ�����Ϣ
		/// </summary>
		/// <param name="moduleName">Ҫ�޺۵�ģ����</param>
		/// <returns>�ɹ����� 0 ʧ�ܷ��� -1����ȡPEB��Ϣʧ�ܣ�</returns>
		int TracelessByPEB(const char* moduleName);
		/// <summary>
		/// ����Ĩ��ģ���ڴ������� ʵ���ڴ��޺�
		/// </summary>
		/// <param name="moduleName">Ҫ�޺۵�ģ����</param>
		/// <returns>�ɹ����� 0 ʧ�ܷ��� -1��ģ�鲻���ڣ�</returns>
		int TracelessByMemory(const char* moduleName);
	};
}


