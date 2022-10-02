#include <iostream>
#include <Shlobj.h>
#include <io.h>
#include <direct.h>
#include <windows.h>


int main()
{
	//激活Htd环境变量
	HKEY hkey;
	long result = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
		"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment",
		0, KEY_ALL_ACCESS, &hkey);
	if (result != ERROR_SUCCESS)
	{
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 4);//设置红色
		std::cout << "激活Htd环境变量失败！请用管理员权限运行程序！\r\nHtd库激活失败！" << std::endl;
		system("Pause");
		return 0;
	}

	int count = 0;
	char htdPath[MAX_PATH]{};
	GetModuleFileNameA(NULL, htdPath, MAX_PATH);
	for (int i = MAX_PATH - 1; i > -1; i--)
	{
		if (htdPath[i] == '\\') {
			count = i;
			htdPath[i] = '\0';
			break;
		}
	}
#ifdef _WIN64
	result = RegSetValueExA(hkey, "HtdX64", 0, REG_SZ, (const BYTE*)htdPath, count + 1);
#else
	result = RegSetValueExA(hkey, "HtdX32", 0, REG_SZ, (const BYTE*)htdPath, count + 1);
#endif
	if (result != ERROR_SUCCESS)
	{
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 4);//设置红色
		std::cout << "激活Htd环境变量失败！请用管理员权限运行程序！\r\nHtd库激活失败！" << std::endl;
		system("Pause");
		RegCloseKey(hkey);
		return 0;
	}
	RegCloseKey(hkey);

	SendMessageTimeoutA(HWND_BROADCAST, WM_SETTINGCHANGE, 0,
		(LPARAM)"Environment", SMTO_ABORTIFHUNG, 5000, (PDWORD_PTR)&result);
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 2);//设置绿色
	std::cout << "Htd环境变量激活成功！\r\nHtd库激活成功！" << std::endl;


	//检测模板安装环境(Visual Studio 2019)
	char documentPath[MAX_PATH]{};
	result = SHGetFolderPathA(NULL, CSIDL_MYDOCUMENTS, NULL, SHGFP_TYPE_CURRENT, documentPath);
	if (result != S_OK)
	{
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 4);//设置红色
		std::cout << "获取“我的文档”路径失败！\r\nHtd项目模板激活失败！" << std::endl;
		system("Pause");
		return 0;
	}

	std::string templatePath = documentPath;
	templatePath += "\\Visual Studio 2019\\";
	if (_access(templatePath.c_str(), 0) == -1)
	{
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 4);//设置红色
		std::cout << "未安装Visual Studio 2019！\r\nHtd项目模板激活失败！" << std::endl;
		system("Pause");
		return 0;
	}
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 2);//设置绿色
	std::cout << "检测环境通过：已安装Visual Studio 2019" << std::endl;


	//激活Htd项目模板
	std::string templateDir[3]{ "Templates\\","ProjectTemplates\\","Visual C++\\" };
	for (int i = 0; i < 3; i++)
	{
		templatePath += templateDir[i];
		if (_access(templatePath.c_str(), 0) == -1) {
			int ret = _mkdir(templatePath.c_str());
		}
	}

	std::string htdTemplate[2] //新增的模板添加到这
	{
		"HtdMfc.zip",
		"HtdMfcDll.zip"
	};

	for (int i = 0; i < sizeof(htdTemplate) / sizeof(std::string); i++)
	{
		std::string existingFile = htdPath + (std::string)"\\" + htdTemplate[i];
		std::string newFile = templatePath + htdTemplate[i];
		if (CopyFileA(existingFile.c_str(), newFile.c_str(), false))
		{
			SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 2);//设置绿色
			std::cout << htdTemplate[i] + " 项目模板导入成功！" << std::endl;
		}
		else
		{
			SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 4);//设置红色
			std::cout << htdTemplate[i] + " 项目模板导入失败！" << std::endl;
			std::cout << "Htd项目模板激活失败！" << std::endl;
			system("Pause");
			return 0;
		}
	}
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 2);//设置绿色
	std::cout << "Htd项目模板激活成功！" << std::endl;
	system("Pause");
	return 0;

}
