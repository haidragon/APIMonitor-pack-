// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "stdafx.h"

extern"C" __declspec(dllexport) void _stdcall Test();

extern HANDLE			g_hPipe1;
extern HANDLE			g_hPipe2;
extern lpModInfo		g_lpModList;

extern DWORD			dwObjectModBaseStart;
extern DWORD			dwObjectModBaseEnd;
extern DWORD			dwSelfModBaseStart;
extern DWORD			dwSelfModBaseEnd;

extern HWND				hDlg;

//////////////////////////////////////////////////////////////////////////
//	Detour注入需要Dll有一个导出函数才行
//////////////////////////////////////////////////////////////////////////
void _stdcall Test(){}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{

	DWORD	dwProcessID;
	WCHAR	szNamePipe_1[MAX_PATH] = { 0 };
	WCHAR	szNamePipe_2[MAX_PATH] = { 0 };
	BOOL	bStartedHook;
	HANDLE	hThread[2];
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:

		if (CreateSSMapFile() == FALSE)
		{
			
			return TRUE;
		}

		bStartedHook = GetHookModel();


		DetourRestoreAfterWith();
		//hDlg =  FindWindow(NULL, L"APIMonitor");
		//if (hDlg == NULL)
		//{
		//	MessageBox(NULL, L"FindWindows Failed!", NULL, NULL);
		//	return FALSE;
		//}
		OutputDebugString(L"[DLL]进入初始化");
		//处理命名管道的名称
		dwProcessID = GetCurrentProcessId();
		wsprintf(szNamePipe_1, L"\\\\.\\pipe\\NamePipe_APIMonitor_1");
		wsprintf(szNamePipe_2, L"\\\\.\\pipe\\NamePipe_APIMonitor_2");

		OutputDebugString(L"[DLL]管道名称处理成功");
		//连接命名管道，做一些连接失败的预处理
		g_hPipe1 = ConnectToNamePipe(szNamePipe_1);	//处理指令线程
		g_hPipe2 = ConnectToNamePipe(szNamePipe_2);	//主线程

		OutputDebugString(L"[DLL]管道连接成功");
		if (!g_hPipe1 || !g_hPipe2)	return FALSE;

		//两个管道建立好连接后，在打开线程进行一个管道的通信测试

		hThread[0] = CreateThread(NULL, NULL, ThreadProc, (LPVOID)g_hPipe1, NULL, NULL);
	//	hThread[1] = CreateThread(NULL, NULL, ThreadProc2, (LPVOID)g_hPipe2, NULL, NULL);

		if (!hThread[0] || !hThread[1])	return FALSE;

		OutputDebugString(L"[DLL]创建线程连接成功");

		//为模块列表申请空间
		g_lpModList = (lpModInfo)VirtualAlloc(NULL, LIST_INC * sizeof(ModInfo), MEM_COMMIT, PAGE_READWRITE);
		if (!g_lpModList) return 0;
		ZeroMemory(g_lpModList, LIST_INC * sizeof(ModInfo));
		

		//获取自身模块和目标宿主模块的范围
		dwObjectModBaseStart = (DWORD) GetModuleHandle(NULL);
		dwObjectModBaseEnd = ((PIMAGE_NT_HEADERS)(((PIMAGE_DOS_HEADER)dwObjectModBaseStart)->e_lfanew + dwObjectModBaseStart))->OptionalHeader.SizeOfImage + dwObjectModBaseStart;

		dwSelfModBaseStart = (DWORD)hModule;
		dwSelfModBaseEnd = ((PIMAGE_NT_HEADERS)(((PIMAGE_DOS_HEADER)dwSelfModBaseStart)->e_lfanew + dwSelfModBaseStart))->OptionalHeader.SizeOfImage + dwSelfModBaseStart;

		if (bStartedHook)
		{
			ScanModule();
		}
		else
		{
			ScanModule2();
		}

	/*	if (ScanModule() == TRUE)
			OutputDebugString(L"ScanModule成功返回");*/

		break;

	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:

		//卸载钩子
		UnHookAllApi();
		//释放list空间
		FreeListMemory();
		//中断通信
		CloseHandle(g_hPipe1);
		CloseHandle(g_hPipe2);

		break;
	}
	return TRUE;
}

