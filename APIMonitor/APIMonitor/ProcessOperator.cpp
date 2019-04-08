// ProcessOperator.cpp : 实现文件
//

#include "stdafx.h"
#include "APIMonitor.h"
#include "ProcessOperator.h"
#include "afxdialogex.h"


// CProcessOperator 对话框
IMPLEMENT_DYNAMIC(CProcessOperator, CDialogEx)

CProcessOperator::CProcessOperator(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_DIALOG_PROC, pParent)
{
}

CProcessOperator::~CProcessOperator()
{
}

void CProcessOperator::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(CProcessOperator, CDialogEx)
	ON_BN_CLICKED(IDC_BUTTON_OK, &CProcessOperator::OnBnClickedButtonOK)
	ON_BN_CLICKED(IDC_BUTTON_OPEN, &CProcessOperator::OnBnClickedButtonOpen)
END_MESSAGE_MAP()


// CProcessOperator 消息处理程序


void CProcessOperator::OnBnClickedButtonOK()
{
	// TODO: 在此添加控件通知处理程序代码
	CString				stcArguments;
	CString				stcPath;
	CString				stcStartDir;
	STARTUPINFO			si;
	PROCESS_INFORMATION pi;
	WCHAR*				szDirPath = new WCHAR[MAX_PATH];
	WCHAR*				szConfig = new WCHAR[MAX_PATH];
	CHAR				szDllName[MAX_PATH] = { 0 };
	BOOL				bInjected;
	HANDLE				hFile;
	DWORD				dwNumOfBytesWritten;


	ZeroMemory(&si, sizeof(STARTUPINFO));
	ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
	si.cb = sizeof(STARTUPINFO);

	bStartedHook =  ((CButton*)(this->GetDlgItem(IDC_CHECK_START)))->GetCheck();

	this->GetDlgItemText(IDC_EDIT_ARG, stcArguments);
	this->GetDlgItemText(IDC_EDIT_DIR, stcStartDir);
	this->GetDlgItemText(IDC_EDIT_PROC, stcPath);

	wcscpy_s(szFile, stcPath);

	GetModuleFileName(NULL, szDirPath, MAX_PATH);
	PathRemoveFileSpec(szDirPath);
	BOOL bRootDir = PathIsRoot(szDirPath);
	if (bRootDir)
	{//若是根目录，不用加反斜杠
		wsprintf(szConfig, L"%s%s", szDirPath, L"Config.ini");
		wcscat_s(szDirPath, MAX_PATH, L"HookAPILibrary.dll");
	}
	else
	{
		wsprintf(szConfig, L"%s\\%s", szDirPath, L"Config.ini");
		wcscat_s(szDirPath, MAX_PATH, L"\\HookAPILibrary.dll");
	}


	hFile = CreateFile(szConfig, GENERIC_WRITE | GENERIC_READ,
		FILE_SHARE_READ, NULL, CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		MessageBox(L"CreateFile Failed", NULL, NULL);
		exit(0);
	}

	WriteFile(hFile, &bStartedHook, sizeof(BOOL), &dwNumOfBytesWritten, NULL);

	CloseHandle(hFile);

	WideCharToMultiByte(CP_ACP, NULL, szDirPath, -1, szDllName, _countof(szDllName), NULL, FALSE);

	//CreateProcess(stcPath, stcArguments.GetBuffer(),
	//	NULL, NULL, FALSE, CREATE_DEFAULT_ERROR_MODE, NULL, stcStartDir.GetBuffer(), &si, &pi);

	//dwFuncAddr = (DWORD)GetProcAddress(hMod, "LoadLibraryA");

	//dwAllocAddr = (DWORD)VirtualAllocEx(pi.hProcess, NULL, strlen(szDllName) + 1, MEM_COMMIT, PAGE_READWRITE);

	//WriteProcessMemory(pi.hProcess, (LPVOID)dwAllocAddr, szDllName, strlen(szDllName) + 1, &dwWriten);


	//CreateRemoteThread(pi.hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)dwFuncAddr, (LPVOID)dwAllocAddr, NULL, NULL);

	//要给出dll的绝对路径,以注入DLL启动目标进程
	//注意：注入的DLL一定要有一个导出函数
	bInjected = DetourCreateProcessWithDll(stcPath, stcArguments.GetBuffer(),
		NULL, NULL, FALSE, CREATE_DEFAULT_ERROR_MODE, NULL, stcStartDir.GetBuffer(), &si, &pi, szDllName, NULL);



	EndDialog(IDOK);
}


void CProcessOperator::OnBnClickedButtonOpen()
{
	// TODO: 在此添加控件通知处理程序代码
	CFileDialog stcFileDialog(TRUE, NULL, NULL, 6UL, L"Executable Files (*.exe)||");
	CString		stcPath;

	WCHAR		szDir[MAX_PATH];

	ZeroMemory(szDir, MAX_PATH);

	if (stcFileDialog.DoModal() == TRUE)
	{
		stcPath = stcFileDialog.GetPathName();
		this->SetDlgItemText(IDC_EDIT_PROC, stcPath);

		wcscpy_s(szDir, stcPath.GetBuffer());
		PathRemoveFileSpec(szDir);						//去除文件名，得到目录
		this->SetDlgItemText(IDC_EDIT_DIR, szDir);
	}


}