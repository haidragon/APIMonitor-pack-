
// APIMonitorDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "APIMonitor.h"
#include "APIMonitorDlg.h"
#include "afxdialogex.h"



//工作线程,接收DLL发送而来的数据，写入list
DWORD WINAPI ThreadProcOfWork(LPVOID lpPara);
//模拟主线程
DWORD  WINAPI ThreadProcMain(LPVOID lpPara);
//UI显示线程，将list中的数据显示在UI控件上
DWORD  WINAPI ThreadProcUI(LPVOID lpPara);



#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
	afx_msg LRESULT OnRecvmod(WPARAM wParam, LPARAM lParam);
//	afx_msg LRESULT OnTrapinfo(WPARAM wParam, LPARAM lParam);
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)


END_MESSAGE_MAP()


// CAPIMonitorDlg 对话框



CAPIMonitorDlg::CAPIMonitorDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_APIMONITOR_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CAPIMonitorDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_TREE_LIST, m_TreeShow);
	DDX_Control(pDX, IDC_LIST_TRAP, m_ListTrap);
	DDX_Control(pDX, IDC_TREE_API, m_TreeAPI);
	DDX_Control(pDX, IDC_EDIT_SHOW, m_LogEdit);
	DDX_Control(pDX, IDC_EDIT_FINDAPI, m_EditApi);
}

BEGIN_MESSAGE_MAP(CAPIMonitorDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_COMMAND(ID_PROC, &CAPIMonitorDlg::OnOpenProc)
	ON_MESSAGE(WM_RECVMODINFO, &CAPIMonitorDlg::OnRecvmodinfo)
	ON_MESSAGE(WM_REVCAPIINFO, &CAPIMonitorDlg::OnRevcapiinfo)
	ON_WM_COPYDATA()

	ON_NOTIFY(NM_CLICK, IDC_TREE_LIST, &CAPIMonitorDlg::OnNMClickTreeList)
	ON_NOTIFY(NM_CLICK, IDC_TREE_API, &CAPIMonitorDlg::OnNMClickTreeApi)
	ON_EN_CHANGE(IDC_EDIT_FINDAPI, &CAPIMonitorDlg::OnEnChangeEditFindapi)
	ON_MESSAGE(WM_TRAPINFO, &CAPIMonitorDlg::OnTrapinfo)
	ON_COMMAND(ID_SaveLog, &CAPIMonitorDlg::OnSavelog)
END_MESSAGE_MAP()


// CAPIMonitorDlg 消息处理程序

BOOL CAPIMonitorDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码
	m_Menu.LoadMenuW(IDR_MENU1);
	SetMenu(&m_Menu);

	//命名管道的前缀
	StrPipeName = L"\\\\.\\pipe\\NamePipe_APIMonitor";
	//为了传递到UI线程中调用操作类，申请指针
	m_lpProessing = new ProcessingList;

	CRect rect;

	// 获取编程语言列表视图控件的位置和大小   
	m_ListTrap.GetClientRect(&rect);

	// 为列表视图控件添加全行选中和栅格风格   
	m_ListTrap.SetExtendedStyle(m_ListTrap.GetExtendedStyle() | LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

	// 为列表视图控件添加4列   
	m_ListTrap.InsertColumn(0, _T("调用地址"), LVCFMT_CENTER,	rect.Width() / 4, 0);
	m_ListTrap.InsertColumn(1, _T("调用模块"), LVCFMT_CENTER,	rect.Width() / 4, 1);
	m_ListTrap.InsertColumn(2, _T("API名称"), LVCFMT_CENTER,	rect.Width() / 4, 2);
	m_ListTrap.InsertColumn(3, _T("调用次数"), LVCFMT_CENTER,	rect.Width() / 4, 3);




	//CString szTest1 = L"FYCK1";
	//CString szTest2 = L"FUCK2";
	//szTest1 += "\r\n";
	//szTest2 += "\r\n";

	//for (DWORD i = 0; i < 100; i++)
	//{
	//	m_LogEdit.LineScroll(m_LogEdit.GetLineCount());
	//	m_LogEdit.SetSel(-1);
	//	m_LogEdit.ReplaceSel(szTest1);
	//	m_LogEdit.LineScroll(m_LogEdit.GetLineCount());
	//	m_LogEdit.SetSel(-1);
	//	m_LogEdit.ReplaceSel(szTest2);
	//}



	//DWORD dwRow;
	//m_ListTrap.SetItemText(m_ListTrap.InsertItem(0, _T("测试1")),
	//	2, _T("fuck1"));
	//dwRow = m_ListTrap.InsertItem(1, _T("测试2"));
	//dwRow =  m_ListTrap.InsertItem(2, _T("测试3"));
	//dwRow = m_ListTrap.InsertItem(3, _T("测试4"));

	//dwRow = m_ListTrap.GetItemCount();
	//CString szTest =  m_ListTrap.GetItemText(0, 2);



	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CAPIMonitorDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CAPIMonitorDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CAPIMonitorDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CAPIMonitorDlg::OnOpenProc()
{
	// TODO: 在此添加命令处理程序代码
	if (m_Proc.DoModal() == IDOK)
	{
		//////////////////////////////////////////////////////////////////////////
		//预处理操作，创建线程，连接管道
		//在此处处理命名管道的名称，接着打开命名管道
		CString	szNamePipe_1;
		CString	szNamePipe_2;

		szNamePipe_1.Format(L"%s_1", StrPipeName);
		szNamePipe_2.Format(L"%s_2", StrPipeName);

		hPipe_1 = GeneratePipe(szNamePipe_1);	//主线程
		hPipe_2 = GeneratePipe(szNamePipe_2);	//UI线程

		if (!hPipe_1 || !hPipe_2)	return ;

		//申请保存线程数据,一个是管道句柄，一个是主操作类的指针  
		//Pipe | Ptr
		PDWORD	pThreadData = new DWORD[3];
		pThreadData[0] = (DWORD)hPipe_2;
		pThreadData[1] = (DWORD)m_lpProessing;
		pThreadData[2] = (DWORD)this;
		//建立两条管道，客户端连接成功后，开启线程去测试某条管道的通信
		CreateThread(NULL, NULL, ThreadProcOfWork, (LPVOID)pThreadData, NULL, NULL);
	//	CreateThread(NULL, NULL, ThreadProcMain, (LPVOID)hPipe_1, NULL, NULL);


		
		WCHAR szDirPath[MAX_PATH] = { 0 };
		WCHAR szLogText[MAX_PATH] = { 0 };
		WCHAR szLogBinary[MAX_PATH] = { 0 };
		CString szTimeOrder;
		CTime	tm;

		tm = CTime::GetCurrentTime();
		szTimeOrder = tm.Format("%y-%m-%d");
		szTimeOrder.Format(L"%s-%d", 
			tm.Format("%y-%m-%d"),
			tm.GetSecond() + tm.GetMinute() * 60);

		GetModuleFileName(NULL, szDirPath, MAX_PATH);
		PathRemoveFileSpec(szDirPath);


		BOOL bRootDir = PathIsRoot(szDirPath);
		if (bRootDir)
		{//若是根目录，不用加反斜杠
		 //	wcscat_s(szDirPath, MAX_PATH, L"HookAPILibrary.dll");

			wsprintf(szLogText, L"%s%s\\%s(%s).txt", szDirPath,
				FILE_DIR,
				PathFindFileName(m_Proc.szFile),
				szTimeOrder);

			wsprintf(szLogBinary, L"%s%s\\%s(%s).log", szDirPath,
				FILE_DIR,
				PathFindFileName(m_Proc.szFile),
				szTimeOrder);


			wcscat_s(szDirPath, FILE_DIR);

		}
		else
		{
			//	wcscat_s(szDirPath, MAX_PATH, L"\\HookAPILibrary.dll");
			wsprintf(szLogText, L"%s\\%s\\%s(%s).txt", szDirPath,
				FILE_DIR,
				PathFindFileName(m_Proc.szFile),
				szTimeOrder);


			wsprintf(szLogBinary, L"%s\\%s\\%s(%s).log", szDirPath,
				FILE_DIR,
				PathFindFileName(m_Proc.szFile),
				szTimeOrder);


			wcscat_s(szDirPath, L"\\");
			wcscat_s(szDirPath, FILE_DIR);

		}


		CFileFind m_sFileFind;
		//判断目录是否创建了
		if (!m_sFileFind.FindFile(szDirPath))
		{
			CreateDirectory(szDirPath, NULL);
		}


		if (m_FileLogText.Open(szLogText, CFile::modeCreate | CFile::modeReadWrite) == FALSE) exit(0x0);

		char szVarName[MAX_BUF_SIZE] = { 0 };

		WideCharToMultiByte(CP_ACP, NULL, L"自身模块调用顺序:\r\n", -1, szVarName, _countof(szVarName), NULL, FALSE);

		m_FileLogText.Write(szVarName, strlen(szVarName));
		
		if (m_FileLogBinary.Open(szLogBinary, CFile::modeCreate | CFile::modeReadWrite) == FALSE) exit(0x1);


	}

}

//////////////////////////////////////////////////////////////////////////
//	创建以szNamePipe为名字的命名管道
//	参数：
//	char*	szNamePipe				命名管道字符串的指针
//	返回值：创建成功，返回创建成功的句柄,否则NULL
//////////////////////////////////////////////////////////////////////////

HANDLE	CAPIMonitorDlg::GeneratePipe(CString szNamePipe)
{
	HANDLE hPipe = CreateNamedPipe(szNamePipe, PIPE_ACCESS_DUPLEX,
		PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
		PIPE_UNLIMITED_INSTANCES, MAX_BUF_SIZE, MAX_BUF_SIZE, NMPWAIT_WAIT_FOREVER, 0);

	if (!hPipe)	return NULL;

	if (ConnectNamedPipe(hPipe, NULL) == NULL)
	{
		CloseHandle(hPipe);//关闭管道
		return	NULL;
	}

	return hPipe;
}




//////////////////////////////////////////////////////////////////////////
//	该线程负责接收dll传来的数据，按照规则写入list中
//	注：对list的操作一定要设置互斥量，防止UI显示线程的读取到脏数据
//	参数：LPVOID lpPara				包含关键信息的结构体（句柄，list操作类的指针）
//////////////////////////////////////////////////////////////////////////

DWORD WINAPI ThreadProcOfWork(LPVOID lpPara)
{
	LPBYTE					pBuff = new BYTE[MAX_BUF_SIZE];
	DWORD					dwBytesOfRead;
	HANDLE					hPipe_2 = (HANDLE)(*(PDWORD)lpPara);
	DWORD					dwRet;
	ProcessingList*			lpProcessing = (ProcessingList*)(*(PDWORD)((DWORD)lpPara + 4));
	CAPIMonitorDlg*			pMainWindows = (CAPIMonitorDlg*)(*(PDWORD)((DWORD)lpPara + 8));
	lpModList				lpModule = lpProcessing->m_pModList;
	lpTrapInfo				lpCurTrap;
	WCHAR*					szInvokedModName;
	WCHAR*					szApiName;
	DWORD					dwType;
	CString					szTrap;
	lpTrapShow				lpTrap;

	ZeroMemory(pBuff, MAX_BUF_SIZE);

	do
	{
		if (dwRet = ReadFile(hPipe_2, pBuff, MAX_BUF_SIZE, &dwBytesOfRead, NULL))
		{
			// BUG：对List操作前进行互斥量的申请
			dwType = lpProcessing->GetMsgInfo((lpPacketInfo)pBuff);

			switch (dwType)
			{
			case MOD_MSG:
				break;
			case API_MSG:			
				break;
			case FINISH_MODMSG:
	
				::SendMessage(pMainWindows->m_hWnd, WM_RECVMODINFO, 0, 0);
				break;
			
			case  FINISH_APIMSG:
				::SendMessage(pMainWindows->m_hWnd, WM_REVCAPIINFO, 0, 0);
				break;

			case TRAP_MSG:
				//1. 数据包信息处理
				lpCurTrap = (lpTrapInfo)((lpPacketInfo)pBuff)->Data;
				szInvokedModName = lpProcessing->GetInvokedModName(lpCurTrap->dwRetAddr);
				szApiName = lpProcessing->GetApiName(lpCurTrap->dwModIndex, lpCurTrap->dwApiIndex);
				
				//1.1 封装信息，用于消息机制
				lpTrap = new TrapShow;
				lpTrap->szModName			= lpModule[lpCurTrap->dwModIndex].szModName;
				lpTrap->szInvokedModName	= szInvokedModName;
				lpTrap->szApiName			= szApiName;
				lpTrap->dwRetAddr			= lpCurTrap->dwRetAddr;
				lpTrap->dwParamLen			= lpCurTrap->dwLength;
				if (lpCurTrap->dwLength != 0)
				{
					lpTrap->szParam = (WCHAR*)VirtualAlloc(NULL, lpTrap->dwParamLen, MEM_COMMIT, PAGE_READWRITE);

					wcscpy_s(lpTrap->szParam, lpTrap->dwParamLen, (WCHAR*)lpCurTrap->byPara);
				}
				

				//2. 发送显示的消息
				::SendMessage(pMainWindows->m_hWnd, WM_TRAPINFO, 0, (LPARAM)lpTrap);

				break;


			default:
				break;
			}

		}

	} while (dwRet);

	return 0;
}

//////////////////////////////////////////////////////////////////////////
//	模拟主线程工作，发送指令给DLL
//	发送20次指令
//	参数：
//	LPVOID lpPara	- 管道句柄
//////////////////////////////////////////////////////////////////////////

DWORD  WINAPI ThreadProcMain(LPVOID lpPara)
{
	HANDLE	hPipe_1 = (HANDLE)lpPara;
	DWORD	dwNumOfWritten;
	DWORD	dwPorcessID;
	CString	szTest;


	dwPorcessID = GetCurrentProcessId();
	OutputDebugString(L"[监控端]负责管道1的主线程已经开启");

	for (DWORD dwIndex = 0; dwIndex < 20; dwIndex++)
	{
		szTest.Format(L"%s_ID:%d_Index:%d", L"[主线程]测试指令", dwPorcessID, dwIndex);
		WriteFile(hPipe_1, szTest, sizeof(WCHAR)*(szTest.GetLength() + 1), &dwNumOfWritten, NULL);
	}

	DisconnectNamedPipe(hPipe_1);
	CloseHandle(hPipe_1);
	return 0;
}

//////////////////////////////////////////////////////////////////////////
//	UI显示线程,对Modlist和ApiList进行显示
//	参数:
//	LPVOID lpPara - 存放着父窗口的指针
//////////////////////////////////////////////////////////////////////////

DWORD  WINAPI ThreadProcUI(LPVOID lpPara)
{
	CAPIMonitorDlg* pMainWindows = (CAPIMonitorDlg*)lpPara;
	

	return 0;
}


//////////////////////////////////////////////////////////////////////////
//	对MOD_MSG类型的通信进行UI的处理
//////////////////////////////////////////////////////////////////////////

afx_msg LRESULT CAPIMonitorDlg::OnRecvmodinfo(WPARAM wParam, LPARAM lParam)
{
	lpModList lpCurModlist = this->m_lpProessing->m_pModList;
	HTREEITEM hitem;

	m_TreeShow.DeleteAllItems();

	for (DWORD dwIndex = 0; dwIndex < this->m_lpProessing->m_dwModListLen; dwIndex++)
	{
		if (lpCurModlist[dwIndex].bActive)
		{
			hitem = m_TreeShow.InsertItem(lpCurModlist[dwIndex].szModName, 0, 0);
			m_TreeShow.SetItemData(hitem, lpCurModlist[dwIndex].dwModIndex);
		}
	}

	UpdateData(TRUE);

	return 0;
}

//////////////////////////////////////////////////////////////////////////
//	对API_MSG消息类型进行处理，将API添加到对应MOD的根节点下
//////////////////////////////////////////////////////////////////////////

afx_msg LRESULT CAPIMonitorDlg::OnRevcapiinfo(WPARAM wParam, LPARAM lParam)
{
	//遍历根节点，找到对应的mod插入
	lpModList		lpCurModlist = this->m_lpProessing->m_pModList;
	lpPacketApiInfo lpCurApiList = NULL;
	HTREEITEM		hInsert;

	m_TreeAPI.DeleteAllItems();

	m_hRoot =		m_TreeAPI.GetRootItem();

		if (lpCurModlist[m_dwModOrder].bActive && lpCurModlist[m_dwModOrder].lpApiList)
		{
			lpCurApiList = lpCurModlist[m_dwModOrder].lpApiList;

			for (DWORD dwApiIndex = 0;dwApiIndex < lpCurModlist[m_dwModOrder].dwApiListLen; dwApiIndex++)
			{
				if (lpCurApiList[dwApiIndex].bActive)
				{
				//	hInsert = FindItem(m_TreeAPI, m_hRoot, lpCurModlist[m_dwModOrder].szModName);
					hInsert = m_TreeAPI.InsertItem(lpCurApiList[dwApiIndex].szApiName, 0, 0);
					m_TreeAPI.SetItemData(hInsert, lpCurApiList[dwApiIndex].dwApiIndex);
					m_TreeAPI.SetCheck(hInsert, TRUE);
				}
			}
		}
	

	UpdateData(TRUE);

	return 0;
}



//////////////////////////////////////////////////////////////////////////
//	将Trap的信息插入或更新在List中
//	参数：
//	WCHAR*			szInvokedMod	- 调用模块的名称
//	WCHAR*			szApiName		- 被调用的API名字
//	DWORD			dwRetAddr		- 调用地址
//////////////////////////////////////////////////////////////////////////

VOID	CAPIMonitorDlg::InsertTrap(WCHAR* szInvokedMod, WCHAR* szApiName, DWORD dwRetAddr)
{

	//1. 更新检测,更新数据
	DWORD	dwItemCount = m_ListTrap.GetItemCount();
	CString	szInvokedAddr;
	CString	szInvokedModName;
	CString	szInvokedCount;
	DWORD	dwTransferdAddr;
	DWORD	dwInvokedCount;
	DWORD	dwCurRow;

	if (szInvokedMod == NULL)
		for (DWORD dwRow = 0; dwRow < dwItemCount; dwRow++)
	{
		szInvokedAddr		= m_ListTrap.GetItemText(dwRow, 0);
		szInvokedModName	= m_ListTrap.GetItemText(dwRow, 1);
		szInvokedCount		= m_ListTrap.GetItemText(dwRow, 3);
		dwTransferdAddr		= wcstol(szInvokedAddr, NULL, 16);

		if (dwTransferdAddr == dwRetAddr)
		{
			dwInvokedCount = wcstol(szInvokedCount, NULL, 10);
			dwInvokedCount++;
			szInvokedCount.Format(L"%d", dwInvokedCount);
			m_ListTrap.SetItemText(dwRow, 3, szInvokedCount);
			return;
		}	
	}
	else
	{
		for (DWORD dwRow = 0; dwRow < dwItemCount; dwRow++)
		{
			szInvokedAddr = m_ListTrap.GetItemText(dwRow, 0);
			szInvokedModName = m_ListTrap.GetItemText(dwRow, 1);
			szInvokedCount = m_ListTrap.GetItemText(dwRow, 3);

			dwTransferdAddr = wcstol(szInvokedAddr, NULL, 16);


			if (wcscmp(szInvokedModName, szInvokedMod) == 0 &&
				dwTransferdAddr == dwRetAddr)
			{//符合条件，进行更新
				dwInvokedCount = wcstol(szInvokedCount, NULL, 10);
				dwInvokedCount++;
				szInvokedCount.Format(L"%d", dwInvokedCount);
				m_ListTrap.SetItemText(dwRow, 3, szInvokedCount);
				return;
			}
		}//for
	}

	 //2. 插入数据
	szInvokedAddr.Format(L"0x%x", dwRetAddr);

	dwCurRow = m_ListTrap.InsertItem(dwItemCount, szInvokedAddr);
	if(szInvokedMod != NULL)
	m_ListTrap.SetItemText(dwCurRow, 1, szInvokedMod);
	else
	m_ListTrap.SetItemText(dwCurRow, 1,L"未知模块");

	m_ListTrap.SetItemText(dwCurRow, 2, szApiName);
	m_ListTrap.SetItemText(dwCurRow, 3, L"1");
		
	return ;

}




//////////////////////////////////////////////////////////////////////////
//	遍历TreeControl控件，找到对应节点的句柄
//	参数:
//	CTreeCtrl& ctrlTree - 树形控件变量的引用
//	HTREEITEM hItem		- 当前开始遍历节点的句柄
//	CString strtext		- 匹配值
//	返回值：	成功返回匹配节点句柄，否则NULL
//////////////////////////////////////////////////////////////////////////


HTREEITEM	CAPIMonitorDlg::FindItem(CTreeCtrl& ctrlTree, HTREEITEM hItem, CString strText)
{
	HTREEITEM  hFind;

	//空树，直接返回NULL 
	if (hItem == NULL)
		return  NULL;

	//遍历查找 
	while (hItem != NULL)
	{
		//当前节点即所需查找节点 
	/*	if (ctrlTree.GetItemText(hItem) == strText)
			return  hItem;*/

		if (_wcsnicmp(strText, ctrlTree.GetItemText(hItem), strText.GetLength()) == 0)
			return  hItem;


		//查找当前节点的子节点 
		if (ctrlTree.ItemHasChildren(hItem))
		{
			hItem = ctrlTree.GetChildItem(hItem);
			//递归调用查找子节点下节点

			hFind = FindItem(ctrlTree, hItem, strText);
			if (hFind)
			{
				return  hFind;
			}
			else
			{
				//子节点中未发现所需节点，继续查找兄弟节点
				hItem = ctrlTree.GetNextSiblingItem(ctrlTree.GetParentItem(hItem));
			}
		}
		else
		{
			//若无子节点，继续查找兄弟节点
			hItem = ctrlTree.GetNextSiblingItem(hItem);
		}
	}

	return hItem;
}




BOOL CAPIMonitorDlg::OnCopyData(CWnd* pWnd, COPYDATASTRUCT* pCopyDataStruct)
{
	// TODO: 在此添加消息处理程序代码和/或调用默认值
	WCHAR				szTrap[MAX_BUF_SIZE];
	lpTrapInfo			lpCurTrap =  (lpTrapInfo)pCopyDataStruct->lpData;

	wsprintf(szTrap, L"Mod:%s ApiIndex:%s RetAddr:%x", m_lpProessing->m_pModList[lpCurTrap->dwModIndex].szModName,
		m_lpProessing->m_pModList[lpCurTrap->dwModIndex].lpApiList[lpCurTrap->dwApiIndex].szApiName,
		lpCurTrap->dwRetAddr);

	return CDialogEx::OnCopyData(pWnd, pCopyDataStruct);
}



//////////////////////////////////////////////////////////////////////////
//	实现过程，通过HitTest获取鼠标指针位置的节点句柄，从而提取该节点的字符串
//////////////////////////////////////////////////////////////////////////

void CAPIMonitorDlg::OnNMClickTreeList(NMHDR *pNMHDR, LRESULT *pResult)
{
	// TODO: 在此添加控件通知处理程序代码
	CPoint pt;
	UINT nFlags;

	 pt = GetCurrentMessage()->pt; //获取当前鼠标点击消息的坐标点  
	m_TreeShow.ScreenToClient(&pt);      //将鼠标的屏幕坐标，转换成树形控件的客户区坐标 

	HTREEITEM	hItem = m_TreeShow.HitTest(pt, &nFlags);


	// 没有勾选，则显示该模块下的API,没碰复选框
	if ((hItem != NULL) && (TVHT_ONITEM & nFlags))
	{
		HTREEITEM hSelected;
		// 显示该模块的API列表
		// 需要对API列表的复选框状态进行勾选
		m_TreeShow.Select(hItem, TVGN_CARET);
		hSelected = m_TreeShow.GetSelectedItem();
		m_dwModOrder = m_TreeShow.GetItemData(hSelected);

		// 如果为0，则代表宿主程序模块，跳过不处理，否则会崩溃
		if (m_dwModOrder == 0)	return;

		SendMessage(WM_REVCAPIINFO, NULL, NULL);
	}


	if ((hItem != NULL) && (TVHT_ONITEMSTATEICON  & nFlags))	
	{
		BOOL			bChecked = m_TreeShow.GetCheck(hItem);
		HTREEITEM		hSelected;

		m_TreeShow.Select(hItem, TVGN_CARET);
		hSelected = m_TreeShow.GetSelectedItem();
		m_dwModOrder = m_TreeShow.GetItemData(hSelected);

		// 如果为0，则代表宿主程序模块，跳过不处理，否则会崩溃
		if (m_dwModOrder == 0)	return;

		if (bChecked)
		{//进行UnHook
			m_lpProessing->SendHookMod(hPipe_1, m_TreeShow.GetItemText(hItem).GetBuffer(), FALSE);
		}
		else
		{//进行Hook

			m_lpProessing->SendHookMod(hPipe_1, m_TreeShow.GetItemText(hItem).GetBuffer(), TRUE);	
		}

	}

	*pResult = 0;
}






void CAPIMonitorDlg::OnNMClickTreeApi(NMHDR *pNMHDR, LRESULT *pResult)
{
	// TODO: 在此添加控件通知处理程序代码

	CPoint pt;
	UINT nFlags;

	pt = GetCurrentMessage()->pt; //获取当前鼠标点击消息的坐标点  
	m_TreeAPI.ScreenToClient(&pt);      //将鼠标的屏幕坐标，转换成树形控件的客户区坐标 

	HTREEITEM	hItem = m_TreeAPI.HitTest(pt, &nFlags);
	DWORD		dwApiIndex;


	//点击并且操作了复选框
	if ((hItem != NULL) && (TVHT_ONITEMSTATEICON  & nFlags))
	{
		BOOL			bChecked = m_TreeAPI.GetCheck(hItem);
		HTREEITEM		hSelected;

		m_TreeAPI.Select(hItem, TVGN_CARET);
		hSelected = m_TreeAPI.GetSelectedItem();
		dwApiIndex = m_TreeAPI.GetItemData(hSelected);

		if (!bChecked)
		{//进行不过滤
			m_lpProessing->SendFilteredApi(hPipe_1, m_dwModOrder, dwApiIndex, FALSE);
		}
		else
		{//进行过滤
			m_lpProessing->SendFilteredApi(hPipe_1, m_dwModOrder, dwApiIndex, TRUE);
		}

	}




	*pResult = 0;
}


void CAPIMonitorDlg::OnEnChangeEditFindapi()
{
	// TODO:  如果该控件是 RICHEDIT 控件，它将不
	// 发送此通知，除非重写 CDialogEx::OnInitDialog()
	// 函数并调用 CRichEditCtrl().SetEventMask()，
	// 同时将 ENM_CHANGE 标志“或”运算到掩码中。

	// TODO:  在此添加控件通知处理程序代码
	CString			szEdit;
	CString			szSelected;
	HTREEITEM		hSelected;


	((CEdit*)GetDlgItem(IDC_EDIT_FINDAPI))->GetWindowTextW(szEdit);

	if (szEdit.IsEmpty()) return;

	hSelected = FindItem(m_TreeAPI, m_TreeAPI.GetRootItem(), szEdit);

	m_TreeAPI.SelectItem(NULL);

	m_TreeAPI.SelectItem(hSelected);


	szSelected = m_TreeAPI.GetItemText(hSelected);

	if (wcscmp(szSelected, szEdit) == 0)
	{
		m_TreeAPI.SetFocus();
	}


//	m_TreeShow.Select(m_hSelected, TVIS_SELECTED);
//	m_TreeShow.SetItemState(m_hSelected, TVIS_SELECTED, TVIS_SELECTED);
	UpdateData(TRUE);


}




//////////////////////////////////////////////////////////////////////////
//	调用情况的消息处理函数
//	参数：
//	LPARAM lParam		 - 包含关键数据的结构体指针
//////////////////////////////////////////////////////////////////////////

afx_msg LRESULT CAPIMonitorDlg::OnTrapinfo(WPARAM wParam, LPARAM lParam)
{
	lpTrapShow	lpTrap = (lpTrapShow)lParam;
	CString		szTrap;

	if (lpTrap->szInvokedModName == NULL)
	{
		lpTrap->szInvokedModName = L"未知模块";
	}

	InsertTrap(lpTrap->szInvokedModName, lpTrap->szApiName, lpTrap->dwRetAddr);

	//3. 显示在日志上
	
	if (m_LogEdit.GetLineCount() > 300)
	{
		m_LogEdit.SetWindowTextW(L"");
	}

	if(lpTrap->dwParamLen != 0x0)
	szTrap.Format(L"Trapped api : API - %s<%s> . Called from 0x%x<%s> ,Param: %s\r\n",
		lpTrap->szApiName, lpTrap->szModName,
		lpTrap->dwRetAddr, lpTrap->szInvokedModName,
		lpTrap->szParam);
	else
	szTrap.Format(L"Trapped api : API - %s<%s> . Called from 0x%x<%s> \r\n",
		lpTrap->szApiName, lpTrap->szModName,
		lpTrap->dwRetAddr, lpTrap->szInvokedModName
		);

	m_LogEdit.LineScroll(m_LogEdit.GetLineCount());
	m_LogEdit.SetSel(-1);
	m_LogEdit.ReplaceSel(szTrap);
	


	if (wcscmp(lpTrap->szInvokedModName, m_lpProessing->m_pModList[0].szModName) == 0)
	{
		char szVarName[MAX_BUF_SIZE] = { 0 };
		WideCharToMultiByte(CP_ACP, NULL, szTrap, -1, szVarName, _countof(szVarName), NULL, FALSE);
		m_FileLogText.Write(szVarName, strlen(szVarName));
		
		WideCharToMultiByte(CP_ACP, NULL, lpTrap->szApiName, -1, szVarName, _countof(szVarName), NULL, FALSE);

		//将其插入到二进制样本数据
		m_lpProessing->InsertOfBinary(szVarName);

	}

	delete lpTrap;

	return 0;
}


//////////////////////////////////////////////////////////////////////////
//	保存日志到当前文件夹下
//////////////////////////////////////////////////////////////////////////


void CAPIMonitorDlg::OnSavelog()
{

	//中断管道连接
	DisconnectNamedPipe(hPipe_1);
	DisconnectNamedPipe(hPipe_2);
	CloseHandle(hPipe_1);
	CloseHandle(hPipe_2);
	

	//对m_FileLogText写入模块调用情况
	char szVarName[MAX_BUF_SIZE] = { 0 };
	WideCharToMultiByte(CP_ACP, NULL, L"\r\n模块调用次数情况:\r\n", -1, szVarName, _countof(szVarName), NULL, FALSE);

	m_FileLogText.Write(szVarName, strlen(szVarName));

	DWORD		dwItemCount = m_ListTrap.GetItemCount();
	CString		szShow;


	for (DWORD dwRow = 0; dwRow < dwItemCount; dwRow++)
	{

		szShow.Format(L"[%d] %s 被 %s调用, 调用地址 = 0x%x, 调用次数 = %d \r\n",
			dwRow,
			m_ListTrap.GetItemText(dwRow, 2),
			m_ListTrap.GetItemText(dwRow, 1),
			wcstol(m_ListTrap.GetItemText(dwRow, 0), NULL, 16),
			wcstol(m_ListTrap.GetItemText(dwRow, 3), NULL, 10));

		WideCharToMultiByte(CP_ACP, NULL, szShow, -1, szVarName, _countof(szVarName), NULL, FALSE);

		m_FileLogText.Write(szVarName, strlen(szVarName));

	}

	//对m_FileLogBinary写入样本数据,待添加
	DWORD	dwSizeOfBytes;
	DWORD	dwAddr;
	dwAddr = m_lpProessing->GetLogInfo(&dwSizeOfBytes);
	if(dwAddr != NULL)
	m_FileLogBinary.Write((PVOID)dwAddr, dwSizeOfBytes);



	m_FileLogText.Close();
	m_FileLogBinary.Close();

	MessageBox(L"日志保存成功，程序即将退出.......", L"Tip");

	exit(0x0);

}

