
// SaerPackUIDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "SaerPackUI.h"
#include "SaerPackUIDlg.h"
#include "afxdialogex.h"

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


// CSaerPackUIDlg 对话框



CSaerPackUIDlg::CSaerPackUIDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_SAERPACKUI_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CSaerPackUIDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CSaerPackUIDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON_OPEN, &CSaerPackUIDlg::OnBnClickedButtonOpen)
	ON_BN_CLICKED(IDC_BUTTON_PACK, &CSaerPackUIDlg::OnBnClickedButtonPack)
	ON_BN_CLICKED(IDC_BUTTON_CHECK, &CSaerPackUIDlg::OnBnClickedButtonCheck)
	ON_BN_CLICKED(IDC_CHECK_COMPRESS, &CSaerPackUIDlg::OnBnClickedCheckCompress)
	ON_BN_CLICKED(IDC_BUTTON_VCODE, &CSaerPackUIDlg::OnBnClickedButtonVcode)
END_MESSAGE_MAP()


// CSaerPackUIDlg 消息处理程序

BOOL CSaerPackUIDlg::OnInitDialog()
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
	bEnabled = FALSE;
	((CComboBox*)GetDlgItem(IDC_COMBO_CPMPRESS))->AddString(L"aplib");
	((CComboBox*)GetDlgItem(IDC_COMBO_CPMPRESS))->AddString(L"JCALG1_FAST");
	((CComboBox*)GetDlgItem(IDC_COMBO_CPMPRESS))->AddString(L"JCALG1_SMALL");
	((CComboBox*)GetDlgItem(IDC_COMBO_CPMPRESS))->SetCurSel(0);


	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CSaerPackUIDlg::OnSysCommand(UINT nID, LPARAM lParam)
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

void CSaerPackUIDlg::OnPaint()
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
HCURSOR CSaerPackUIDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CSaerPackUIDlg::OnBnClickedButtonOpen()
{
	// TODO: 在此添加控件通知处理程序代码
	OutputDebugString(L"打开");
	CString	str;
	CFileDialog  fileDlg(TRUE);
	if (fileDlg.DoModal() == IDOK)
	{
		str = fileDlg.GetPathName();

		//判断文件是否存在
		this->SetDlgItemText(IDC_EDIT_PATH, str);
	}
	
}


void CSaerPackUIDlg::OnBnClickedButtonPack()
{
	// TODO: 在此添加控件通知处理程序代码

	SelectionInfo	stcConfig;
	CString			str;
	CString			strSample;
	HMODULE			hMod;
	fnPackBase		g_pfnPackBase;

	ZeroMemory(&stcConfig, sizeof(SelectionInfo));

	hMod			= 	 LoadLibraryEx(L"SaerPackBase.dll", NULL , NULL);
	g_pfnPackBase	=	(fnPackBase)GetProcAddress(hMod, "PackBase");

	OutputDebugString(L"生成输出文件路径");

	if (((CButton*)GetDlgItem(IDC_CHECK_COMPRESS))->GetCheck())
	{
		stcConfig.bIsCompression	= TRUE;
		stcConfig.dwCompressionType	= ((CComboBox*)GetDlgItem(IDC_COMBO_CPMPRESS))->GetCurSel();
	}

	if (((CButton*)GetDlgItem(IDC_CHECK_IAT))->GetCheck())
	{
		stcConfig.bIsTransferIAT = TRUE;
	}
	
	if (((CButton*)GetDlgItem(IDC_CHECK_RELOC))->GetCheck())
	{
		stcConfig.bIsTransferReloc = TRUE;
	}

	if (((CButton*)GetDlgItem(IDC_CHECK_HOOK))->GetCheck())
	{
		stcConfig.bIsApiRedirect = TRUE;
	}

	if (((CButton*)GetDlgItem(IDC_CHECK_DUMP))->GetCheck())
	{
		stcConfig.bIsAntiDump = TRUE;
	}

	if (((CButton*)GetDlgItem(IDC_CHECK_DEBUG))->GetCheck())
	{
		stcConfig.bIsAntiDebugging = TRUE;
	}


	if (((CButton*)GetDlgItem(IDC_CHECK_MEM))->GetCheck())
	{
		stcConfig.bIsMemVerification = TRUE;
	}

	if (((CButton*)GetDlgItem(IDC_CHECK_FILE))->GetCheck())
	{
		stcConfig.bIsFileVerification = TRUE;
	}

	this->GetDlgItemTextW(IDC_EDIT_PATH, str);
	

	if (((CButton*)GetDlgItem(IDC_CHECK_VCODE))->GetCheck())
	{
		stcConfig.bIsVirtualizeCode = TRUE;

		this->GetDlgItemTextW(IDC_EDIT_VCODE, strSample);

		if (strSample.IsEmpty())
		{
			ZeroMemory(stcConfig.szSample, MAX_PATH * sizeof(WCHAR));
		}
		else
		{
			wcsncpy_s(stcConfig.szSample, strSample, MAX_PATH);
		}

	}//if






	if (g_pfnPackBase(str.GetBuffer(), &stcConfig))
		MessageBox(L"加壳成功", L"提示", 0);
	else
		MessageBox(L"加壳失败", L"提示", 0);

	FreeLibrary(hMod);
}


void CSaerPackUIDlg::OnBnClickedButtonCheck()
{
	DWORD DWSel = ((CComboBox*)GetDlgItem(IDC_COMBO_CPMPRESS))->GetCurSel();
}


void CSaerPackUIDlg::OnBnClickedCheckCompress()
{
	// TODO: 在此添加控件通知处理程序代码
	
	if (!bEnabled)
	{
		GetDlgItem(IDC_COMBO_CPMPRESS)->EnableWindow(TRUE);
		bEnabled = TRUE;
	}
	else
	{
		GetDlgItem(IDC_COMBO_CPMPRESS)->EnableWindow(FALSE);
		bEnabled = FALSE;
	}

}


void CSaerPackUIDlg::OnBnClickedButtonVcode()
{
	// TODO: 在此添加控件通知处理程序代码
	CString	str;
	CFileDialog  fileDlg(TRUE);
	if (fileDlg.DoModal() == IDOK)
	{
		str = fileDlg.GetPathName();
		//判断文件是否存在
		this->SetDlgItemText(IDC_EDIT_VCODE, str);
	}


}
