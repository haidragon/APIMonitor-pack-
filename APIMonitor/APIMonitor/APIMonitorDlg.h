
// APIMonitorDlg.h : 头文件
//

#pragma once
#include "ProcessOperator.h"
#include "ProcessingTransmit.h"
#include "./src/detours.h"
#include <shlwapi.h>
#include <locale.h>
#include "afxcmn.h"
#include "afxwin.h"
#pragma comment(lib,"shlwapi.lib")

//注：定义自定义消息
#define WM_RECVMODINFO				WM_USER + 1	
#define	WM_REVCAPIINFO				WM_USER + 2
#define	 WM_TRAPINFO                 WM_USER + 3



//用于显示调用信息
typedef struct _TrapShow
{
	WCHAR*	szModName;
	WCHAR*	szApiName;
	WCHAR*	szInvokedModName;
	DWORD 	dwRetAddr;
	WCHAR*	szParam;
	DWORD	dwParamLen;
}TrapShow, *lpTrapShow;


// CAPIMonitorDlg 对话框
class CAPIMonitorDlg : public CDialogEx
{
	// 构造
public:
	CAPIMonitorDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_APIMONITOR_DIALOG };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void		OnOpenProc();
	HANDLE				GeneratePipe(CString szNamePipe);		//管道生成函数
	ProcessingList*		m_lpProessing;							//保存信息的数组操作类
	HTREEITEM			FindItem(CTreeCtrl& ctrlTree, HTREEITEM hItem, CString strText);
private:
	CMenu				m_Menu;
	CProcessOperator	m_Proc;
	CString				StrPipeName;
	HANDLE				hPipe_1;			// 监控端发送指令的管道句柄
	HANDLE				hPipe_2;			// 监控端接收DLL数据的管道句柄

public:
	CTreeCtrl			m_TreeShow;			// 显示模块列表
	CTreeCtrl			m_TreeAPI;			// 显示API列表
	HTREEITEM			m_hRoot;
	HTREEITEM			hTestTree;
	CListCtrl			m_ListTrap;		
	CEdit				m_LogEdit;
	CFile				m_FileLogText;
	CFile				m_FileLogBinary;



protected:
	afx_msg LRESULT		OnRecvmodinfo(WPARAM wParam, LPARAM lParam);
	afx_msg LRESULT		OnRevcapiinfo(WPARAM wParam, LPARAM lParam);
	DWORD				m_dwModOrder;			// 用于m_TreeAPI 这个显示API的树形控件变量，显示当前选中模块的序号，给API显示做参考
public:
	afx_msg BOOL OnCopyData(CWnd* pWnd, COPYDATASTRUCT* pCopyDataStruct);
	afx_msg void OnNMClickTreeList(NMHDR *pNMHDR, LRESULT *pResult);
	VOID		 InsertTrap(WCHAR* szInvokedMod, WCHAR* szApiName, DWORD dwRetAddr);
	afx_msg void OnNMClickTreeApi(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnEnChangeEditFindapi();
	CEdit			m_EditApi;
protected:
	afx_msg LRESULT OnTrapinfo(WPARAM wParam, LPARAM lParam);
public:
	afx_msg void OnSavelog();
};
