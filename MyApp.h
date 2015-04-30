
#include "windows.h"
#include <CString>
#include <Tlhelp32.h>


class JysNT
{
	CString CSDirectory,CSAlloc;
	WCHAR pBuf[MAX_PATH];
public:
	void  LastError(LPCWSTR Caption);//--------------------------------------------------------LastError

	HANDLE FindWindowtoOpenProcess(LPTSTR window);//-------------------------------------------打开进程返回被打开进程的句柄

	HANDLE CreateToolhelp32SnapshottoOpenProcess(WCHAR* lpcszProcName);//----------------------CreateToolhelp32Snapshot 找PID

	void InjectDll(WCHAR* lpcszProcName,LPCSTR dlladdr);//-------------------------------------远程线程注入DLL

	DWORD EnumProcesses(LPCWSTR window,WCHAR *Name);//-----------------------------------------枚举EXE模块地址

	DWORD EnumProcessesdll(LPCWSTR ProcessName,LPCWSTR DllName);//---------------------------------------枚举DLL模块地址

	unsigned char * MemSearch(const unsigned char *mem, const int memSize, const unsigned char *patt, const int pattSize);//搜索内存

	BOOL AnsiToUcs(const CStringA &strAnsi, CStringW &strUcs);	;//---------------------------多字节转宽字节 用ATL A2W,使用前加上USES_CONVERSION;

	BOOL UcsToAnsi(const CStringW &strUcs,  CStringA &strAnsi);	;//---------------------------宽字节转多字节 用ATL W2A,使用前加上USES_CONVERSION;

	void warningSound();

};

//获取到的地址减去大小等于偏移，偏移加上模块首地址等于目标地址
//////////////////////////////////////////////////////////////////////////////////////////////////////// “打开”对话框

	/*
	CString CSPath，Directory;
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	CFileDialog dlg(TRUE);
	if (dlg.DoModal()==IDOK)
	{
	CSPath=dlg.GetPathName();
	SetDlgItemTextW(IDC_EDIT1,dlg.GetPathName());

	_splitpath( GamePath, Gamedrive, Gamedir, Gamefname, Gameext );  // 分割文件路径
	Directory.Format("%s%s",Gamedrive,Gamedir);
	SetCurrentDirectory(Directory);

	ZeroMemory( &si, sizeof(si) );
	si.cb = sizeof(si);
	ZeroMemory( &pi, sizeof(pi) );
	if(!CreateProcess(GamePath,
		NULL,
		NULL,
		NULL,
		FALSE,
		NULL,
		NULL,
		NULL,
		&si,              // Pointer to STARTUPINFO structure.
		&pi
		))
	{
		MessageBox("没有找到游戏目录哦!");


	}*/

////////////////////////////////////////////////////////////////////////////////////////////////////////CBitmapButton 设置按钮图片
/*
	CBitmapButton btnbmp;
	btnbmp.LoadBitmaps(IDB_BITMAP1,0,0,0);
	btnbmp.SubclassDlgItem(IDC_BUTTON2,this);
	btnbmp.SizeToContent();
*/

////////////////////////////////////////////////////////////////////////////////////////////////////////  设置定时器
/*

int const PLAYID=111;
void CALLBACK TimerProc(HWND hWnd,UINT nMsg,UINT nTimerid,DWORD dwTime)  //回调函数
{
	
}
SetTimer(PLAYID,1*1000,&TimerProc);

*/

////////////////////////////////////////////////////////////////////////////////////////////////////////反 IDA F5，加到 代码任意位置


#define huazhiling _asm{jb label jnb label _emit 0xE8 label:}
	
////////////////////////////////////////////////////////////////////////////////////////////////////////保护寄存器


/*		搜索ascii
void NsEncrypt::htexttohex(void* dest, char* source)
{
	CStringA changdu;
	changdu.Format("%s",source);
	void far* ss=::GlobalAlloc(0,changdu.GetLength()+1);
	int j=0;
	for(int i=0;*(source+i)!='\0';)
	{
		CStringA zj;
		zj.Format("%c%c",*(source+i),*(source+i+1));
//		if(zj=="00")zj="20";
		sscanf(zj, "%x", (char*)ss+j);
		j++;
		i=i+3;

	}
	memcpy(dest,ss,j+1);
	//strcpy(dest,(char*)ss);
	::GlobalFree(ss);
}
*/




// void NsEncrypt::htexttohex(void* dest, char* source)
// {
// 	CStringA changdu;
// 	changdu.Format("%s",source);
// 	void far* ss=::GlobalAlloc(0,changdu.GetLength()+1);
// 	int j=0;
// 	for(int i=0;*(source+i)!='\0';)
// 	{
// 		CStringA zj;
// 		zj.Format("%c%c",*(source+i),*(source+i+1));
// 		/*if(zj=="00")zj="20";*/
// 		sscanf(zj, "%x", (char*)ss+j);
// 		j++;
// 		i=i+3;
// 
// 	}
// 	memcpy(dest,ss,j+1);
// 	//strcpy(dest,(char*)ss);
// 	::GlobalFree(ss);
// }

