
#include "windows.h"
#include <CString>
#include <Tlhelp32.h>


class JysNT
{
	CString CSDirectory,CSAlloc;
	WCHAR pBuf[MAX_PATH];
public:
	void  LastError(LPCWSTR Caption);//--------------------------------------------------------LastError

	HANDLE FindWindowtoOpenProcess(LPTSTR window);//-------------------------------------------�򿪽��̷��ر��򿪽��̵ľ��

	HANDLE CreateToolhelp32SnapshottoOpenProcess(WCHAR* lpcszProcName);//----------------------CreateToolhelp32Snapshot ��PID

	void InjectDll(WCHAR* lpcszProcName,LPCSTR dlladdr);//-------------------------------------Զ���߳�ע��DLL

	DWORD EnumProcesses(LPCWSTR window,WCHAR *Name);//-----------------------------------------ö��EXEģ���ַ

	DWORD EnumProcessesdll(LPCWSTR ProcessName,LPCWSTR DllName);//---------------------------------------ö��DLLģ���ַ

	unsigned char * MemSearch(const unsigned char *mem, const int memSize, const unsigned char *patt, const int pattSize);//�����ڴ�

	BOOL AnsiToUcs(const CStringA &strAnsi, CStringW &strUcs);	;//---------------------------���ֽ�ת���ֽ� ��ATL A2W,ʹ��ǰ����USES_CONVERSION;

	BOOL UcsToAnsi(const CStringW &strUcs,  CStringA &strAnsi);	;//---------------------------���ֽ�ת���ֽ� ��ATL W2A,ʹ��ǰ����USES_CONVERSION;

	void warningSound();

};

//��ȡ���ĵ�ַ��ȥ��С����ƫ�ƣ�ƫ�Ƽ���ģ���׵�ַ����Ŀ���ַ
//////////////////////////////////////////////////////////////////////////////////////////////////////// ���򿪡��Ի���

	/*
	CString CSPath��Directory;
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	CFileDialog dlg(TRUE);
	if (dlg.DoModal()==IDOK)
	{
	CSPath=dlg.GetPathName();
	SetDlgItemTextW(IDC_EDIT1,dlg.GetPathName());

	_splitpath( GamePath, Gamedrive, Gamedir, Gamefname, Gameext );  // �ָ��ļ�·��
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
		MessageBox("û���ҵ���ϷĿ¼Ŷ!");


	}*/

////////////////////////////////////////////////////////////////////////////////////////////////////////CBitmapButton ���ð�ťͼƬ
/*
	CBitmapButton btnbmp;
	btnbmp.LoadBitmaps(IDB_BITMAP1,0,0,0);
	btnbmp.SubclassDlgItem(IDC_BUTTON2,this);
	btnbmp.SizeToContent();
*/

////////////////////////////////////////////////////////////////////////////////////////////////////////  ���ö�ʱ��
/*

int const PLAYID=111;
void CALLBACK TimerProc(HWND hWnd,UINT nMsg,UINT nTimerid,DWORD dwTime)  //�ص�����
{
	
}
SetTimer(PLAYID,1*1000,&TimerProc);

*/

////////////////////////////////////////////////////////////////////////////////////////////////////////�� IDA F5���ӵ� ��������λ��


#define huazhiling _asm{jb label jnb label _emit 0xE8 label:}
	
////////////////////////////////////////////////////////////////////////////////////////////////////////�����Ĵ���


/*		����ascii
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

