
#include "StdAfx.h"
#include "MyApp.h"

////////////////////////////////////////////////////////////////////////////////////////////////// 警告

void JysNT::warningSound()
{
	MessageBeep(0);
	Sleep(100);
	MessageBeep(16);
}

////////////////////////////////////////////////////////////////////////////////////////////////// LastError
void JysNT::LastError(LPCWSTR Caption)
{
	DWORD err1=GetLastError();
	if (0!=err1)
	{
		LPSTR lpBuffer1;
		FormatMessage ( FORMAT_MESSAGE_ALLOCATE_BUFFER  | 
			FORMAT_MESSAGE_IGNORE_INSERTS  | 
			FORMAT_MESSAGE_FROM_SYSTEM,
			NULL,
			err1, 
			LANG_NEUTRAL,
			(LPTSTR) & lpBuffer1,
			0 ,
			NULL );
		MessageBox(0,(LPCTSTR)lpBuffer1,Caption,0);  
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////////打开进程

HANDLE JysNT::FindWindowtoOpenProcess(LPTSTR window)
{
	HANDLE processH=0;
	DWORD processid;
	HWND gameh=::FindWindow(NULL,window);
	//LastError(L"F");
	if(!gameh)
	{
		MessageBox(0,L"查找错误 : )",0,0);
	}
	else
	{
		GetWindowThreadProcessId(gameh,&processid);
		processH=OpenProcess(PROCESS_ALL_ACCESS,false,processid);
		return processH;
	}
}
//////////////////////////////////////////////////////////////////////////////////////////////////CreateToolhelp32Snapshot 找PID
HANDLE JysNT::CreateToolhelp32SnapshottoOpenProcess(WCHAR* lpcszProcName)
{
	HANDLE processH=0;
	HANDLE handle=::CreateToolhelp32Snapshot(TH32CS_SNAPALL,0);
	PROCESSENTRY32 Info;
	Info.dwSize = sizeof(PROCESSENTRY32);
	if(::Process32First(handle,&Info))
	{
		do{
			if( _tcsicmp(Info.szExeFile, lpcszProcName) == 0 )
			{
				processH=OpenProcess(PROCESS_ALL_ACCESS,false,Info.th32ProcessID);
				return processH;
			}
		}
		while(::Process32Next(handle,&Info)); 
		::CloseHandle(handle);
	}
}
//////////////////////////////////////////////////////////////////////////////////////////////////远程线程注入DLL
void JysNT::InjectDll(WCHAR* lpcszProcName,LPCSTR dlladdr)
{
	HANDLE processH=CreateToolhelp32SnapshottoOpenProcess(lpcszProcName);
	LPVOID AllocAddr=VirtualAllocEx(processH,0,256,MEM_COMMIT,PAGE_EXECUTE_READWRITE);
	//LastError(L"V");
	// 	CSAlloc.Format(L"%x",AllocAddr);
	// 	MessageBox(0,(LPCTSTR)CSAlloc,0,0);

	GetCurrentDirectory(MAX_PATH,pBuf);
	//LastError(L"01");

	CString dll(dlladdr);		//DLL 名字记得在前面加上 "\\"
	dll=L"\\"+dll;
	CSDirectory=pBuf+dll;

	int cb = ((1 + lstrlenW(CSDirectory))* sizeof(WCHAR));
	//LPCTSTR writeBuf=CSDirectory;
	//CString writeBuf;
	//writeBuf.Format(L"%s",CSDirectory);
	WriteProcessMemory(processH,AllocAddr,CSDirectory,cb,0);

	PTHREAD_START_ROUTINE addr=(PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(L"Kernel32"),"LoadLibraryW");
	//LastError(L"G");
	//CSaddr.Format(L"%x",addr);
	//MessageBox((LPCTSTR)CSaddr,0,0);
	CreateRemoteThread(processH,NULL,0,addr,AllocAddr,0,0);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////枚举EXE模块地址

DWORD JysNT::EnumProcesses(LPCWSTR window,WCHAR *Name)
{
	CString output;

	HWND gameh=::FindWindow(NULL,window);
	if(gameh==0)
	{
		MessageBoxW(0,L"FIND 失败",L"？",0);
	}

	DWORD processid;
	GetWindowThreadProcessId(gameh,&processid);

	HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,processid);

	if (hModuleSnap == INVALID_HANDLE_VALUE) 
	{
		::OutputDebugString(L"初始化错误，不支持该进程模块枚举\n"); 
		MessageBoxW(0,L"不支持该进程模块枚举",0,0);
	}

	MODULEENTRY32   ModuleEntry32;
	ModuleEntry32.dwSize = sizeof(MODULEENTRY32); 
	if(Module32First(hModuleSnap, &ModuleEntry32)) 
	{
		CString Filename,checkname;
		Filename=ModuleEntry32.szExePath;
		Filename.MakeUpper();
		checkname=Name;
		checkname.MakeUpper();
		output.Format(L"dll文件地址: %x\r\n",ModuleEntry32.szExePath);
		if(Filename.Find(checkname,0)>0)
		{
			return (DWORD)ModuleEntry32.modBaseAddr;
		}

	}
}
//////////////////////////////////////////////////////////////////////////////////////////////////////// 枚举DLL模块地址

DWORD JysNT::EnumProcessesdll(LPCWSTR ProcessName,LPCWSTR DllName)
{
	CString output;
	DWORD processid;
	HANDLE processH=0;
	HANDLE handle=::CreateToolhelp32Snapshot(TH32CS_SNAPALL,0);
	PROCESSENTRY32 Info;
	Info.dwSize = sizeof(PROCESSENTRY32);
	if(::Process32First(handle,&Info))
	{
		do{
			if( _tcsicmp(Info.szExeFile, ProcessName) == 0 )
			{
				processid=Info.th32ProcessID;
			}
		}
		while(::Process32Next(handle,&Info)); 
		::CloseHandle(handle);
	}

	HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,processid);

	if (hModuleSnap == INVALID_HANDLE_VALUE) 
	{
		::OutputDebugString(L"初始化错误，不支持该进程模块枚举\n"); 
		MessageBoxW(0,L"不支持该进程模块枚举",0,0);
	}

	MODULEENTRY32   ModuleEntry32;
	ModuleEntry32.dwSize = sizeof(MODULEENTRY32); 
	if(Module32First(hModuleSnap, &ModuleEntry32)) 
	{ 
		while (Module32Next(hModuleSnap, &ModuleEntry32))
		{    
			SHFILEINFO sfi;
			int nFlag;
			nFlag=SHGFI_USEFILEATTRIBUTES | SHGFI_DISPLAYNAME | SHGFI_ICON| SHGFI_SMALLICON;
			if (SHGetFileInfo (ModuleEntry32.szExePath, FILE_ATTRIBUTE_NORMAL, &sfi, sizeof(SHFILEINFO),nFlag))
			{
				CString Filename,checkname;
				Filename=ModuleEntry32.szExePath;
				Filename.MakeUpper();
				checkname=DllName;
				checkname.MakeUpper();
				if(Filename.Find(checkname,0)>0)
				{
					//output.Format(L"dll文件地址: %x\r\n",ModuleEntry32.modBaseAddr);
					return (DWORD)ModuleEntry32.modBaseAddr;
				}
			}

		}
	}
}
////////////////////////////////////////////////////////////////////////////////////////////////////////搜索内存

unsigned char *JysNT:: MemSearch(const unsigned char *mem, const int memSize, const unsigned char *patt, const int pattSize)
{
	if (memSize <= 0 || pattSize <= 0)
	{
		return 0;
	}

	int i;

	int td[256];
	for (int c=0; c<256; ++c)
	{
		td[c] = pattSize + 1;
	}
	const unsigned char *p;
	for (p=patt, i=0; i<pattSize; ++p, ++i)
	{
		td[*p] = pattSize - (p - patt);
	}

	const unsigned char *t, *tx = mem;

	while (tx + pattSize <= mem + memSize)
	{
		for (p=patt, t=tx, i=0; i<pattSize; ++p, ++t, ++i)
		{
			if (*p != *t)
			{
				break;
			}
		}
		if (i == pattSize)
		{
			return (unsigned char*)tx;
		}
		tx += td[tx[pattSize]];
	}
	return 0;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////多字节转宽字节

BOOL JysNT::AnsiToUcs(const CStringA &strAnsi, CStringW &strUcs) ///USES_CONVERSION;
{
	// Ansi 转换为 Ucs
	int iRet = ::MultiByteToWideChar(CP_ACP, 0, strAnsi, -1, NULL, 0);
	if (iRet == 0)
		return FALSE;
	WCHAR *szBuff = new WCHAR[iRet];
	iRet = ::MultiByteToWideChar(CP_ACP, 0, strAnsi, -1, szBuff, iRet);
	if (iRet == 0)
		return FALSE;
	strUcs = szBuff;
	delete [] szBuff;
	return TRUE;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////宽字节转多字节

BOOL JysNT::UcsToAnsi(const CStringW &strUcs, CStringA &strAnsi) ///USES_CONVERSION;
{
	// Ucs 转换为 Ansi
	int iRet = WideCharToMultiByte(CP_ACP, 0, strUcs, -1, NULL, 0, NULL, NULL);
	if (iRet == 0)
		return FALSE;
	CHAR *szBuff = new CHAR[iRet ];
	iRet = WideCharToMultiByte(CP_ACP, 0, strUcs, -1, szBuff, iRet, NULL, NULL);
	if (iRet == 0)
		return FALSE;
	strAnsi = szBuff;
	delete [] szBuff;
	return TRUE;
}


BOOL EnableDebugPrivilege() 
{ 
HANDLE hToken; 
BOOL fOk=FALSE; 
if(OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES,&hToken)) 
{ 
TOKEN_PRIVILEGES tp; 
tp.PrivilegeCount=1; 
if(!LookupPrivilegeValue(NULL,SE_DEBUG_NAME,&tp.Privileges[0].Luid)) 
printf("Can't lookup privilege value.\n"); 
tp.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED; 
if(!AdjustTokenPrivileges(hToken,FALSE,&tp,sizeof(tp),NULL,NULL)) 
printf("Can't adjust privilege value.\n"); 
fOk=(GetLastError()==ERROR_SUCCESS); 
CloseHandle(hToken); 
} 
return fOk; 
} 