#pragma once
//在这里添加头文件

#include <iostream>
#include <Windows.h>
#include <atlfile.h>
#include <winsock2.h>
#include <iphlpapi.h>

#pragma comment(lib, "IPHLPAPI.lib")
using namespace std;

//在这里定义类
class LogFileHelper
{
public:
	static LogFileHelper* Instance()
	{
		static LogFileHelper logFile_;
		return &logFile_;
	}

	LogFileHelper()
	{
		InitLogFile();

		CreatLogFile();
	}

	~LogFileHelper()
	{ 
		CloseLogFile(); 
	}
	
	CString LogFileGetIP()
	{
		CString LocalIP = "";
		//BYTE MAC = NULL;
		CString LogFileName = "";
		int nRel = 0;
		PIP_ADAPTER_INFO pIpAdapterInfo = new IP_ADAPTER_INFO();

		if(pIpAdapterInfo == NULL)
		{
			OutputDebugStringA("NetProtect ：Error allocating memory needed to call GetAdaptersinfo");
		}
   
		unsigned long stSize = sizeof(IP_ADAPTER_INFO);
    
		nRel = GetAdaptersInfo(pIpAdapterInfo,&stSize);
    
		if (ERROR_BUFFER_OVERFLOW == nRel)
		{
			if(pIpAdapterInfo != NULL)
			{
				delete pIpAdapterInfo;
				pIpAdapterInfo = NULL;
			}
		
		   pIpAdapterInfo = (PIP_ADAPTER_INFO)new BYTE[stSize];
			if(pIpAdapterInfo == NULL)
			{
				OutputDebugStringA("NetProtect ：Error allocating memory needed to call GetAdaptersinfo!");
			}
			nRel=GetAdaptersInfo(pIpAdapterInfo,&stSize);    
		}
		if (ERROR_SUCCESS == nRel)
		{
			IP_ADDR_STRING *pIpAddrString =&(pIpAdapterInfo->IpAddressList);
			/*do //不考虑一个网卡多ip的情况
			{*/
				LocalIP = pIpAddrString->IpAddress.String;//ip
				//pIpAddrString=pIpAddrString->Next;
			
			/*} while (pIpAddrString);*/
    
		}
		
		if(!LocalIP.IsEmpty())
		{
			return LocalIP;
		}
		//释放内存空间
		if (pIpAdapterInfo != NULL)
		{
			delete pIpAdapterInfo;
			pIpAdapterInfo = NULL;
		}
	
		
	}

	CString LogFileGetMAC()
	{
		CString LocalMAC = "";
		u_char g_ucLocalMac[6];
		char mac[32];
		int nRel = 0;
		u_char *p = NULL;
		PIP_ADAPTER_INFO pIpAdapterInfo = new IP_ADAPTER_INFO();

		if(pIpAdapterInfo == NULL)
		{
			OutputDebugStringA("NetProtect ：Error allocating memory needed to call GetAdaptersinfo");
		}
   
		unsigned long stSize = sizeof(IP_ADAPTER_INFO);
    
		nRel = GetAdaptersInfo(pIpAdapterInfo,&stSize);
    
		if (ERROR_BUFFER_OVERFLOW == nRel)
		{
			if(pIpAdapterInfo != NULL)
			{
				delete pIpAdapterInfo;
				pIpAdapterInfo = NULL;
			}
		
		   pIpAdapterInfo = (PIP_ADAPTER_INFO)new BYTE[stSize];
			if(pIpAdapterInfo == NULL)
			{
				OutputDebugStringA("NetProtect ：Error allocating memory needed to call GetAdaptersinfo!");
			}
			nRel=GetAdaptersInfo(pIpAdapterInfo,&stSize);    
		}
		if (ERROR_SUCCESS == nRel)
		{
			memset(mac,0,32);
			memcpy(g_ucLocalMac,pIpAdapterInfo->Address,6);
			p = g_ucLocalMac;
			printf("MAC Address:%02X%02X%02X%02X%02X%02X\n",p[0],p[1],p[2],p[3],p[4],p[5]);
			
			sprintf(mac,"%02X%02X%02X%02X%02X%02X\n",p[0],p[1],p[2],p[3],p[4],p[5]);
			printf("mac:%s\n",mac);
			LocalMAC.Format(_T("%s"),mac);
    
		}
		/*LogFileName.Format(_T("%s%s%s%s"),IP,"-",MAC,".txt");*/
		if(LocalMAC.IsEmpty())
		{
			return LogFileName;
		}
		//释放内存空间
		if (pIpAdapterInfo != NULL)
		{
			delete pIpAdapterInfo;
			pIpAdapterInfo = NULL;
		}
	
		return LocalMAC;
	}
	BOOL InitLogFile()
	{
		CString log_strIP = LogFileGetIP();
		CString log_strMAC = LogFileGetMAC(); 
		CString log_strFileName = log_strIP + L"-" + log_strMAC;

		CRegKey wpKey;
		LPCTSTR lpszKeyName = _T("Software\\Topsec\\EndpointPlantform\\Config");
		if (ERROR_SUCCESS == wpKey.Open(HKEY_LOCAL_MACHINE,lpszKeyName,KEY_ALL_ACCESS))
		{
			CString stFilePath = "" ;
			
			ULONG Length = 2048;

			Length = 2048;
			if (wpKey.QueryStringValue(_T("AllTempDir"),stFilePath .GetBuffer(Length),&Length) == ERROR_SUCCESS)
			{
				if(stFilePath.IsEmpty())
				{
					if(ERROR_SUCCESS == wpKey.SetValue("C:\\Program Files\\Topsec\\EndpointPlantform\\Log","AllTempDir"))
					{
						Length = 2048;
						if (wpKey.QueryStringValue(_T("AllTempDir"),stFilePath .GetBuffer(Length),&Length) == ERROR_SUCCESS)
						{
							m_strLogFilePath  = stFilePath;
							
						}
						else
						{
							m_strLogFilePath = "C:\\Program Files\\Topsec\\EndpointPlantform\\Log";
						}
					}
					
				}
				else
				{
					stFilePath = stFilePath.Trim(";");
					m_strLogFilePath  = stFilePath;
					printf("%s\n",m_strLogFilePath  );
					
				}
				m_strLogFilePath.Format(_T("%s%s%s%s"),m_strLogFilePath,"\\",log_strFileName,".txt");
				//m_strLogFilePath += L"\\" + log_strFileName + L".txt";	
				printf("日志存储路径为 %s\n" ,m_strLogFilePath );
				OutputDebugStringA(m_strLogFilePath);
				return 1;
			}
		
		}
	}

	BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)   // 令牌、权限名字、打开还是关闭权限
	{
		TOKEN_PRIVILEGES tp; // 该结构包含一个数组，数据组的每个项指明了权限的类型和要进行的操作
		LUID luid;

		// 查找
		if (!LookupPrivilegeValue(
			NULL,            // 系统的名字,null,在本地系统上查找权限 lookup privilege on local system
			lpszPrivilege,   // 要找的权限名 privilege to lookup 
			&luid))        // 通过指针返回权限的LUID receives LUID of privilege
		{
			printf("LookupPrivilegeValue error: %u\n", GetLastError());
			return FALSE;
		}

		tp.PrivilegeCount = 1;    // 要修改的特权数目
		tp.Privileges[0].Luid = luid;    // 代表不同特权类型
		if (bEnablePrivilege)
			tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		else
			tp.Privileges[0].Attributes = 0;

		// 调整访问令牌的权限
		if (!AdjustTokenPrivileges(
			hToken,// OpenProcessToken第三个指针参数传出的访问令牌的句柄
			FALSE, // 是否禁用所有所有的特权
			&tp,    // 指明要修改的权限
			sizeof(TOKEN_PRIVILEGES),    // PreviousState的长度
			&oldPls,   // 存放修改前的访问权限的信息，可空
			(PDWORD)NULL))    // 实际PreviousState结构返回的大小
		{
			printf("AdjustTokenPrivileges error: %u\n", GetLastError());
			return FALSE;
		}
		if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
		{
			printf("令牌没有这个权限 \n");
			return FALSE;
		}
		return TRUE;
	}

	BOOL getFiles( BOOL choiseUser)
	{
		HANDLE hToken;
		BOOL bRet = OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken ); // 获取进程的令牌句柄，进程句柄(当前进程)、全权访问令牌、 进程令牌句柄 （就是AdjustTokenPrivileges的第一个参数）
		if (bRet != TRUE)
		{
			cout << "获取令牌句柄失败!" << endl;
			return FALSE;
		}
		BOOL set = SetPrivilege(hToken, SE_DEBUG_NAME, choiseUser);
		if (!set || GetLastError() != ERROR_SUCCESS) {
			// 设置权限失败
			cout << "提升权限失败 error：" << GetLastError() << endl;
			return FALSE;
		}
		// 权限设置成功，继续执行
		cout << "权限设置完成" << endl;
		cout << GetLastError()<<endl;
	}
	BOOL CreatLogFile()
	{
		HRESULT myni;
		if (LogFile.Create(m_strLogFilePath, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_WRITE|FILE_SHARE_READ, CREATE_NEW) != S_OK)
		{
			if (5 == GetLastError())
			{
				getFiles(TRUE);
				//权限问题
			}
			if ((myni = LogFile.Create(m_strLogFilePath, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_WRITE|FILE_SHARE_READ, OPEN_EXISTING)) != S_OK)
			{
				if (5 == GetLastError())
				{
					//权限问题
					getFiles(TRUE);
				}
				char* str ;
				sprintf(str,"LogFileHelper: Create Log File Fail!!       错误码   %d \r\n",GetLastError());
				OutputDebugString(str);
			}
		}
		
		OutputDebugString(L"LogFile : 日志文件的目录在 " + m_strLogFilePath + L"\n");
		return TRUE;
	}

	BOOL CloseLogFile()
	{
		LogFile.Close();
		return TRUE;
	}

	
		//获取即时时间
BOOL WriteLogMsg(CStringA msg, DWORD msgStrlen, DWORD errorCode = 0, BOOL IsCommon = TRUE)
{
	CString isOpenLogTool = L"1";

	//根据 IsCommon 判断是否要访问注册表, true不访问
	if ( IsCommon )
	{
		isOpenLogTool = CMiscHelper::RegGetString(L"EndpointPlantform\\DLP\\IsOpenTepLog");
	}
	if (0 != isOpenLogTool.CompareNoCase(L"1"))
	{
		//没有开启分析模式，不要记录日志
		return TRUE;
	}
	//获取即时时间
	SYSTEMTIME	sys;
	GetLocalTime( &sys );
	memset(m_presentTime, 0, sizeof( m_presentTime ));
	sprintf(m_presentTime, "%d/%02d/%02d %02d:%02d:%02d", sys.wYear, sys.wMonth, sys.wDay, sys.wHour, sys.wMinute, sys.wSecond);
	CStringA msgToWrite;
	switch(errorCode)
	{
	case 2:
		msgToWrite.Format(" %s    error = %d  系统找不到指定的文件。 \r\n", msg, errorCode);
	case 5:
		msgToWrite.Format(" %s    error = %d  拒绝访问。 \r\n", msg, errorCode);
	case 1072:
		msgToWrite.Format(" %s    error = %d  指定的服务已标记为删除。 \r\n", msg, errorCode);
	case 1056:
		msgToWrite.Format(" %s    error = %d  服务的实例已在运行中。 \r\n", msg, errorCode);
	default:
		//msgToWrite.Format(" %s    error = %d  \r\n", msgToWrite, errorCode);
		msgToWrite.Format(" %s", msg);
	}
	LogFile.Seek(0,2);
	LogFile.Write(m_presentTime, strlen( m_presentTime ) );
	LogFile.Seek(4,FILE_CURRENT);
	LogFile.Write(msgToWrite, msgToWrite.GetLength());
	return TRUE;
}

CString GetLogFilePath()
{
	return m_strLogFilePath;
}
protected:
private:
	CAtlFile LogFile;
	CString m_strLogFilePath;
	char m_presentTime[256];
	TOKEN_PRIVILEGES oldPls;
};

#define CLogFileHelper() LogFileHelper::Instance()


