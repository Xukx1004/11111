#pragma once
//���������ͷ�ļ�

#include <iostream>
#include <Windows.h>
#include <atlfile.h>
#include <winsock2.h>
#include <iphlpapi.h>

#pragma comment(lib, "IPHLPAPI.lib")
using namespace std;

//�����ﶨ����
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
			OutputDebugStringA("NetProtect ��Error allocating memory needed to call GetAdaptersinfo");
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
				OutputDebugStringA("NetProtect ��Error allocating memory needed to call GetAdaptersinfo!");
			}
			nRel=GetAdaptersInfo(pIpAdapterInfo,&stSize);    
		}
		if (ERROR_SUCCESS == nRel)
		{
			IP_ADDR_STRING *pIpAddrString =&(pIpAdapterInfo->IpAddressList);
			/*do //������һ��������ip�����
			{*/
				LocalIP = pIpAddrString->IpAddress.String;//ip
				//pIpAddrString=pIpAddrString->Next;
			
			/*} while (pIpAddrString);*/
    
		}
		
		if(!LocalIP.IsEmpty())
		{
			return LocalIP;
		}
		//�ͷ��ڴ�ռ�
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
			OutputDebugStringA("NetProtect ��Error allocating memory needed to call GetAdaptersinfo");
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
				OutputDebugStringA("NetProtect ��Error allocating memory needed to call GetAdaptersinfo!");
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
		//�ͷ��ڴ�ռ�
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
				printf("��־�洢·��Ϊ %s\n" ,m_strLogFilePath );
				OutputDebugStringA(m_strLogFilePath);
				return 1;
			}
		
		}
	}

	BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)   // ���ơ�Ȩ�����֡��򿪻��ǹر�Ȩ��
	{
		TOKEN_PRIVILEGES tp; // �ýṹ����һ�����飬�������ÿ����ָ����Ȩ�޵����ͺ�Ҫ���еĲ���
		LUID luid;

		// ����
		if (!LookupPrivilegeValue(
			NULL,            // ϵͳ������,null,�ڱ���ϵͳ�ϲ���Ȩ�� lookup privilege on local system
			lpszPrivilege,   // Ҫ�ҵ�Ȩ���� privilege to lookup 
			&luid))        // ͨ��ָ�뷵��Ȩ�޵�LUID receives LUID of privilege
		{
			printf("LookupPrivilegeValue error: %u\n", GetLastError());
			return FALSE;
		}

		tp.PrivilegeCount = 1;    // Ҫ�޸ĵ���Ȩ��Ŀ
		tp.Privileges[0].Luid = luid;    // ����ͬ��Ȩ����
		if (bEnablePrivilege)
			tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		else
			tp.Privileges[0].Attributes = 0;

		// �����������Ƶ�Ȩ��
		if (!AdjustTokenPrivileges(
			hToken,// OpenProcessToken������ָ����������ķ������Ƶľ��
			FALSE, // �Ƿ�����������е���Ȩ
			&tp,    // ָ��Ҫ�޸ĵ�Ȩ��
			sizeof(TOKEN_PRIVILEGES),    // PreviousState�ĳ���
			&oldPls,   // ����޸�ǰ�ķ���Ȩ�޵���Ϣ���ɿ�
			(PDWORD)NULL))    // ʵ��PreviousState�ṹ���صĴ�С
		{
			printf("AdjustTokenPrivileges error: %u\n", GetLastError());
			return FALSE;
		}
		if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
		{
			printf("����û�����Ȩ�� \n");
			return FALSE;
		}
		return TRUE;
	}

	BOOL getFiles( BOOL choiseUser)
	{
		HANDLE hToken;
		BOOL bRet = OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken ); // ��ȡ���̵����ƾ�������̾��(��ǰ����)��ȫȨ�������ơ� �������ƾ�� ������AdjustTokenPrivileges�ĵ�һ��������
		if (bRet != TRUE)
		{
			cout << "��ȡ���ƾ��ʧ��!" << endl;
			return FALSE;
		}
		BOOL set = SetPrivilege(hToken, SE_DEBUG_NAME, choiseUser);
		if (!set || GetLastError() != ERROR_SUCCESS) {
			// ����Ȩ��ʧ��
			cout << "����Ȩ��ʧ�� error��" << GetLastError() << endl;
			return FALSE;
		}
		// Ȩ�����óɹ�������ִ��
		cout << "Ȩ���������" << endl;
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
				//Ȩ������
			}
			if ((myni = LogFile.Create(m_strLogFilePath, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_WRITE|FILE_SHARE_READ, OPEN_EXISTING)) != S_OK)
			{
				if (5 == GetLastError())
				{
					//Ȩ������
					getFiles(TRUE);
				}
				char* str ;
				sprintf(str,"LogFileHelper: Create Log File Fail!!       ������   %d \r\n",GetLastError());
				OutputDebugString(str);
			}
		}
		
		OutputDebugString(L"LogFile : ��־�ļ���Ŀ¼�� " + m_strLogFilePath + L"\n");
		return TRUE;
	}

	BOOL CloseLogFile()
	{
		LogFile.Close();
		return TRUE;
	}

	
		//��ȡ��ʱʱ��
BOOL WriteLogMsg(CStringA msg, DWORD msgStrlen, DWORD errorCode = 0, BOOL IsCommon = TRUE)
{
	CString isOpenLogTool = L"1";

	//���� IsCommon �ж��Ƿ�Ҫ����ע���, true������
	if ( IsCommon )
	{
		isOpenLogTool = CMiscHelper::RegGetString(L"EndpointPlantform\\DLP\\IsOpenTepLog");
	}
	if (0 != isOpenLogTool.CompareNoCase(L"1"))
	{
		//û�п�������ģʽ����Ҫ��¼��־
		return TRUE;
	}
	//��ȡ��ʱʱ��
	SYSTEMTIME	sys;
	GetLocalTime( &sys );
	memset(m_presentTime, 0, sizeof( m_presentTime ));
	sprintf(m_presentTime, "%d/%02d/%02d %02d:%02d:%02d", sys.wYear, sys.wMonth, sys.wDay, sys.wHour, sys.wMinute, sys.wSecond);
	CStringA msgToWrite;
	switch(errorCode)
	{
	case 2:
		msgToWrite.Format(" %s    error = %d  ϵͳ�Ҳ���ָ�����ļ��� \r\n", msg, errorCode);
	case 5:
		msgToWrite.Format(" %s    error = %d  �ܾ����ʡ� \r\n", msg, errorCode);
	case 1072:
		msgToWrite.Format(" %s    error = %d  ָ���ķ����ѱ��Ϊɾ���� \r\n", msg, errorCode);
	case 1056:
		msgToWrite.Format(" %s    error = %d  �����ʵ�����������С� \r\n", msg, errorCode);
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


