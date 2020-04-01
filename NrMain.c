#include "NrPrecomp.h"

BOOL				g_BalancerLoaded	= TRUE;

PDRIVER_OBJECT		g_DriverObject		= NULL;

PDEVICE_OBJECT		g_TDDeviceObject	= NULL;

PDEVICE_OBJECT		m_Tcp6DeviceObject	= NULL;
PDEVICE_OBJECT		m_Udp6DeviceObject	= NULL;
PDEVICE_OBJECT		m_Raw6DeviceObject	= NULL;
PDEVICE_OBJECT		m_Ip6DeviceObject	= NULL;

BOOL				g_TcpIp6HaveMapped			= FALSE;
BOOL				g_TcpIp6HaveAttached		= FALSE;

BOOLEAN		ps_imgnotify	= FALSE;

ERESOURCE	g_netlplock;

DWORD		g_NpPid[256]			= {0};	

UNICODE_STRING	Explorer;
UNICODE_STRING	DlpPattern;
UNICODE_STRING	Noton;


ULONG g_MonitorPoint;


NTSTATUS DriverEntry(
					 PDRIVER_OBJECT	DriverObject,
					 PUNICODE_STRING RegistryPath
					 )
{
	ULONG				i;
	
	NTSTATUS			status;
	g_DriverObject = DriverObject;
	
	
	NrInitLists();
	NrInitConObjThread();//KeSetEvent后将pConnObj从g_PendingAddrList移到g_OpenAddrList
	NrInitActionAndRecycleThread();//从g_OotObjectList删除并加到g_FreeAddrList
	NRInitializeDevice(DriverObject);

	NrInitializeCallback(NrCallbackFunction);//??
	ExInitializeResourceLite(&g_netlplock);

	RtlInitUnicodeString(&Explorer,EXPLORER);
	RtlInitUnicodeString(&DlpPattern,PROTECT_NAME);
	RtlInitUnicodeString(&Noton,NOTON);
	

	//g_MonitorPoint |= Monitor_HTTP|Monitor_SMTP|Monitor_HTTPS|Monitor_IMAP;
	g_MonitorPoint |= Monitor_HTTP|Monitor_SMTP|Monitor_HTTPS|Monitor_IMAP|Monitor_FTP;
	KdPrint(("Nr_Tdi:g_MonitorPoint 1 %u",g_MonitorPoint));
	IsMonitorPoitOpen(&g_MonitorPoint);
	KdPrint(("Nr_Tdi:g_MonitorPoint 2 %u",g_MonitorPoint));
	for (i = 0;i < IRP_MJ_MAXIMUM_FUNCTION;i++)
	{
		DriverObject->MajorFunction[i]	= NRDefaultDisPatch;
	}

	DriverObject->DriverUnload									= NrUnload;
	DriverObject->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL]	= NRInternalDeviceControlDisPatch;//请求发送 I/O 管理器和其他操作系统组件，以及其他内核模式驱动程序

	PsSetCreateProcessNotifyRoutine(NRCreateProcessNotifyRoutine, FALSE);//记录不需要的进程的pid

	return STATUS_SUCCESS;
}

VOID	NRImageLoadNotifyRoutine(
								 PUNICODE_STRING	FullImageName,
								 HANDLE				ProcessId,
								 PIMAGE_INFO		ImageInfo
								 )
{
	LONG			pCompare	= 0;
	NTSTATUS		ntStatus	= STATUS_SUCCESS;
	UNICODE_STRING	pTcpIp6;

	RtlInitUnicodeString(&pTcpIp6,NR_XPTCPIP6_DEVICE_NAME);

	if (g_TcpIp6HaveMapped)
	{
		if (!g_TcpIp6HaveAttached)
		{
			ntStatus	= NRAttachToStack6(g_DriverObject);
			if (NT_SUCCESS(ntStatus))
			{
				g_TcpIp6HaveAttached	= TRUE;
			}
		}
	} 
	else
	{
		if (!g_TcpIp6HaveAttached)
		{
			pCompare	= RtlCompareUnicodeString(FullImageName,&pTcpIp6,TRUE);
			if (pCompare == 0)
			{
				g_TcpIp6HaveMapped	= TRUE;
			}
		}
	}
	return;
}

VOID NrUnload(IN  PDRIVER_OBJECT  DriverObject)
{
	if (ps_imgnotify == TRUE)
	{
		PsRemoveLoadImageNotifyRoutine(NRImageLoadNotifyRoutine);
	}

	PsSetCreateProcessNotifyRoutine(NRCreateProcessNotifyRoutine, TRUE);

	ExDeleteResourceLite(&g_netlplock);
}

VOID NRCreateProcessNotifyRoutine(HANDLE ParentId, HANDLE  ProcessId, BOOLEAN  Create)
{
	WCHAR	FileName[MAX_PATH+1]	= L"";
	BOOLEAN	Ret						= FALSE;

	__try
	{
		if (Create)
		{
			if (NR_GetProcessNameByProcessId(HandleToULong(ProcessId),FileName,MAX_PATH))
			{
				UNICODE_STRING FilePath;
				RtlInitUnicodeString(&FilePath,FileName);
				if (FsRtlIsNameInExpression(&DlpPattern,&FilePath,TRUE,NULL)	|| 
					FsRtlIsNameInExpression(&Noton,&FilePath,TRUE,NULL)	)		//|| 
					//FsRtlIsNameInExpression(&Explorer,&FilePath,TRUE,NULL))//NR_PatternMatch(PROTECT_NAME,FileName)
				{
					int j = 0;
					while (g_NpPid[j] != 0)
					{
						j++;
					}
					if (j<256)
					{
						g_NpPid[j] = HandleToULong(ProcessId);
					}
						
				}
			}
		}
		else
		{
			int i;
			for (i=0;i<256;i++)
			{
				if (g_NpPid[i] == HandleToULong(ProcessId))
				{
					g_NpPid[i] = 0;
				}
			}
		}

	}
	__except(1)
	{

	}

}

