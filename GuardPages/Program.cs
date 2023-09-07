using System;
using System.Diagnostics;
using System.Runtime.InteropServices;


namespace GuardPages
{
    internal class Program
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] public static extern IntPtr GetModuleHandle([MarshalAs(UnmanagedType.LPWStr)] string lpModuleName);
        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)] static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        [DllImport("kernel32.dll")] static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32.dll", SetLastError = true)] public static extern IntPtr GetCurrentProcess();
        // PVOID WINAPI AddVectoredExceptionHandler(_In_ ULONG FirstHandler, _In_ PVECTORED_EXCEPTION_HANDLER VectoredHandler);
        [DllImport("kernel32.dll")] public static extern IntPtr AddVectoredExceptionHandler(uint FirstHandler, IntPtr VectoredHandler_POINTER);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);
        [DllImport("User32.dll")] public static extern int MessageBox(int h, string m, string c, int type);

        const int PAGE_EXECUTE_READ = 0x20;
        const int PAGE_GUARD = 0x100;
        const uint STATUS_GUARD_PAGE_VIOLATION = 2147483649; // Exception code = 0x80000001
        const long EXCEPTION_CONTINUE_EXECUTION = -1;
        const long EXCEPTION_CONTINUE_SEARCH = 0;
        const long EXCEPTION_EXECUTE_HANDLER = 1;

        public delegate long hookDel(IntPtr ExceptionInfo_Pointer);
        public delegate void testDel();


        public struct EXCEPTION_POINTERS
        {
            public EXCEPTION_RECORD exceptionRecord;
            public CONTEXT contextRecord;

        }

        // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record
        /*
        typedef struct _EXCEPTION_RECORD64 {
            DWORD    ExceptionCode;
            DWORD ExceptionFlags;
            DWORD64 ExceptionRecord;
            DWORD64 ExceptionAddress;
            DWORD NumberParameters;
            DWORD __unusedAlignment;
            DWORD64 ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
        } EXCEPTION_RECORD64, *PEXCEPTION_RECORD64;
        */
        public struct EXCEPTION_RECORD
        {
            public uint ExceptionCode;
            public uint ExceptionFlags;
            public IntPtr pExceptionRecord;
            public IntPtr ExceptionAddress;
            public uint NumberParameters;
            // public uint unusedAlignment;
            public IntPtr ExceptionInformation;
        }

        // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context       
        public struct CONTEXT
        {
            public UInt64 P1Home;
            public UInt64 P2Home;
            public UInt64 P3Home;
            public UInt64 P4Home;
            public UInt64 P5Home;
            public UInt64 P6Home;
            // Control Flags
            public UInt32 ContextFlags;
            public UInt32 MxCsr;
            // Segment Register and Processor Flags
            public UInt16 SegCs;
            public UInt16 SegDs;
            public UInt16 SegEs;
            public UInt16 SegFs;
            public UInt16 SegGs;
            public UInt16 SegSs;
            public UInt32 EFlags;
            // Debug Registers
            public UInt64 Dr0;
            public UInt64 Dr1;
            public UInt64 Dr2;
            public UInt64 Dr3;
            public UInt64 Dr6;
            public UInt64 Dr7;
            // Registers
            public UInt64 Rax;
            public UInt64 Rcx;
            public UInt64 Rdx;
            public UInt64 Rbx;
            public UInt64 Rsp;
            public UInt64 Rbp;
            public UInt64 Rsi;
            public UInt64 Rdi;
            public UInt64 R8;
            public UInt64 R9;
            public UInt64 R10;
            public UInt64 R11;
            public UInt64 R12;
            public UInt64 R13;
            public UInt64 R14;
            public UInt64 R15;
            public IntPtr Rip;
            //    public anon0[512] byte,
            /*
            union {
            XMM_SAVE_AREA32 FltSave,
            NEON128 Q[16],
            ULONGLONG D[32],
            struct {
            M128A Header[2],
            M128A Legacy[8],
            M128A Xmm0,
            M128A Xmm1,
            M128A Xmm2,
            M128A Xmm3,
            M128A Xmm4,
            M128A Xmm5,
            M128A Xmm6,
            M128A Xmm7,
            M128A Xmm8,
            M128A Xmm9,
            M128A Xmm10,
            M128A Xmm11,
            M128A Xmm12,
            M128A Xmm13,
            M128A Xmm14,
            M128A Xmm15,
            } DUMMYSTRUCTNAME,
            UInt32 S[32],
            } DUMMYUNIONNAME,
            public M128A VectorRegister[26],
            public UInt64 VectorControl,
            public UInt64 DebugControl,
            public UInt64 LastBranchToRip,
            public UInt64 LastBranchFromRip,
            public UInt64 LastExceptionToRip,
            public UInt64 LastExceptionFromRip
            */
        };
    

        /*
        // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context   
        public struct CONTEXT
        {
            public IntPtr P1Home;
            public IntPtr P2Home;
            public IntPtr P3Home;
            public IntPtr P4Home;
            public IntPtr P5Home;
            public IntPtr P6Home;
            // Control Flags
            public uint ContextFlags;
            public uint MxCsr;
            // Segment Register and Processor Flags
            public ushort SegCs;
            public ushort SegDs;
            public ushort SegEs;
            public ushort SegFs;
            public ushort SegGs;
            public ushort SegSs;
            public uint EFlags;
            // Debug Registers
            public IntPtr Dr0;
            public IntPtr Dr1;
            public IntPtr Dr2;
            public IntPtr Dr3;
            public IntPtr Dr6;
            public IntPtr Dr7;
            // Registers
            public IntPtr Rax;
            public IntPtr Rcx;
            public IntPtr Rdx;
            public IntPtr Rbx;
            public IntPtr Rsp;
            public IntPtr Rbp;
            public IntPtr Rsi;
            public IntPtr Rdi;
            public IntPtr R8;
            public IntPtr R9;
            public IntPtr R10;
            public IntPtr R11;
            public IntPtr R12;
            public IntPtr R13;
            public IntPtr R14;
            public IntPtr R15;
            public IntPtr Rip;
        };*/

        private static T MarshalBytesTo<T>(byte[] bytes)
        {
            GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            T theStructure = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            handle.Free();
            return theStructure;
        }

        public static void test() {
            Console.WriteLine("[+] Message after hooking");
            Debug.WriteLine("[+] Debug 2");
            return;
        }

        static void printDebugInfo(EXCEPTION_POINTERS ExceptionInfo) {
            Console.WriteLine("\n[+] Debug Information...");
            Console.WriteLine("[+] ExceptionInfo.exceptionRecord.ExceptionCode:        0x{0}", ExceptionInfo.exceptionRecord.ExceptionCode.ToString("X"));
            Console.WriteLine("[+] ExceptionInfo.exceptionRecord.ExceptionFlags:       0x{0}", ExceptionInfo.exceptionRecord.ExceptionFlags.ToString("X"));
            Console.WriteLine("[+] ExceptionInfo.exceptionRecord.pExceptionRecord:     0x{0}", ExceptionInfo.exceptionRecord.pExceptionRecord.ToString("X"));
            Console.WriteLine("[+] ExceptionInfo.exceptionRecord.ExceptionAddress:     0x{0}", ExceptionInfo.exceptionRecord.ExceptionAddress.ToString("X"));
            Console.WriteLine("[+] ExceptionInfo.exceptionRecord.NumberParameters:     0x{0}", ExceptionInfo.exceptionRecord.NumberParameters.ToString("X"));
            // Console.WriteLine("[+] ExceptionInfo.exceptionRecord.unusedAlignment:      0x{0}", ExceptionInfo.exceptionRecord.unusedAlignment.ToString("X"));
            Console.WriteLine("[+] ExceptionInfo.exceptionRecord.ExceptionInformation: 0x{0}",   ExceptionInfo.exceptionRecord.ExceptionInformation.ToString("X"));
            
            Console.WriteLine("");

            Console.WriteLine("[+] ExceptionInfo.contextRecord.P1Home:                 0x{0}", ExceptionInfo.contextRecord.P1Home.ToString("X"));
            Console.WriteLine("[+] ExceptionInfo.contextRecord.P2Home:                 0x{0}", ExceptionInfo.contextRecord.P2Home.ToString("X"));
            Console.WriteLine("[+] ExceptionInfo.contextRecord.P3Home:                 0x{0}", ExceptionInfo.contextRecord.P3Home.ToString("X"));
            Console.WriteLine("[+] ExceptionInfo.contextRecord.P4Home:                 0x{0}", ExceptionInfo.contextRecord.P4Home.ToString("X"));
            Console.WriteLine("[+] ExceptionInfo.contextRecord.P5Home:                 0x{0}", ExceptionInfo.contextRecord.P5Home.ToString("X"));
            Console.WriteLine("[+] ExceptionInfo.contextRecord.P6Home:                 0x{0}", ExceptionInfo.contextRecord.P6Home.ToString("X"));
            Console.WriteLine("[+] ExceptionInfo.contextRecord.ContextFlags:           0x{0}", ExceptionInfo.contextRecord.ContextFlags.ToString("X"));
            Console.WriteLine("[+] ExceptionInfo.contextRecord.MxCsr:                  0x{0}", ExceptionInfo.contextRecord.MxCsr.ToString("X"));
            Console.WriteLine("[+] ExceptionInfo.contextRecord.SegCs:                  0x{0}", ExceptionInfo.contextRecord.SegCs.ToString("X"));
            Console.WriteLine("[+] ExceptionInfo.contextRecord.SegDs:                  0x{0}", ExceptionInfo.contextRecord.SegDs.ToString("X"));
            Console.WriteLine("[+] ExceptionInfo.contextRecord.SegEs:                  0x{0}", ExceptionInfo.contextRecord.SegEs.ToString("X"));
            Console.WriteLine("[+] ExceptionInfo.contextRecord.SegFs:                  0x{0}", ExceptionInfo.contextRecord.SegFs.ToString("X"));
            Console.WriteLine("[+] ExceptionInfo.contextRecord.SegGs:                  0x{0}", ExceptionInfo.contextRecord.SegGs.ToString("X"));
            Console.WriteLine("[+] ExceptionInfo.contextRecord.SegSs:                  0x{0}", ExceptionInfo.contextRecord.SegSs.ToString("X"));
            Console.WriteLine("[+] ExceptionInfo.contextRecord.EFlags:                 0x{0}", ExceptionInfo.contextRecord.EFlags.ToString("X"));
            Console.WriteLine("[+] ExceptionInfo.contextRecord.Dr0:                    0x{0}", ExceptionInfo.contextRecord.Dr0.ToString("X"));
            Console.WriteLine("[+] ExceptionInfo.contextRecord.Dr1:                    0x{0}", ExceptionInfo.contextRecord.Dr1.ToString("X"));
            Console.WriteLine("[+] ExceptionInfo.contextRecord.Dr2:                    0x{0}", ExceptionInfo.contextRecord.Dr2.ToString("X"));
            Console.WriteLine("[+] ExceptionInfo.contextRecord.Dr3:                    0x{0}", ExceptionInfo.contextRecord.Dr3.ToString("X"));
            Console.WriteLine("[+] ExceptionInfo.contextRecord.Dr6:                    0x{0}", ExceptionInfo.contextRecord.Dr6.ToString("X"));
            Console.WriteLine("[+] ExceptionInfo.contextRecord.Dr7:                    0x{0}", ExceptionInfo.contextRecord.Dr7.ToString("X"));
            Console.WriteLine("[+] ExceptionInfo.contextRecord.Rax:                    0x{0}", ExceptionInfo.contextRecord.Rax.ToString("X"));
            Console.WriteLine("[+] ExceptionInfo.contextRecord.Rcx:                    0x{0}", ExceptionInfo.contextRecord.Rcx.ToString("X"));
            Console.WriteLine("[+] ExceptionInfo.contextRecord.Rdx:                    0x{0}", ExceptionInfo.contextRecord.Rdx.ToString("X"));
            Console.WriteLine("[+] ExceptionInfo.contextRecord.Rbx:                    0x{0}", ExceptionInfo.contextRecord.Rbx.ToString("X"));
            Console.WriteLine("[+] ExceptionInfo.contextRecord.Rsp:                    0x{0}", ExceptionInfo.contextRecord.Rsp.ToString("X"));
            Console.WriteLine("[+] ExceptionInfo.contextRecord.Rbp:                    0x{0}", ExceptionInfo.contextRecord.Rbp.ToString("X"));
            Console.WriteLine("[+] ExceptionInfo.contextRecord.Rsi:                    0x{0}", ExceptionInfo.contextRecord.Rsi.ToString("X"));
            Console.WriteLine("[+] ExceptionInfo.contextRecord.Rdi:                    0x{0}", ExceptionInfo.contextRecord.Rdi.ToString("X"));
            Console.WriteLine("[+] ExceptionInfo.contextRecord.R8:                     0x{0}", ExceptionInfo.contextRecord.R8.ToString("X"));
            Console.WriteLine("[+] ExceptionInfo.contextRecord.R9:                     0x{0}", ExceptionInfo.contextRecord.R9.ToString("X"));
            Console.WriteLine("[+] ExceptionInfo.contextRecord.R10:                    0x{0}", ExceptionInfo.contextRecord.R10.ToString("X"));
            Console.WriteLine("[+] ExceptionInfo.contextRecord.R11:                    0x{0}", ExceptionInfo.contextRecord.R11.ToString("X"));
            Console.WriteLine("[+] ExceptionInfo.contextRecord.R12:                    0x{0}", ExceptionInfo.contextRecord.R12.ToString("X"));
            Console.WriteLine("[+] ExceptionInfo.contextRecord.R13:                    0x{0}", ExceptionInfo.contextRecord.R13.ToString("X"));
            Console.WriteLine("[+] ExceptionInfo.contextRecord.R14:                    0x{0}", ExceptionInfo.contextRecord.R14.ToString("X"));
            Console.WriteLine("[+] ExceptionInfo.contextRecord.R15:                    0x{0}", ExceptionInfo.contextRecord.R15.ToString("X"));
            Console.WriteLine("[+] ExceptionInfo.contextRecord.Rip:                    0x{0}", ExceptionInfo.contextRecord.Rip.ToString("X"));

            Console.WriteLine("");
        }


        static long hhandler(IntPtr ExceptionInfo_Pointer) {
            IntPtr hProcess = Process.GetCurrentProcess().Handle;
            byte[] data1 = new byte[Marshal.SizeOf(typeof(IntPtr))];
            ReadProcessMemory(hProcess, ExceptionInfo_Pointer, data1, data1.Length, out _);
            IntPtr aux = MarshalBytesTo<IntPtr>(data1);

            byte[] data2 = new byte[Marshal.SizeOf(typeof(EXCEPTION_POINTERS))];
            ReadProcessMemory(hProcess, aux, data2, data2.Length, out _);
            EXCEPTION_POINTERS ExceptionInfo = MarshalBytesTo<EXCEPTION_POINTERS>(data2);

            if (ExceptionInfo.exceptionRecord.ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)
            {
                printDebugInfo(ExceptionInfo);
                Console.WriteLine("[+] Captured exception with exception code:\t0x{0}", ExceptionInfo.exceptionRecord.ExceptionCode.ToString("X"));
                Console.WriteLine("[+] ExceptionInfo.contextRecord.Eip 1:  \t0x{0}", ExceptionInfo.contextRecord.Rip.ToString("X"));
        
                unsafe
                {
                    var b = new testDel(test);
                    IntPtr testPtr = Marshal.GetFunctionPointerForDelegate(b);
                    Console.WriteLine("[+] Function test address:  \t\t\t0x{0}", testPtr.ToString("X"));
                    ExceptionInfo.contextRecord.Rip = (IntPtr)testPtr;
                }

                Console.WriteLine("[+] ExceptionInfo.contextRecord.Eip 2: \t\t0x{0}", ExceptionInfo.contextRecord.Rip.ToString("X"));
                Debug.WriteLine("[+] Debug 1");
                // System.Threading.Thread.Sleep(30000);
                return EXCEPTION_CONTINUE_EXECUTION;
            }
            return EXCEPTION_CONTINUE_SEARCH;
        }



        static void Main(string[] args)
        {
            String dll_name =  "User32.dll";
            String func_name = "MessageBoxA";

            Console.WriteLine("[+] Setting Page Guard...");
            IntPtr dll_handle = GetModuleHandle(dll_name);
            IntPtr func_address = GetProcAddress(dll_handle, func_name);
            
            bool vp = VirtualProtectEx(GetCurrentProcess(), func_address, (UIntPtr) 1, PAGE_EXECUTE_READ | PAGE_GUARD, out _);
            if (vp) {
                Console.WriteLine("[+] Guard Page set in address: \t\t\t0x{0} ({1}.{2})", func_address.ToString("X"), dll_name, func_name);
            }

            IntPtr hookPtr = IntPtr.Zero;
            unsafe {
                var aux_hook = new hookDel(hhandler);
                hookPtr = Marshal.GetFunctionPointerForDelegate(aux_hook);
            }
            Console.WriteLine("[+] Function hhandler address: \t\t\t0x{0}", hookPtr.ToString("X"));
            AddVectoredExceptionHandler((uint)1, hookPtr);
            Console.WriteLine("\n[+] Calling MessageBoxA...");
            MessageBox(0, "Test 2", "Test 2", 0);
        }
    }
}
