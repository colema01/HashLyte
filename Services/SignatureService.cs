using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using HashLyte.Models;

namespace HashLyte.Services
{
    public sealed class SignatureService
    {
        private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 =
            new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

        public SignatureInfo Inspect(string filePath)
        {
            int trustResult = VerifyTrust(filePath);

            try
            {
                using X509Certificate certificate =
                    X509Certificate.CreateFromSignedFile(filePath);

                using X509Certificate2 certificate2 =
                    new(certificate);

                string status =
                    trustResult == 0
                        ? "VALID"
                        : $"SIGNED BUT INVALID (0x{trustResult:X8})";

                return new SignatureInfo
                {
                    Status = status,
                    Signer = certificate2.GetNameInfo(
                        X509NameType.SimpleName,
                        false),

                    Subject = certificate2.Subject,
                    Issuer = certificate2.Issuer,
                    Thumbprint = certificate2.Thumbprint ?? "",
                    ValidFrom = certificate2.NotBefore,
                    ValidTo = certificate2.NotAfter
                };
            }
            catch
            {
                return new SignatureInfo
                {
                    Status =
                        trustResult == 0
                            ? "SIGNED"
                            : "UNSIGNED"
                };
            }
        }

        private static int VerifyTrust(string filePath)
        {
            WINTRUST_FILE_INFO fileInfo =
                new(filePath);

            WINTRUST_DATA trustData =
                new(fileInfo);

            try
            {
                return WinVerifyTrust(
                    IntPtr.Zero,
                    WINTRUST_ACTION_GENERIC_VERIFY_V2,
                    ref trustData);
            }
            finally
            {
                fileInfo.Dispose();
                trustData.Dispose();
            }
        }

        [DllImport(
            "wintrust.dll",
            ExactSpelling = true,
            SetLastError = true,
            CharSet = CharSet.Unicode)]
        private static extern int WinVerifyTrust(
            IntPtr hwnd,
            [MarshalAs(UnmanagedType.LPStruct)]
            Guid pgActionID,
            ref WINTRUST_DATA pWVTData);

        [StructLayout(
            LayoutKind.Sequential,
            CharSet = CharSet.Unicode)]
        private struct WINTRUST_FILE_INFO_NATIVE
        {
            public uint cbStruct;
            public IntPtr pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }

        private sealed class WINTRUST_FILE_INFO : IDisposable
        {
            public IntPtr Pointer { get; }

            public WINTRUST_FILE_INFO(string filePath)
            {
                WINTRUST_FILE_INFO_NATIVE native =
                    new()
                    {
                        cbStruct =
                            (uint)Marshal.SizeOf<
                                WINTRUST_FILE_INFO_NATIVE>(),

                        pcwszFilePath =
                            Marshal.StringToCoTaskMemUni(
                                filePath),

                        hFile = IntPtr.Zero,
                        pgKnownSubject = IntPtr.Zero
                    };

                Pointer =
                    Marshal.AllocCoTaskMem(
                        Marshal.SizeOf<
                            WINTRUST_FILE_INFO_NATIVE>());

                Marshal.StructureToPtr(
                    native,
                    Pointer,
                    false);
            }

            public void Dispose()
            {
                if (Pointer == IntPtr.Zero)
                    return;

                WINTRUST_FILE_INFO_NATIVE native =
                    Marshal.PtrToStructure<
                        WINTRUST_FILE_INFO_NATIVE>(
                        Pointer);

                if (native.pcwszFilePath != IntPtr.Zero)
                {
                    Marshal.FreeCoTaskMem(
                        native.pcwszFilePath);
                }

                Marshal.FreeCoTaskMem(Pointer);
            }
        }

        [StructLayout(
            LayoutKind.Sequential,
            CharSet = CharSet.Unicode)]
        private struct WINTRUST_DATA
        {
            public uint cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public uint dwUIChoice;
            public uint fdwRevocationChecks;
            public uint dwUnionChoice;
            public IntPtr pFile;
            public uint dwStateAction;
            public IntPtr hWVTStateData;
            public IntPtr pwszURLReference;
            public uint dwProvFlags;
            public uint dwUIContext;
            public IntPtr pSignatureSettings;

            public WINTRUST_DATA(
                WINTRUST_FILE_INFO fileInfo)
            {
                cbStruct =
                    (uint)Marshal.SizeOf<
                        WINTRUST_DATA>();

                pPolicyCallbackData =
                    IntPtr.Zero;

                pSIPClientData =
                    IntPtr.Zero;

                // WTD_UI_NONE
                dwUIChoice = 2;

                // WTD_REVOKE_NONE
                fdwRevocationChecks = 0;

                // WTD_CHOICE_FILE
                dwUnionChoice = 1;

                pFile =
                    fileInfo.Pointer;

                // WTD_STATEACTION_IGNORE
                dwStateAction = 0;

                hWVTStateData =
                    IntPtr.Zero;

                pwszURLReference =
                    IntPtr.Zero;

                dwProvFlags = 0;

                dwUIContext = 0;

                pSignatureSettings =
                    IntPtr.Zero;
            }

            public void Dispose()
            {
                // Structure contains no separately
                // allocated buffers owned here.
            }
        }
    }
}