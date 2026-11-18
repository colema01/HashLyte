using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace HashLyte.Services
{
    public sealed class SmbConnectionManager : IDisposable
    {
        private const int RESOURCETYPE_DISK = 0x00000001;
        private const int CONNECT_TEMPORARY = 0x00000004;

        private string? _connectedShare;
        private bool _createdByHashLyte;

        public bool IsConnected =>
            !string.IsNullOrWhiteSpace(_connectedShare);

        public string? ConnectedShare =>
            _connectedShare;

        public void ConnectWithCurrentCredentials(string computerName)
        {
            if (string.IsNullOrWhiteSpace(computerName))
                throw new ArgumentException(
                    "Computer name is required.",
                    nameof(computerName));

            computerName = computerName
                .Trim()
                .TrimStart('\\');

            string remoteShare =
                $@"\\{computerName}\IPC$";

            NETRESOURCE resource = new()
            {
                dwType = RESOURCETYPE_DISK,
                lpRemoteName = remoteShare
            };

            int result = WNetAddConnection2(
                ref resource,
                null,
                null,
                CONNECT_TEMPORARY);

            if (result == 1219)
            {
                throw new InvalidOperationException(
                    "Windows already has a connection to this computer " +
                    "using different credentials.");
            }

            if (result != 0)
            {
                throw new Win32Exception(result);
            }

            _connectedShare = remoteShare;
            _createdByHashLyte = true;
        }

        public void Disconnect()
        {
            if (!_createdByHashLyte ||
                string.IsNullOrWhiteSpace(_connectedShare))
            {
                return;
            }

            // Do NOT force the connection closed.
            WNetCancelConnection2(
                _connectedShare,
                0,
                false);

            _connectedShare = null;
            _createdByHashLyte = false;
        }

        public void Dispose()
        {
            Disconnect();
        }

        [StructLayout(
            LayoutKind.Sequential,
            CharSet = CharSet.Unicode)]
        private struct NETRESOURCE
        {
            public int dwScope;
            public int dwType;
            public int dwDisplayType;
            public int dwUsage;

            public string? lpLocalName;
            public string? lpRemoteName;
            public string? lpComment;
            public string? lpProvider;
        }

        [DllImport(
            "mpr.dll",
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        private static extern int WNetAddConnection2(
            ref NETRESOURCE lpNetResource,
            string? lpPassword,
            string? lpUsername,
            int dwFlags);

        [DllImport(
            "mpr.dll",
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        private static extern int WNetCancelConnection2(
            string lpName,
            int dwFlags,
            bool fForce);
    }
}