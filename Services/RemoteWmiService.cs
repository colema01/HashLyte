using System.Management;
using HashLyte.Models;

namespace HashLyte.Services
{
    public sealed class RemoteWmiService
    {
        private ManagementScope? _scope;

        public bool IsConnected =>
            _scope?.IsConnected == true;

        public void ConnectWithCurrentCredentials(
            string computerName)
        {
            if (string.IsNullOrWhiteSpace(computerName))
            {
                throw new ArgumentException(
                    "Computer name is required.",
                    nameof(computerName));
            }

            ConnectionOptions options =
                new()
                {
                    Impersonation =
                        ImpersonationLevel.Impersonate,

                    Authentication =
                        AuthenticationLevel.PacketPrivacy,

                    EnablePrivileges = false,

                    Timeout =
                        TimeSpan.FromSeconds(15)
                };

            _scope =
                new ManagementScope(
                    $@"\\{computerName}\root\cimv2",
                    options);

            _scope.Connect();
        }

        public List<RemoteProcessInfo> GetProcesses()
        {
            EnsureConnected();

            List<RemoteProcessInfo> results =
                new();

            ObjectQuery query =
                new(
                    "SELECT " +
                    "ProcessId, " +
                    "ParentProcessId, " +
                    "Name, " +
                    "ExecutablePath, " +
                    "CommandLine, " +
                    "CreationDate " +
                    "FROM Win32_Process");

            using ManagementObjectSearcher searcher =
                new(
                    _scope,
                    query);

            foreach (ManagementObject process
                     in searcher.Get())
            {
                int pid =
                    Convert.ToInt32(
                        process["ProcessId"] ?? 0);

                int parentPid =
                    Convert.ToInt32(
                        process["ParentProcessId"] ?? 0);

                string user =
                    GetProcessOwner(process);

                DateTime? startTime =
                    GetCreationDate(process);

                results.Add(
                    new RemoteProcessInfo
                    {
                        Pid = pid,

                        ParentPid = parentPid,

                        Name =
                            process["Name"]?.ToString()
                            ?? "",

                        ExecutablePath =
                            process["ExecutablePath"]
                                ?.ToString()
                            ?? "",

                        CommandLine =
                            process["CommandLine"]
                                ?.ToString()
                            ?? "",

                        User = user,

                        StartTime = startTime
                    });
            }

            return results
                .OrderBy(x => x.Name)
                .ThenBy(x => x.Pid)
                .ToList();
        }

        public List<RemoteServiceInfo> GetServices()
        {
            EnsureConnected();

            List<RemoteServiceInfo> results =
                new();

            ObjectQuery query =
                new(
                    "SELECT " +
                    "Name, " +
                    "DisplayName, " +
                    "State, " +
                    "StartMode, " +
                    "StartName, " +
                    "PathName, " +
                    "ProcessId " +
                    "FROM Win32_Service");

            using ManagementObjectSearcher searcher =
                new(
                    _scope,
                    query);

            foreach (ManagementObject service
                     in searcher.Get())
            {
                results.Add(
                    new RemoteServiceInfo
                    {
                        Name =
                            service["Name"]
                                ?.ToString()
                            ?? "",

                        DisplayName =
                            service["DisplayName"]
                                ?.ToString()
                            ?? "",

                        State =
                            service["State"]
                                ?.ToString()
                            ?? "",

                        StartMode =
                            service["StartMode"]
                                ?.ToString()
                            ?? "",

                        StartAccount =
                            service["StartName"]
                                ?.ToString()
                            ?? "",

                        PathName =
                            service["PathName"]
                                ?.ToString()
                            ?? "",

                        ProcessId =
                            Convert.ToInt32(
                                service["ProcessId"]
                                ?? 0)
                    });
            }

            return results
                .OrderBy(x => x.Name)
                .ToList();
        }

        private static string GetProcessOwner(
            ManagementObject process)
        {
            try
            {
                object[] arguments =
                {
                    "",
                    ""
                };

                uint result =
                    Convert.ToUInt32(
                        process.InvokeMethod(
                            "GetOwner",
                            arguments));

                if (result != 0)
                    return "";

                string username =
                    arguments[0]?.ToString()
                    ?? "";

                string domain =
                    arguments[1]?.ToString()
                    ?? "";

                if (string.IsNullOrWhiteSpace(domain))
                    return username;

                return $@"{domain}\{username}";
            }
            catch
            {
                return "";
            }
        }

        private static DateTime? GetCreationDate(
            ManagementObject process)
        {
            try
            {
                string? raw =
                    process["CreationDate"]
                        ?.ToString();

                if (string.IsNullOrWhiteSpace(raw))
                    return null;

                return
                    ManagementDateTimeConverter
                        .ToDateTime(raw);
            }
            catch
            {
                return null;
            }
        }

        private void EnsureConnected()
        {
            if (_scope == null ||
                !_scope.IsConnected)
            {
                throw new InvalidOperationException(
                    "Remote WMI is not connected.");
            }
        }

        public void Disconnect()
        {
            _scope = null;
        }
    }
}