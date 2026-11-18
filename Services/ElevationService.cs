using System.Windows;
using System.Diagnostics;
using System.Security.Principal;

namespace HashLyte.Services
{
    public static class ElevationService
    {
        public static bool IsRunningAsAdministrator()
        {
            using WindowsIdentity identity =
                WindowsIdentity.GetCurrent();

            WindowsPrincipal principal =
                new(identity);

            return principal.IsInRole(
                WindowsBuiltInRole.Administrator);
        }

        public static string GetCurrentIdentity()
        {
            using WindowsIdentity identity =
                WindowsIdentity.GetCurrent();

            return identity.Name;
        }

        public static void RestartAsAdministrator()
        {
            string? executablePath =
                Environment.ProcessPath;

            if (string.IsNullOrWhiteSpace(executablePath))
            {
                throw new InvalidOperationException(
                    "HashLyte could not determine its executable path.");
            }

            ProcessStartInfo startInfo =
                new()
                {
                    FileName = executablePath,

                    UseShellExecute = true,

                    Verb = "runas",

                    WorkingDirectory =
                        AppContext.BaseDirectory
                };

            Process.Start(startInfo);

            Application.Current.Shutdown();
        }
    }
}