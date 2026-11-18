using HashLyte.Models;

namespace HashLyte.Services
{
    public sealed class ProcessRiskService
    {
        public ProcessRiskAssessment Assess(
            RemoteProcessInfo process,
            IReadOnlyCollection<RemoteProcessInfo> allProcesses)
        {
            int score = 0;

            List<string> findings = new();

            string path =
                process.ExecutablePath ?? "";

            string commandLine =
                process.CommandLine ?? "";

            string name =
                process.Name ?? "";

            // --------------------------------------------------------
            // Unusual / user-writable execution locations
            // --------------------------------------------------------

            if (ContainsPathPart(path, @"\AppData\Local\Temp\") ||
                ContainsPathPart(path, @"\Windows\Temp\"))
            {
                score += 30;

                findings.Add(
                    "Executable is running from a temporary directory.");
            }

            if (ContainsPathPart(path, @"\AppData\Roaming\"))
            {
                score += 20;

                findings.Add(
                    "Executable is running from AppData\\Roaming.");
            }

            if (ContainsPathPart(path, @"\Downloads\"))
            {
                score += 25;

                findings.Add(
                    "Executable is running directly from a Downloads folder.");
            }

            if (ContainsPathPart(path, @"\Desktop\"))
            {
                score += 15;

                findings.Add(
                    "Executable is running directly from a user Desktop.");
            }

            if (ContainsPathPart(path, @"\Users\Public\"))
            {
                score += 20;

                findings.Add(
                    "Executable is running from the Public user profile.");
            }

            // ProgramData itself is not malicious, so keep this low.
            if (ContainsPathPart(path, @"\ProgramData\"))
            {
                score += 5;

                findings.Add(
                    "Executable is running from ProgramData.");
            }

            // --------------------------------------------------------
            // Missing executable information
            // --------------------------------------------------------

            if (string.IsNullOrWhiteSpace(path))
            {
                score += 5;

                findings.Add(
                    "Executable path was not available through WMI.");
            }

            // --------------------------------------------------------
            // Common LOLBin / script-host processes
            //
            // These are NOT automatically malicious.
            // We are only saying they deserve context.
            // --------------------------------------------------------

            string lowerName =
                name.ToLowerInvariant();

            string[] interestingProcesses =
            {
                "powershell.exe",
                "pwsh.exe",
                "cmd.exe",
                "mshta.exe",
                "wscript.exe",
                "cscript.exe",
                "rundll32.exe",
                "regsvr32.exe",
                "certutil.exe",
                "bitsadmin.exe"
            };

            if (interestingProcesses.Contains(lowerName))
            {
                score += 10;

                findings.Add(
                    $"{name} is a powerful Windows utility that warrants context.");
            }

            // --------------------------------------------------------
            // Encoded PowerShell
            // --------------------------------------------------------

            if ((lowerName == "powershell.exe" ||
                 lowerName == "pwsh.exe") &&
                ContainsAny(
                    commandLine,
                    "-enc",
                    "-encodedcommand"))
            {
                score += 35;

                findings.Add(
                    "PowerShell command line appears to use encoded commands.");
            }

            // --------------------------------------------------------
            // Hidden PowerShell
            // --------------------------------------------------------

            if ((lowerName == "powershell.exe" ||
                 lowerName == "pwsh.exe") &&
                ContainsAny(
                    commandLine,
                    "-windowstyle hidden",
                    "-w hidden"))
            {
                score += 20;

                findings.Add(
                    "PowerShell appears configured to run with a hidden window.");
            }

            // --------------------------------------------------------
            // Parent process checks
            // --------------------------------------------------------

            RemoteProcessInfo? parent =
                allProcesses.FirstOrDefault(
                    x => x.Pid == process.ParentPid);

            if (parent != null)
            {
                string parentName =
                    parent.Name.ToLowerInvariant();

                // Office launching scripting/shell utilities
                if (IsOfficeProcess(parentName) &&
                    IsShellOrScriptProcess(lowerName))
                {
                    score += 35;

                    findings.Add(
                        $"{parent.Name} spawned {process.Name}.");
                }

                // Browser -> scripting engine can be worth reviewing.
                if (IsBrowser(parentName) &&
                    IsShellOrScriptProcess(lowerName))
                {
                    score += 20;

                    findings.Add(
                        $"{parent.Name} spawned {process.Name}.");
                }
            }

            // --------------------------------------------------------
            // Decide level
            // --------------------------------------------------------

            string level =
                score switch
                {
                    >= 60 => "High",
                    >= 35 => "Suspicious",
                    >= 20 => "Interesting",
                    _ => "Normal"
                };

            return new ProcessRiskAssessment
            {
                Score = score,
                Level = level,
                Findings = findings
            };
        }

        private static bool ContainsPathPart(
            string path,
            string value)
        {
            return path.Contains(
                value,
                StringComparison.OrdinalIgnoreCase);
        }

        private static bool ContainsAny(
            string text,
            params string[] values)
        {
            return values.Any(
                value =>
                    text.Contains(
                        value,
                        StringComparison.OrdinalIgnoreCase));
        }

        private static bool IsOfficeProcess(
            string name)
        {
            return name is
                "winword.exe" or
                "excel.exe" or
                "powerpnt.exe" or
                "outlook.exe" or
                "onenote.exe";
        }

        private static bool IsBrowser(
            string name)
        {
            return name is
                "chrome.exe" or
                "msedge.exe" or
                "firefox.exe" or
                "iexplore.exe";
        }

        private static bool IsShellOrScriptProcess(
            string name)
        {
            return name is
                "powershell.exe" or
                "pwsh.exe" or
                "cmd.exe" or
                "mshta.exe" or
                "wscript.exe" or
                "cscript.exe";
        }
    }
}