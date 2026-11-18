using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using HashLyte.Models;
using HashLyte.Services;

namespace HashLyte
{
    public partial class MainWindow : Window
    {
        private readonly SmbConnectionManager _smbConnection = new();
        private readonly RemoteFileBrowserService _fileBrowser = new();
        private readonly FileInvestigationService _fileInvestigator = new();
        private readonly RemoteWmiService _remoteWmi = new();
        private readonly ProcessTreeService _processTreeService = new();
        private readonly ProcessRiskService _processRiskService = new();

        private string? _currentTarget;
        private string? _currentPath;
        private string? _rootPath;

        private string? _currentSha256;
        private string? _currentProcessSha256;
        private string? _currentTreeSha256;

        private RemoteProcessInfo? _selectedProcess;
        private RemoteProcessInfo? _selectedTreeProcess;

        private List<RemoteFileItem> _currentDirectoryItems = new();
        private List<RemoteProcessInfo> _processes = new();
        private List<RemoteServiceInfo> _services = new();

        public MainWindow()
        {
            InitializeComponent();

            UpdateRunningIdentity();

            Closed += (_, _) =>
            {
                _remoteWmi.Disconnect();
                _smbConnection.Dispose();
            };
        }

        // ============================================================
        // IDENTITY / ELEVATION
        // ============================================================

        private void UpdateRunningIdentity()
        {
            string identity =
                ElevationService.GetCurrentIdentity();

            bool isAdmin =
                ElevationService.IsRunningAsAdministrator();

            RunningIdentityText.Text =
                $"Running as: {identity} | " +
                (isAdmin
                    ? "Administrator"
                    : "Standard");

            RestartAsAdminButton.IsEnabled =
                !isAdmin;
        }

        private void RestartAsAdminButton_Click(
            object sender,
            RoutedEventArgs e)
        {
            try
            {
                ConnectionStatusText.Text =
                    "Requesting Administrator privileges...";

                ElevationService.RestartAsAdministrator();
            }
            catch (Win32Exception ex)
                when (ex.NativeErrorCode == 1223)
            {
                ConnectionStatusText.Text =
                    "Administrator restart was cancelled.";
            }
            catch (Exception ex)
            {
                ConnectionStatusText.Text =
                    $"Unable to restart as Administrator: {ex.Message}";
            }
        }

        // ============================================================
        // CONNECTION
        // ============================================================

        private async void ConnectButton_Click(
            object sender,
            RoutedEventArgs e)
        {
            string target =
                TargetComputerTextBox.Text.Trim();

            if (string.IsNullOrWhiteSpace(target))
            {
                ConnectionStatusText.Text =
                    "Enter a computer name.";

                return;
            }

            target =
                target.TrimStart('\\');

            string adminShare =
                $@"\\{target}\C$";

            ConnectButton.IsEnabled =
                false;

            ConnectionStatusText.Text =
                $"Connecting to {target}...";

            bool smbConnected =
                false;

            bool wmiConnected =
                false;

            try
            {
                await Task.Run(() =>
                    _smbConnection
                        .ConnectWithCurrentCredentials(
                            target));

                bool accessible =
                    await Task.Run(() =>
                        Directory.Exists(
                            adminShare));

                if (!accessible)
                {
                    throw new UnauthorizedAccessException(
                        $"Unable to access {adminShare}.");
                }

                smbConnected =
                    true;
            }
            catch (Exception ex)
            {
                ConnectionStatusText.Text =
                    $"SMB connection failed: {ex.Message}";

                ConnectButton.IsEnabled =
                    true;

                return;
            }

            try
            {
                ConnectionStatusText.Text =
                    $"SMB connected. Connecting to WMI on {target}...";

                await Task.Run(() =>
                    _remoteWmi
                        .ConnectWithCurrentCredentials(
                            target));

                wmiConnected =
                    true;
            }
            catch (Exception ex)
            {
                ConnectionStatusText.Text =
                    $"SMB connected, but WMI failed: {ex.Message}";
            }

            _currentTarget =
                target;

            _rootPath =
                adminShare;

            _currentPath =
                adminShare;

            TargetComputerTextBox.IsEnabled =
                false;

            ConnectButton.IsEnabled =
                false;

            DisconnectButton.IsEnabled =
                true;

            await LoadDirectoryAsync(
                adminShare);

            if (wmiConnected)
            {
                await LoadRemoteWmiDataAsync();
            }

            ConnectionStatusText.Text =
                $"Connected to {target}. " +
                $"SMB: {(smbConnected ? "OK" : "Failed")} | " +
                $"WMI: {(wmiConnected ? "OK" : "Unavailable")}";
        }

        private void DisconnectButton_Click(
            object sender,
            RoutedEventArgs e)
        {
            _remoteWmi.Disconnect();
            _smbConnection.Disconnect();

            _currentTarget =
                null;

            _currentPath =
                null;

            _rootPath =
                null;

            _currentSha256 =
                null;

            _currentProcessSha256 =
                null;

            _currentTreeSha256 =
                null;

            _selectedProcess =
                null;

            _selectedTreeProcess =
                null;

            _currentDirectoryItems.Clear();
            _processes.Clear();
            _services.Clear();

            RemoteFilesGrid.ItemsSource =
                null;

            ProcessesGrid.ItemsSource =
                null;

            ServicesGrid.ItemsSource =
                null;

            ProcessTreeView.ItemsSource =
                null;

            CurrentPathTextBox.Text =
                "";

            FileSearchTextBox.Text =
                "";

            ProcessSearchTextBox.Text =
                "";

            ServiceSearchTextBox.Text =
                "";

            SuspiciousOnlyCheckBox.IsChecked =
                false;

            SelectedFileNameText.Text =
                "None selected";

            SelectedRemotePathText.Text =
                "";

            SelectedLocalPathText.Text =
                "";

            InvestigationResultsText.Text =
                "No file investigated.";

            ProcessDetailsText.Text =
                "No process selected.";

            ProcessServiceText.Text =
                "No process selected.";

            TreeProcessDetailsText.Text =
                "No process selected.";

            TreeServiceText.Text =
                "No process selected.";

            InvestigateFileButton.IsEnabled =
                false;

            CopyHashButton.IsEnabled =
                false;

            VirusTotalButton.IsEnabled =
                false;

            InvestigateProcessExecutableButton.IsEnabled =
                false;

            ProcessCopyHashButton.IsEnabled =
                false;

            ProcessVirusTotalButton.IsEnabled =
                false;

            TreeInvestigateExecutableButton.IsEnabled =
                false;

            TreeCopyHashButton.IsEnabled =
                false;

            TreeVirusTotalButton.IsEnabled =
                false;

            UpButton.IsEnabled =
                false;

            TargetComputerTextBox.IsEnabled =
                true;

            ConnectButton.IsEnabled =
                true;

            DisconnectButton.IsEnabled =
                false;

            ConnectionStatusText.Text =
                "Not connected";
        }

        // ============================================================
        // WMI
        // ============================================================

        private async Task LoadRemoteWmiDataAsync()
        {
            try
            {
                ConnectionStatusText.Text =
                    "Loading processes...";

                _processes =
                    await Task.Run(() =>
                        _remoteWmi.GetProcesses());

                ApplyProcessFilter();

                ConnectionStatusText.Text =
                    "Loading services...";

                _services =
                    await Task.Run(() =>
                        _remoteWmi.GetServices());

                ServicesGrid.ItemsSource =
                    _services;

                BuildProcessTree();
            }
            catch (Exception ex)
            {
                ConnectionStatusText.Text =
                    $"WMI inventory failed: {ex.Message}";
            }
        }

        // ============================================================
        // PROCESS TREE
        // ============================================================

        private void BuildProcessTree()
        {
            List<ProcessTreeNode> tree =
                _processTreeService.BuildTree(
                    _processes);

            ProcessTreeView.ItemsSource =
                tree;
        }

        private async void RefreshProcessTreeButton_Click(
            object sender,
            RoutedEventArgs e)
        {
            if (!_remoteWmi.IsConnected)
            {
                ConnectionStatusText.Text =
                    "Remote WMI is not connected.";

                return;
            }

            try
            {
                ConnectionStatusText.Text =
                    "Refreshing process inventory...";

                _processes =
                    await Task.Run(() =>
                        _remoteWmi.GetProcesses());

                ApplyProcessFilter();

                BuildProcessTree();

                ConnectionStatusText.Text =
                    $"Process tree refreshed. {_processes.Count} processes loaded.";
            }
            catch (Exception ex)
            {
                ConnectionStatusText.Text =
                    $"Unable to refresh process tree: {ex.Message}";
            }
        }

        private void ProcessTreeView_SelectedItemChanged(
            object sender,
            RoutedPropertyChangedEventArgs<object> e)
        {
            _currentTreeSha256 =
                null;

            TreeCopyHashButton.IsEnabled =
                false;

            TreeVirusTotalButton.IsEnabled =
                false;

            if (ProcessTreeView.SelectedItem
                is not ProcessTreeNode node)
            {
                _selectedTreeProcess =
                    null;

                TreeProcessDetailsText.Text =
                    "No process selected.";

                TreeServiceText.Text =
                    "No process selected.";

                TreeInvestigateExecutableButton.IsEnabled =
                    false;

                return;
            }

            RemoteProcessInfo process =
                node.Process;

            _selectedTreeProcess =
                process;

            ProcessRiskAssessment risk =
                _processRiskService.Assess(
                    process,
                    _processes);

            TreeProcessDetailsText.Text =
                BuildProcessRuntimeText(
                    process) +
                "\n\n" +
                BuildRiskText(
                    risk);

            ShowTreeServiceAssociation(
                process);

            TreeInvestigateExecutableButton.IsEnabled =
                !string.IsNullOrWhiteSpace(
                    process.ExecutablePath);
        }

        private void ShowTreeServiceAssociation(
            RemoteProcessInfo process)
        {
            List<RemoteServiceInfo> services =
                _services
                    .Where(x =>
                        x.ProcessId == process.Pid &&
                        process.Pid != 0)
                    .ToList();

            if (services.Count == 0)
            {
                TreeServiceText.Text =
                    "No Windows service is currently associated with this PID.";

                return;
            }

            TreeServiceText.Text =
                string.Join(
                    "\n\n",
                    services.Select(service =>
                        BuildServiceText(
                            service)));
        }

        private async void TreeInvestigateExecutableButton_Click(
            object sender,
            RoutedEventArgs e)
        {
            if (_selectedTreeProcess == null)
                return;

            if (string.IsNullOrWhiteSpace(
                _selectedTreeProcess.ExecutablePath))
            {
                return;
            }

            TreeInvestigateExecutableButton.IsEnabled =
                false;

            TreeCopyHashButton.IsEnabled =
                false;

            TreeVirusTotalButton.IsEnabled =
                false;

            _currentTreeSha256 =
                null;

            try
            {
                ConnectionStatusText.Text =
                    $"Investigating {_selectedTreeProcess.Name}...";

                string uncPath =
                    ConvertTargetPathToUnc(
                        _selectedTreeProcess.ExecutablePath);

                if (!File.Exists(uncPath))
                {
                    throw new FileNotFoundException(
                        "HashLyte could not access the executable over SMB.",
                        uncPath);
                }

                FileInvestigationResult result =
                    await Task.Run(() =>
                        _fileInvestigator.Investigate(
                            uncPath,
                            _selectedTreeProcess.ExecutablePath));

                _currentTreeSha256 =
                    result.Sha256;

                TreeCopyHashButton.IsEnabled =
                    true;

                TreeVirusTotalButton.IsEnabled =
                    true;

                ProcessRiskAssessment risk =
                    _processRiskService.Assess(
                        _selectedTreeProcess,
                        _processes);

                TreeProcessDetailsText.Text =
                    $"PROCESS\n" +
                    $"────────────────────────────\n" +
                    BuildProcessRuntimeText(
                        _selectedTreeProcess) +
                    "\n\n" +
                    BuildRiskText(
                        risk) +
                    "\n\n" +
                    BuildFileInvestigationText(
                        result);

                ConnectionStatusText.Text =
                    $"Investigation complete for {_selectedTreeProcess.Name}.";
            }
            catch (Exception ex)
            {
                ConnectionStatusText.Text =
                    $"Tree process investigation failed: {ex.Message}";
            }
            finally
            {
                TreeInvestigateExecutableButton.IsEnabled =
                    true;
            }
        }

        private void TreeCopyHashButton_Click(
            object sender,
            RoutedEventArgs e)
        {
            CopyHash(
                _currentTreeSha256);
        }

        private void TreeVirusTotalButton_Click(
            object sender,
            RoutedEventArgs e)
        {
            OpenVirusTotal(
                _currentTreeSha256);
        }

        // ============================================================
        // FILE BROWSER
        // ============================================================

        private async Task LoadDirectoryAsync(
            string path)
        {
            try
            {
                ConnectionStatusText.Text =
                    $"Loading {path}...";

                _currentDirectoryItems =
                    await Task.Run(() =>
                        _fileBrowser.GetItems(
                            path));

                _currentPath =
                    path;

                CurrentPathTextBox.Text =
                    path;

                FileSearchTextBox.Text =
                    "";

                ApplyFileFilter();

                UpButton.IsEnabled =
                    !string.Equals(
                        _currentPath,
                        _rootPath,
                        StringComparison.OrdinalIgnoreCase);
            }
            catch (UnauthorizedAccessException)
            {
                ConnectionStatusText.Text =
                    $"Access denied to {path}.";
            }
            catch (Exception ex)
            {
                ConnectionStatusText.Text =
                    $"Unable to load directory: {ex.Message}";
            }
        }

        private void FileSearchTextBox_TextChanged(
            object sender,
            TextChangedEventArgs e)
        {
            ApplyFileFilter();
        }

        private void ApplyFileFilter()
        {
            if (RemoteFilesGrid == null)
                return;

            string search =
                FileSearchTextBox?.Text.Trim()
                ?? "";

            if (string.IsNullOrWhiteSpace(
                search))
            {
                RemoteFilesGrid.ItemsSource =
                    _currentDirectoryItems;

                return;
            }

            RemoteFilesGrid.ItemsSource =
                _currentDirectoryItems
                    .Where(x =>
                        x.Name.Contains(
                            search,
                            StringComparison.OrdinalIgnoreCase))
                    .ToList();
        }

        private async void RemoteFilesGrid_MouseDoubleClick(
            object sender,
            MouseButtonEventArgs e)
        {
            if (RemoteFilesGrid.SelectedItem
                is not RemoteFileItem item)
            {
                return;
            }

            if (!item.IsDirectory)
                return;

            await LoadDirectoryAsync(
                item.FullPath);
        }

        private void RemoteFilesGrid_SelectionChanged(
            object sender,
            SelectionChangedEventArgs e)
        {
            _currentSha256 =
                null;

            CopyHashButton.IsEnabled =
                false;

            VirusTotalButton.IsEnabled =
                false;

            InvestigationResultsText.Text =
                "No file investigated.";

            if (RemoteFilesGrid.SelectedItem
                is not RemoteFileItem item)
            {
                InvestigateFileButton.IsEnabled =
                    false;

                SelectedFileNameText.Text =
                    "None selected";

                SelectedRemotePathText.Text =
                    "";

                SelectedLocalPathText.Text =
                    "";

                return;
            }

            SelectedFileNameText.Text =
                item.Name;

            SelectedRemotePathText.Text =
                item.FullPath;

            SelectedLocalPathText.Text =
                ConvertUncToTargetPath(
                    item.FullPath);

            InvestigateFileButton.IsEnabled =
                !item.IsDirectory;
        }

        private async void UpButton_Click(
            object sender,
            RoutedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(
                    _currentPath) ||
                string.IsNullOrWhiteSpace(
                    _rootPath))
            {
                return;
            }

            if (string.Equals(
                _currentPath,
                _rootPath,
                StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            DirectoryInfo? parent =
                Directory.GetParent(
                    _currentPath);

            if (parent == null)
                return;

            string parentPath =
                parent.FullName;

            if (!parentPath.StartsWith(
                _rootPath,
                StringComparison.OrdinalIgnoreCase))
            {
                parentPath =
                    _rootPath;
            }

            await LoadDirectoryAsync(
                parentPath);
        }

        // ============================================================
        // FILE INVESTIGATION
        // ============================================================

        private async void InvestigateFileButton_Click(
            object sender,
            RoutedEventArgs e)
        {
            if (RemoteFilesGrid.SelectedItem
                is not RemoteFileItem item)
            {
                return;
            }

            if (item.IsDirectory)
                return;

            string targetPath =
                ConvertUncToTargetPath(
                    item.FullPath);

            InvestigateFileButton.IsEnabled =
                false;

            CopyHashButton.IsEnabled =
                false;

            VirusTotalButton.IsEnabled =
                false;

            _currentSha256 =
                null;

            InvestigationResultsText.Text =
                "Investigating file...";

            try
            {
                FileInvestigationResult result =
                    await Task.Run(() =>
                        _fileInvestigator.Investigate(
                            item.FullPath,
                            targetPath));

                _currentSha256 =
                    result.Sha256;

                CopyHashButton.IsEnabled =
                    true;

                VirusTotalButton.IsEnabled =
                    true;

                InvestigationResultsText.Text =
                    BuildFileInvestigationText(
                        result);

                ConnectionStatusText.Text =
                    $"Investigation complete for {result.FileName}.";
            }
            catch (Exception ex)
            {
                InvestigationResultsText.Text =
                    $"Investigation failed:\n{ex.Message}";

                ConnectionStatusText.Text =
                    "File investigation failed.";
            }
            finally
            {
                InvestigateFileButton.IsEnabled =
                    true;
            }
        }

        // ============================================================
        // PROCESS FILTERING / TRIAGE
        // ============================================================

        private void ProcessSearchTextBox_TextChanged(
            object sender,
            TextChangedEventArgs e)
        {
            ApplyProcessFilter();
        }

        private void SuspiciousOnlyCheckBox_Changed(
            object sender,
            RoutedEventArgs e)
        {
            ApplyProcessFilter();
        }

        private void ApplyProcessFilter()
        {
            if (ProcessesGrid == null)
                return;

            IEnumerable<RemoteProcessInfo> filtered =
                _processes;

            string search =
                ProcessSearchTextBox?.Text.Trim()
                ?? "";

            if (!string.IsNullOrWhiteSpace(
                search))
            {
                filtered =
                    filtered.Where(x =>
                        x.Name.Contains(
                            search,
                            StringComparison.OrdinalIgnoreCase)

                        ||

                        x.Pid.ToString()
                            .Contains(search)

                        ||

                        x.User.Contains(
                            search,
                            StringComparison.OrdinalIgnoreCase)

                        ||

                        x.ExecutablePath.Contains(
                            search,
                            StringComparison.OrdinalIgnoreCase)

                        ||

                        x.CommandLine.Contains(
                            search,
                            StringComparison.OrdinalIgnoreCase));
            }

            if (SuspiciousOnlyCheckBox?.IsChecked ==
                true)
            {
                filtered =
                    filtered.Where(process =>
                    {
                        ProcessRiskAssessment assessment =
                            _processRiskService.Assess(
                                process,
                                _processes);

                        return assessment.IsSuspicious;
                    });
            }

            ProcessesGrid.ItemsSource =
                filtered.ToList();
        }

        private void ProcessesGrid_SelectionChanged(
            object sender,
            SelectionChangedEventArgs e)
        {
            _currentProcessSha256 =
                null;

            ProcessCopyHashButton.IsEnabled =
                false;

            ProcessVirusTotalButton.IsEnabled =
                false;

            if (ProcessesGrid.SelectedItem
                is not RemoteProcessInfo process)
            {
                _selectedProcess =
                    null;

                ProcessDetailsText.Text =
                    "No process selected.";

                ProcessServiceText.Text =
                    "No process selected.";

                InvestigateProcessExecutableButton.IsEnabled =
                    false;

                return;
            }

            _selectedProcess =
                process;

            ProcessRiskAssessment risk =
                _processRiskService.Assess(
                    process,
                    _processes);

            ProcessDetailsText.Text =
                BuildProcessRuntimeText(
                    process) +
                "\n\n" +
                BuildRiskText(
                    risk);

            List<RemoteServiceInfo> services =
                _services
                    .Where(x =>
                        x.ProcessId == process.Pid &&
                        process.Pid != 0)
                    .ToList();

            if (services.Count == 0)
            {
                ProcessServiceText.Text =
                    "No Windows service is currently associated with this PID.";
            }
            else
            {
                ProcessServiceText.Text =
                    string.Join(
                        "\n\n",
                        services.Select(service =>
                            BuildServiceText(
                                service)));
            }

            InvestigateProcessExecutableButton.IsEnabled =
                !string.IsNullOrWhiteSpace(
                    process.ExecutablePath);
        }

        private async void InvestigateProcessExecutableButton_Click(
            object sender,
            RoutedEventArgs e)
        {
            if (_selectedProcess ==
                null)
            {
                return;
            }

            if (string.IsNullOrWhiteSpace(
                _selectedProcess.ExecutablePath))
            {
                return;
            }

            InvestigateProcessExecutableButton.IsEnabled =
                false;

            ProcessCopyHashButton.IsEnabled =
                false;

            ProcessVirusTotalButton.IsEnabled =
                false;

            _currentProcessSha256 =
                null;

            try
            {
                string uncPath =
                    ConvertTargetPathToUnc(
                        _selectedProcess.ExecutablePath);

                if (!File.Exists(
                    uncPath))
                {
                    throw new FileNotFoundException(
                        "HashLyte could not access the process executable over SMB.",
                        uncPath);
                }

                FileInvestigationResult result =
                    await Task.Run(() =>
                        _fileInvestigator.Investigate(
                            uncPath,
                            _selectedProcess.ExecutablePath));

                _currentProcessSha256 =
                    result.Sha256;

                ProcessCopyHashButton.IsEnabled =
                    true;

                ProcessVirusTotalButton.IsEnabled =
                    true;

                ProcessRiskAssessment risk =
                    _processRiskService.Assess(
                        _selectedProcess,
                        _processes);

                ProcessDetailsText.Text =
                    $"PROCESS\n" +
                    $"────────────────────────────\n" +
                    BuildProcessRuntimeText(
                        _selectedProcess) +
                    "\n\n" +
                    BuildRiskText(
                        risk) +
                    "\n\n" +
                    BuildFileInvestigationText(
                        result);

                ConnectionStatusText.Text =
                    $"Investigation complete for {_selectedProcess.Name}.";
            }
            catch (Exception ex)
            {
                ConnectionStatusText.Text =
                    $"Process investigation failed: {ex.Message}";
            }
            finally
            {
                InvestigateProcessExecutableButton.IsEnabled =
                    true;
            }
        }

        // ============================================================
        // SERVICES
        // ============================================================

        private void ServiceSearchTextBox_TextChanged(
            object sender,
            TextChangedEventArgs e)
        {
            if (ServicesGrid == null)
                return;

            string search =
                ServiceSearchTextBox.Text.Trim();

            if (string.IsNullOrWhiteSpace(
                search))
            {
                ServicesGrid.ItemsSource =
                    _services;

                return;
            }

            ServicesGrid.ItemsSource =
                _services
                    .Where(x =>
                        x.Name.Contains(
                            search,
                            StringComparison.OrdinalIgnoreCase)

                        ||

                        x.DisplayName.Contains(
                            search,
                            StringComparison.OrdinalIgnoreCase)

                        ||

                        x.StartAccount.Contains(
                            search,
                            StringComparison.OrdinalIgnoreCase)

                        ||

                        x.PathName.Contains(
                            search,
                            StringComparison.OrdinalIgnoreCase))
                    .ToList();
        }

        // ============================================================
        // HASH / VIRUSTOTAL
        // ============================================================

        private void CopyHashButton_Click(
            object sender,
            RoutedEventArgs e)
        {
            CopyHash(
                _currentSha256);
        }

        private void VirusTotalButton_Click(
            object sender,
            RoutedEventArgs e)
        {
            OpenVirusTotal(
                _currentSha256);
        }

        private void ProcessCopyHashButton_Click(
            object sender,
            RoutedEventArgs e)
        {
            CopyHash(
                _currentProcessSha256);
        }

        private void ProcessVirusTotalButton_Click(
            object sender,
            RoutedEventArgs e)
        {
            OpenVirusTotal(
                _currentProcessSha256);
        }

        private void CopyHash(
            string? sha256)
        {
            if (string.IsNullOrWhiteSpace(
                sha256))
            {
                return;
            }

            Clipboard.SetText(
                sha256);

            ConnectionStatusText.Text =
                "SHA-256 copied.";
        }

        private void OpenVirusTotal(
            string? sha256)
        {
            if (string.IsNullOrWhiteSpace(
                sha256))
            {
                return;
            }

            string url =
                $"https://www.virustotal.com/gui/file/{sha256}";

            Process.Start(
                new ProcessStartInfo
                {
                    FileName =
                        url,

                    UseShellExecute =
                        true
                });
        }

        // ============================================================
        // PATH HELPERS
        // ============================================================

        private string ConvertTargetPathToUnc(
            string targetPath)
        {
            if (string.IsNullOrWhiteSpace(
                _currentTarget))
            {
                throw new InvalidOperationException(
                    "No target computer is connected.");
            }

            string path =
                targetPath
                    .Trim()
                    .Trim('"');

            if (path.StartsWith(
                @"\\"))
            {
                return path;
            }

            if (path.Length < 3 ||
                path[1] != ':')
            {
                throw new InvalidOperationException(
                    $"Unsupported executable path: {path}");
            }

            char drive =
                char.ToUpperInvariant(
                    path[0]);

            string remainder =
                path.Substring(
                    3);

            return
                $@"\\{_currentTarget}\{drive}$\{remainder}";
        }

        private string ConvertUncToTargetPath(
            string uncPath)
        {
            if (string.IsNullOrWhiteSpace(
                _currentTarget))
            {
                return "";
            }

            string prefix =
                $@"\\{_currentTarget}\C$";

            if (!uncPath.StartsWith(
                prefix,
                StringComparison.OrdinalIgnoreCase))
            {
                return uncPath;
            }

            string remainder =
                uncPath.Substring(
                    prefix.Length);

            return
                @"C:" + remainder;
        }

        // ============================================================
        // DISPLAY HELPERS
        // ============================================================

        private static string BuildRiskText(
            ProcessRiskAssessment risk)
        {
            return
                $"TRIAGE\n" +
                $"────────────────────────────\n" +
                $"Level:        {risk.Level}\n" +
                $"Score:        {risk.Score}\n\n" +
                $"{risk.FindingsText}";
        }

        private static string BuildProcessRuntimeText(
            RemoteProcessInfo process)
        {
            return
                $"Process:      {process.Name}\n" +
                $"PID:          {process.Pid}\n" +
                $"Parent PID:   {process.ParentPid}\n" +
                $"User:         {Display(process.User)}\n" +
                $"Started:      {process.StartTime?.ToString() ?? "Unknown"}\n\n" +

                $"Executable:\n" +
                $"{Display(process.ExecutablePath)}\n\n" +

                $"Command Line:\n" +
                $"{Display(process.CommandLine)}";
        }

        private static string BuildServiceText(
            RemoteServiceInfo service)
        {
            return
                $"Service:      {service.Name}\n" +
                $"Display Name: {service.DisplayName}\n" +
                $"State:        {service.State}\n" +
                $"Startup:      {service.StartMode}\n" +
                $"Runs As:      {service.StartAccount}\n" +
                $"PID:          {service.ProcessId}\n\n" +

                $"Service Path:\n" +
                $"{service.PathName}";
        }

        private static string BuildFileInvestigationText(
            FileInvestigationResult result)
        {
            return
                $"FILE\n" +
                $"────────────────────────────\n" +
                $"Name:          {result.FileName}\n" +
                $"Size:          {FormatBytes(result.Size)}\n" +
                $"Created:       {result.Created}\n" +
                $"Modified:      {result.Modified}\n\n" +

                $"VERSION\n" +
                $"────────────────────────────\n" +
                $"Company:       {Display(result.Company)}\n" +
                $"Description:   {Display(result.Description)}\n" +
                $"Product:       {Display(result.ProductName)}\n" +
                $"Product Ver:   {Display(result.ProductVersion)}\n" +
                $"File Version:  {Display(result.FileVersion)}\n" +
                $"Original Name: {Display(result.OriginalFileName)}\n\n" +

                $"SIGNATURE\n" +
                $"────────────────────────────\n" +
                $"Status:        {result.Signature.Status}\n" +
                $"Signer:        {Display(result.Signature.Signer)}\n" +
                $"Subject:       {Display(result.Signature.Subject)}\n" +
                $"Issuer:        {Display(result.Signature.Issuer)}\n" +
                $"Valid From:    {result.Signature.ValidFrom?.ToString() ?? "Unknown"}\n" +
                $"Valid Until:   {result.Signature.ValidTo?.ToString() ?? "Unknown"}\n" +
                $"Thumbprint:    {Display(result.Signature.Thumbprint)}\n\n" +

                $"SHA-256\n" +
                $"────────────────────────────\n" +
                $"{result.Sha256}";
        }

        private static string Display(
            string value)
        {
            return string.IsNullOrWhiteSpace(
                value)
                ? "Unknown"
                : value;
        }

        private static string FormatBytes(
            long bytes)
        {
            double value =
                bytes;

            string[] units =
            {
                "B",
                "KB",
                "MB",
                "GB"
            };

            int unit =
                0;

            while (value >= 1024 &&
                   unit < units.Length - 1)
            {
                value /= 1024;
                unit++;
            }

            return
                $"{value:N2} {units[unit]}";
        }
    }
}