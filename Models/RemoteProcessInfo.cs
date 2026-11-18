namespace HashLyte.Models
{
    public sealed class RemoteProcessInfo
    {
        public int Pid { get; init; }
        public int ParentPid { get; init; }

        public string Name { get; init; } = "";
        public string ExecutablePath { get; init; } = "";
        public string CommandLine { get; init; } = "";
        public string User { get; init; } = "";

        public DateTime? StartTime { get; init; }
    }
}