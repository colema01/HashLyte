namespace HashLyte.Models
{
    public sealed class RemoteServiceInfo
    {
        public string Name { get; init; } = "";
        public string DisplayName { get; init; } = "";

        public string State { get; init; } = "";
        public string StartMode { get; init; } = "";
        public string StartAccount { get; init; } = "";

        public string PathName { get; init; } = "";

        public int ProcessId { get; init; }
    }
}