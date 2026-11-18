namespace HashLyte.Models
{
    public sealed class FileInvestigationResult
    {
        public string FileName { get; init; } = "";
        public string RemotePath { get; init; } = "";
        public string TargetPath { get; init; } = "";

        public long Size { get; init; }

        public DateTime Created { get; init; }
        public DateTime Modified { get; init; }

        public string Company { get; init; } = "";
        public string Description { get; init; } = "";
        public string ProductName { get; init; } = "";
        public string ProductVersion { get; init; } = "";
        public string FileVersion { get; init; } = "";
        public string OriginalFileName { get; init; } = "";

        public string Sha256 { get; init; } = "";

        public SignatureInfo Signature { get; init; } =
            new();
    }
}