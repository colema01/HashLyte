namespace HashLyte.Models
{
    public sealed class SignatureInfo
    {
        public string Status { get; init; } = "Unknown";
        public string Signer { get; init; } = "";
        public string Subject { get; init; } = "";
        public string Issuer { get; init; } = "";
        public string Thumbprint { get; init; } = "";
        public DateTime? ValidFrom { get; init; }
        public DateTime? ValidTo { get; init; }
    }
}