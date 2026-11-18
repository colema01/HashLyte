namespace HashLyte.Models
{
    public sealed class ProcessRiskAssessment
    {
        public int Score { get; init; }

        public string Level { get; init; } = "Normal";

        public List<string> Findings { get; init; } = new();

        public bool IsSuspicious =>
            Score >= 20;

        public string FindingsText =>
            Findings.Count == 0
                ? "No lightweight indicators detected."
                : string.Join("\n", Findings.Select(x => $"• {x}"));
    }
}