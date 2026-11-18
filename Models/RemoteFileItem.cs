using System;

namespace HashLyte.Models
{
    public sealed class RemoteFileItem
    {
        public string Name { get; init; } = "";
        public string FullPath { get; init; } = "";
        public bool IsDirectory { get; init; }
        public long? Size { get; init; }
        public DateTime? Modified { get; init; }

        public string Type => IsDirectory ? "Folder" : "File";

        public string SizeDisplay
        {
            get
            {
                if (IsDirectory || Size == null)
                    return "";

                double value = Size.Value;
                string[] units = { "B", "KB", "MB", "GB" };
                int unit = 0;

                while (value >= 1024 && unit < units.Length - 1)
                {
                    value /= 1024;
                    unit++;
                }

                return $"{value:N1} {units[unit]}";
            }
        }
    }
}