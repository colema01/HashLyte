using System.Collections.ObjectModel;

namespace HashLyte.Models
{
    public sealed class ProcessTreeNode
    {
        public RemoteProcessInfo Process { get; init; } = new();

        public ObservableCollection<ProcessTreeNode> Children { get; } = new();

        public string DisplayName =>
            $"{Process.Name}  [{Process.Pid}]";
    }
}