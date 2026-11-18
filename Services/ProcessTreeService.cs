using HashLyte.Models;

namespace HashLyte.Services
{
    public sealed class ProcessTreeService
    {
        public List<ProcessTreeNode> BuildTree(
            IEnumerable<RemoteProcessInfo> processes)
        {
            Dictionary<int, ProcessTreeNode> nodes =
                processes
                    .GroupBy(p => p.Pid)
                    .Select(g => g.First())
                    .ToDictionary(
                        p => p.Pid,
                        p => new ProcessTreeNode
                        {
                            Process = p
                        });

            List<ProcessTreeNode> roots = new();

            foreach (ProcessTreeNode node in nodes.Values)
            {
                int parentPid =
                    node.Process.ParentPid;

                if (parentPid != 0 &&
                    parentPid != node.Process.Pid &&
                    nodes.TryGetValue(
                        parentPid,
                        out ProcessTreeNode? parent))
                {
                    parent.Children.Add(node);
                }
                else
                {
                    roots.Add(node);
                }
            }

            SortNodes(roots);

            return roots;
        }

        private static void SortNodes(
            IEnumerable<ProcessTreeNode> nodes)
        {
            foreach (ProcessTreeNode node in nodes)
            {
                List<ProcessTreeNode> sortedChildren =
                    node.Children
                        .OrderBy(x => x.Process.Name)
                        .ThenBy(x => x.Process.Pid)
                        .ToList();

                node.Children.Clear();

                foreach (ProcessTreeNode child in sortedChildren)
                {
                    node.Children.Add(child);
                }

                SortNodes(node.Children);
            }
        }
    }
}