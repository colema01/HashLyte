using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using HashLyte.Models;

namespace HashLyte.Services
{
    public sealed class RemoteFileBrowserService
    {
        public List<RemoteFileItem> GetItems(string uncPath)
        {
            var results = new List<RemoteFileItem>();

            foreach (string directory in Directory.GetDirectories(uncPath))
            {
                try
                {
                    DirectoryInfo info = new(directory);

                    results.Add(new RemoteFileItem
                    {
                        Name = info.Name,
                        FullPath = info.FullName,
                        IsDirectory = true,
                        Modified = info.LastWriteTime
                    });
                }
                catch
                {
                    // Ignore folders Windows does not let us inspect.
                }
            }

            foreach (string file in Directory.GetFiles(uncPath))
            {
                try
                {
                    FileInfo info = new(file);

                    results.Add(new RemoteFileItem
                    {
                        Name = info.Name,
                        FullPath = info.FullName,
                        IsDirectory = false,
                        Size = info.Length,
                        Modified = info.LastWriteTime
                    });
                }
                catch
                {
                    // Ignore inaccessible files.
                }
            }

            return results
                .OrderByDescending(x => x.IsDirectory)
                .ThenBy(x => x.Name)
                .ToList();
        }
    }
}