using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using HashLyte.Models;

namespace HashLyte.Services
{
    public sealed class FileInvestigationService
    {
        private readonly SignatureService
            _signatureService = new();

        public FileInvestigationResult Investigate(
            string remotePath,
            string targetPath)
        {
            if (!File.Exists(remotePath))
            {
                throw new FileNotFoundException(
                    "The remote file could not be found.",
                    remotePath);
            }

            FileInfo fileInfo =
                new(remotePath);

            FileVersionInfo versionInfo =
                FileVersionInfo.GetVersionInfo(
                    remotePath);

            string sha256 =
                CalculateSha256(remotePath);

            SignatureInfo signature =
                _signatureService.Inspect(
                    remotePath);

            return new FileInvestigationResult
            {
                FileName =
                    fileInfo.Name,

                RemotePath =
                    remotePath,

                TargetPath =
                    targetPath,

                Size =
                    fileInfo.Length,

                Created =
                    fileInfo.CreationTime,

                Modified =
                    fileInfo.LastWriteTime,

                Company =
                    versionInfo.CompanyName ?? "",

                Description =
                    versionInfo.FileDescription ?? "",

                ProductName =
                    versionInfo.ProductName ?? "",

                ProductVersion =
                    versionInfo.ProductVersion ?? "",

                FileVersion =
                    versionInfo.FileVersion ?? "",

                OriginalFileName =
                    versionInfo.OriginalFilename ?? "",

                Sha256 =
                    sha256,

                Signature =
                    signature
            };
        }

        private static string CalculateSha256(
            string path)
        {
            using FileStream stream =
                new(
                    path,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.ReadWrite |
                    FileShare.Delete);

            using SHA256 sha256 =
                SHA256.Create();

            byte[] hash =
                sha256.ComputeHash(stream);

            return Convert.ToHexString(hash);
        }
    }
}