using System;
using System.CommandLine;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;
using RNCryptor;
internal class Program
{
    private static async Task<int> Main(string[] args)
    {
        RootCommand rootCommand = new RootCommand("Encrypt or decrypt FILEs (by default, encrypts FILES in-place).");
        Option<bool> decryptOption = new Option<bool>(
            name: "--decrypt",
            description: "decrypt");
        decryptOption.AddAlias("-d");
        rootCommand.AddOption(decryptOption);
        Option<FormatVersion> formatOption = new Option<FormatVersion>(
            name: "--format",
            description: "use version VER on encrypted files",
            getDefaultValue: () => FormatVersion.V3);
        rootCommand.AddOption(formatOption);
        Option<string> passwordOption = new Option<string>(
            name: "--password",
            description: "use password PASS on encrypted files");
        passwordOption.AddAlias("-p");
        passwordOption.IsRequired = true;
        rootCommand.AddOption(passwordOption);
        Argument<string[]> fileArgument = new Argument<string[]>(
            name: "FILE");
        rootCommand.Add(fileArgument);
        rootCommand.SetHandler((decrypt, format, password, files) =>
        {
            Cryptor cryptor = new Cryptor()
            {
                Password = password
            };
            if (files.Length == 0 || files.Length == 1 && files[0] == "-")
            {
                using (Stream inputStream = Console.OpenStandardInput())
                {
                    using (Stream outputStream = Console.OpenStandardOutput())
                    {
                        Execute(inputStream, outputStream, decrypt ? cryptor.CreateDecryptor() : cryptor.CreateEncryptor());
                    }
                }
                return;
            }
            foreach (string file in files)
            {
                using (Stream inputStream = File.OpenRead(file))
                {
                    using (Stream outputStream = File.Create(file + ".rnc"))
                    {
                        Execute(inputStream, outputStream, decrypt ? cryptor.CreateDecryptor() : cryptor.CreateEncryptor());
                    }
                }
            }
        }, decryptOption, formatOption, passwordOption, fileArgument);
        return await rootCommand.InvokeAsync(args);
    }
    private static void Execute(Stream inputStream, Stream outputStream, ICryptoTransform transform)
    {
        using (CryptoStream cryptoStream = new CryptoStream(outputStream, transform, CryptoStreamMode.Write))
        {
            inputStream.CopyTo(cryptoStream);
        }
    }
}