using System.CommandLine;
using System.Security.Cryptography;
using System.Text;
using RNCryptor;

internal class Program
{
    private static async Task<int> Main(string[] args)
    {
        RootCommand rootCommand = new("Encrypt or decrypt FILEs (by default, encrypts FILES in-place).");

        Option<bool> decryptOption = new(
            name: "--decrypt",
            description: "decrypt");
        decryptOption.AddAlias("-d");
        rootCommand.AddOption(decryptOption);

        Option<FormatVersion> formatOption = new(
            name: "--format",
            description: "use version VER on encrypted files",
            getDefaultValue: () => FormatVersion.V3);
        rootCommand.AddOption(formatOption);

        Option<string> passwordOption = new(
            name: "--password",
            description: "use password PASS on encrypted files");
        passwordOption.AddAlias("-p");
        passwordOption.IsRequired = true;
        rootCommand.AddOption(passwordOption);

        Argument<string[]> fileArgument = new(
            name: "FILE");
        rootCommand.Add(fileArgument);

        rootCommand.SetHandler((decrypt, format, password, files) =>
        {
            Cryptor cryptor = new()
            {
                Password = password
            };
            if (files.Length == 0 || files.Length == 1 && files[0] == "-")
            {
                using var inputStream = Console.OpenStandardInput();
                using var outputStream = Console.OpenStandardOutput();
                Execute(inputStream, outputStream, decrypt ? cryptor.CreateDecryptor() : cryptor.CreateEncryptor());
                return;
            }
            foreach (string file in files)
            {
                using var inputStream = File.OpenRead(file);
                using var outputStream = File.Create(file + ".rnc");
                Execute(inputStream, outputStream, decrypt ? cryptor.CreateDecryptor() : cryptor.CreateEncryptor());
            }
        }, decryptOption, formatOption, passwordOption, fileArgument);

        return await rootCommand.InvokeAsync(args);

    }

    private static void Execute(Stream inputStream, Stream outputStream, ICryptoTransform transform)
    {
        using CryptoStream cryptoStream = new(outputStream, transform, CryptoStreamMode.Write);
        inputStream.CopyTo(cryptoStream);
    }
}