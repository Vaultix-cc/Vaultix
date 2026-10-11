namespace Vaultix.Examples;

/// <summary>
/// Runs one example: dotnet run --project examples -- 2
/// </summary>
public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        string[] rest = args.Skip(1).ToArray();
        switch (args.FirstOrDefault())
        {
            case "1": await Example01_BasicAuth.Main(rest); return 0;
            case "2": await Example02_FileOperations.Main(rest); return 0;
            case "3": await Example03_Subscription.Main(rest); return 0;
            case "4": await Example04_ProductInfo.Main(rest); return 0;
            case "5": await Example05_AutoLogin.Main(rest); return 0;
            case "6": await Example06_CompleteApp.Main(rest); return 0;
            default:
                Console.WriteLine("usage: dotnet run --project examples -- <1-6>");
                Console.WriteLine("  1 basic authentication   2 files and folders   3 subscriptions");
                Console.WriteLine("  4 product info           5 auto-login          6 complete app");
                return 1;
        }
    }
}
