using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Xml;

class Program
{
    static int Main(string[] args)
    {
        if (args.Length == 0 || args.Contains("--help", StringComparer.OrdinalIgnoreCase))
        {
            PrintHelp();
            return 0;
        }

        var stopwatch = Stopwatch.StartNew();
        var options = ParseArgs(args);

        var operation = GetOption(options, "operation");
        var endpoint = GetOption(options, "endpoint");
        var token = GetOption(options, "token");
        var outDir = GetOption(options, "out-dir");
        var certPfx = GetOption(options, "cert-pfx");
        var certPass = GetOption(options, "cert-pass");

        var result = new Dictionary<string, object?>
        {
            ["ok"] = false,
            ["engine"] = "dotnet",
            ["operation"] = operation ?? string.Empty,
            ["endpoint"] = endpoint ?? string.Empty,
            ["endpoint_mode"] = "normal",
            ["sent_utc"] = DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture),
            ["took_ms"] = 0,
            ["http_status"] = null,
            ["soap_action"] = string.Empty,
            ["message_id"] = null,
            ["request_saved_path"] = null,
            ["response_saved_path"] = null,
            ["parsed_saved_path"] = null,
            ["fault_code"] = null,
            ["fault_reason"] = null,
            ["stderr"] = string.Empty,
        };

        if (string.IsNullOrWhiteSpace(operation))
        {
            result["fault_reason"] = "Missing --operation";
            WriteResult(result);
            return 1;
        }

        if (string.IsNullOrWhiteSpace(endpoint))
        {
            result["fault_reason"] = "Missing --endpoint";
            WriteResult(result);
            return 1;
        }

        if (string.IsNullOrWhiteSpace(outDir))
        {
            outDir = Directory.GetCurrentDirectory();
        }

        X509Certificate2? certificate = null;
        if (!string.IsNullOrWhiteSpace(certPfx))
        {
            certificate = new X509Certificate2(certPfx, certPass);
        }

        try
        {
            Directory.CreateDirectory(outDir);
            var response = InvokeOperation(operation, endpoint, token ?? string.Empty, certificate);
            var responseText = NormalizeResponse(response);

            var timestamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss", CultureInfo.InvariantCulture);
            var responsePath = Path.Combine(outDir, $"{operation}_{timestamp}_response.xml");
            File.WriteAllText(responsePath, responseText);

            result["ok"] = true;
            result["response_saved_path"] = responsePath;
        }
        catch (Exception ex)
        {
            result["fault_reason"] = ex.Message;
            result["stderr"] = ex.ToString();
        }
        finally
        {
            stopwatch.Stop();
            result["took_ms"] = stopwatch.ElapsedMilliseconds;
        }

        WriteResult(result);
        return result["ok"] is true ? 0 : 1;
    }

    static void PrintHelp()
    {
        Console.WriteLine("VdaaDivBridge --operation <name> --endpoint <url> --token <token> --out-dir <dir> --cert-pfx <path> --cert-pass <password>");
    }

    static Dictionary<string, string> ParseArgs(string[] args)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (var i = 0; i < args.Length; i++)
        {
            var arg = args[i];
            if (!arg.StartsWith("--", StringComparison.Ordinal))
            {
                continue;
            }

            var key = arg.Substring(2);
            var value = string.Empty;
            if (i + 1 < args.Length && !args[i + 1].StartsWith("--", StringComparison.Ordinal))
            {
                value = args[i + 1];
                i++;
            }
            map[key] = value;
        }
        return map;
    }

    static string? GetOption(Dictionary<string, string> options, string key)
    {
        return options.TryGetValue(key, out var value) ? value : null;
    }

    static object? InvokeOperation(string operation, string endpoint, string token, X509Certificate2? certificate)
    {
        var dllPath = ResolveDllPath();
        var assembly = Assembly.LoadFrom(dllPath);

        var candidateTypes = assembly.GetTypes()
            .Where(t => t.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static)
                .Any(m => string.Equals(m.Name, operation, StringComparison.Ordinal)))
            .ToList();

        if (candidateTypes.Count == 0)
        {
            throw new InvalidOperationException($"Method {operation} not found in {dllPath}.");
        }

        foreach (var type in candidateTypes)
        {
            var method = SelectMethod(type, operation, endpoint, token, certificate, out var args);
            if (method == null)
            {
                continue;
            }

            var target = method.IsStatic ? null : Activator.CreateInstance(type);
            return method.Invoke(target, args);
        }

        throw new InvalidOperationException($"Unable to bind parameters for {operation}.");
    }

    static MethodInfo? SelectMethod(
        Type type,
        string operation,
        string endpoint,
        string token,
        X509Certificate2? certificate,
        out object?[] args)
    {
        var methods = type.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static)
            .Where(m => string.Equals(m.Name, operation, StringComparison.Ordinal))
            .ToList();

        foreach (var method in methods)
        {
            if (TryBuildArgs(method, endpoint, token, certificate, out args))
            {
                return method;
            }
        }

        args = Array.Empty<object?>();
        return null;
    }

    static bool TryBuildArgs(MethodInfo method, string endpoint, string token, X509Certificate2? certificate, out object?[] args)
    {
        var parameters = method.GetParameters();
        args = new object?[parameters.Length];

        for (var i = 0; i < parameters.Length; i++)
        {
            var parameter = parameters[i];
            var paramType = parameter.ParameterType;
            var name = parameter.Name ?? string.Empty;

            if (paramType == typeof(string))
            {
                if (name.Contains("endpoint", StringComparison.OrdinalIgnoreCase) || name.Contains("url", StringComparison.OrdinalIgnoreCase))
                {
                    args[i] = endpoint;
                    continue;
                }

                if (name.Contains("token", StringComparison.OrdinalIgnoreCase))
                {
                    args[i] = token;
                    continue;
                }

                if (parameter.HasDefaultValue)
                {
                    args[i] = parameter.DefaultValue;
                    continue;
                }

                return false;
            }

            if (paramType == typeof(Uri))
            {
                args[i] = new Uri(endpoint);
                continue;
            }

            if (certificate != null && paramType.IsInstanceOfType(certificate))
            {
                args[i] = certificate;
                continue;
            }

            if (parameter.HasDefaultValue)
            {
                args[i] = parameter.DefaultValue;
                continue;
            }

            return false;
        }

        return true;
    }

    static string NormalizeResponse(object? response)
    {
        if (response == null)
        {
            return string.Empty;
        }

        if (response is string text)
        {
            return text;
        }

        if (response is XmlDocument xmlDocument)
        {
            return xmlDocument.OuterXml;
        }

        if (response is XmlNode xmlNode)
        {
            return xmlNode.OuterXml;
        }

        return response.ToString() ?? string.Empty;
    }

    static string ResolveDllPath()
    {
        var baseDir = AppContext.BaseDirectory;
        var local = Path.Combine(baseDir, "Vraa.Div.Client.dll");
        if (File.Exists(local))
        {
            return local;
        }

        var current = Path.Combine(Directory.GetCurrentDirectory(), "Vraa.Div.Client.dll");
        if (File.Exists(current))
        {
            return current;
        }

        var repoRelative = Path.GetFullPath(
            Path.Combine(baseDir, "../../../../examples/VDAA_docs/Client/NET/Any CPU/Vraa.Div.Client.dll")
        );
        if (File.Exists(repoRelative))
        {
            return repoRelative;
        }

        throw new FileNotFoundException("Vraa.Div.Client.dll not found next to executable.");
    }

    static void WriteResult(Dictionary<string, object?> result)
    {
        var json = JsonSerializer.Serialize(result, new JsonSerializerOptions
        {
            WriteIndented = false
        });
        Console.WriteLine(json);
    }
}
