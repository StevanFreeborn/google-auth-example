using System.Diagnostics;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

var options = await GetAuthOptionsAsync();
var authUrl = BuildAuthUrl(options);
var oauthCode = GetOAuthCodeAsync(authUrl, options);
var token = await GetAccessTokenAsync(oauthCode, options);
var name = await GetUsersNameAsync(token);

Console.WriteLine($"The logged user's name is {name}");

static async Task<string> GetUsersNameAsync(TokenResponse token)
{
  const string userInfoUri = "https://people.googleapis.com/v1/people/me?personFields=names";
  var userInfoRequest = new HttpRequestMessage(HttpMethod.Get, userInfoUri);
  userInfoRequest.Headers.Add("Authorization", $"Bearer {token.AccessToken}");

  using var httpClient = new HttpClient();
  var userInfoResponse = await httpClient.SendAsync(userInfoRequest);
  var userInfoResponseContent = await userInfoResponse.Content.ReadAsStringAsync();

  if (userInfoResponse.IsSuccessStatusCode is false)
  {
    throw new ApplicationException($"Failed to get user info.");
  }

  if (string.IsNullOrEmpty(userInfoResponseContent))
  {
    throw new ApplicationException($"User info response is empty.");
  }

  var userInfo = JsonSerializer.Deserialize<PersonResponse>(userInfoResponseContent, new JsonSerializerOptions
  {
    PropertyNameCaseInsensitive = true
  });

  if (userInfo is null)
  {
    throw new ApplicationException($"Failed to parse user info response.");
  }
  
  return userInfo.Names[0].DisplayName;
}

static async Task<TokenResponse> GetAccessTokenAsync(string oauthCode, GoogleAuthOptions options)
{
  const string tokenUri = "https://oauth2.googleapis.com/token";
  var tokenRequestParams = new Dictionary<string, string>
  {
    ["code"] = oauthCode,
    ["client_id"] = options.ClientId,
    ["client_secret"] = options.ClientSecret,
    ["redirect_uri"] = options.RedirectUri,
    ["grant_type"] = "authorization_code"
  };

  var tokenRequest = new HttpRequestMessage(HttpMethod.Post, tokenUri)
  {
    Content = new FormUrlEncodedContent(tokenRequestParams)
  };

  using var httpClient = new HttpClient();
  var tokenResponse = await httpClient.SendAsync(tokenRequest);
  var tokenResponseContent = await tokenResponse.Content.ReadAsStringAsync();

  if (tokenResponse.IsSuccessStatusCode is false)
  {
    throw new ApplicationException($"Failed to get access token.");
  }

  var token = JsonSerializer.Deserialize<TokenResponse>(tokenResponseContent);

  if (token is null)
  {
    throw new ApplicationException($"Failed to parse access token response.");
  }

  return token;
}

static string GetOAuthCodeAsync(string authUrl, GoogleAuthOptions options)
{
  using var listener = new HttpListener();
  listener.Prefixes.Add(options.RedirectUri);
  listener.Start();
  Console.WriteLine("Waiting for login response...");
  Process.Start(new ProcessStartInfo
  {
    FileName = authUrl,
    UseShellExecute = true
  });

  var listenerContext = listener.GetContext();
  var oauthCode = listenerContext.Request.QueryString["code"];

  try
  {
    if (string.IsNullOrEmpty(oauthCode))
    {
      throw new ApplicationException("OAuth code is missing or invalid");
    }

    const string responseHtml = @"
      <html>
        <body>
          <script>
            alert('Login successful! You can close this window now.');
          </script>
        </body>
      </html>";
    var buffer = Encoding.UTF8.GetBytes(responseHtml);
    listenerContext.Response.ContentLength64 = buffer.Length;
    listenerContext.Response.OutputStream.Write(buffer, 0, buffer.Length);
    listenerContext.Response.Close();

    return oauthCode;
  }
  finally
  {
    listener.Stop();
  }
}

static string BuildAuthUrl(GoogleAuthOptions options)
{
  const string baseAuthUri = "https://accounts.google.com/o/oauth2/v2/auth";
  var authUriQueryParams = new Dictionary<string, string>
  {
    ["client_id"] = options.ClientId,
    ["redirect_uri"] = options.RedirectUri,
    ["response_type"] = "code",
    ["scope"] = "https://www.googleapis.com/auth/userinfo.profile", // add the scopes you need
    ["access_type"] = "offline" // request a refresh token
  };

  var authUri = $"{baseAuthUri}?{string.Join("&", authUriQueryParams.Select(kvp => $"{kvp.Key}={Uri.EscapeDataString(kvp.Value)}"))}";

  return authUri;
}

static async Task<GoogleAuthOptions> GetAuthOptionsAsync()
{
  var settingsPath = Path.Combine(AppContext.BaseDirectory, "appsettings.json");
  var settingsText = await File.ReadAllTextAsync(settingsPath);
  var settings = JsonSerializer.Deserialize<JsonDocument>(settingsText);

  if (settings is null)
  {
    throw new ApplicationException("appsettings.json is missing or invalid");
  }

  var googleAuth = settings.RootElement.GetProperty("GoogleAuth");
  var clientId = googleAuth.GetProperty("ClientId").GetString();
  var clientSecret = googleAuth.GetProperty("ClientSecret").GetString();
  var redirectUri = googleAuth.GetProperty("RedirectUri").GetString();

  if (
      string.IsNullOrWhiteSpace(clientId) ||
      string.IsNullOrWhiteSpace(clientSecret) ||
      string.IsNullOrWhiteSpace(redirectUri)
  )
  {
    throw new ApplicationException("ClientId or ClientSecret is missing or invalid");
  }

  return new(clientId, clientSecret, redirectUri);
}

record PersonResponse(string ResourceName, string ETag, List<Name> Names);

record Name(
  Metadata Metadata, 
  string DisplayName, 
  string FamilyName, 
  string GivenName, 
  string DisplayNameLastFirst, 
  string UnstructuredName
);

record Metadata(bool Primary, Source Source);

record Source(string Type, string Id);

record TokenResponse(
  [property: JsonPropertyName("access_token")]
  string AccessToken,
  [property: JsonPropertyName("expires_in")]
  int ExpiresIn,
  [property: JsonPropertyName("token_type")]
  string TokenType,
  [property: JsonPropertyName("scope")]
  string Scope,
  [property: JsonPropertyName("refresh_token")]
  string RefreshToken
);

record GoogleAuthOptions(string ClientId, string ClientSecret, string RedirectUri);