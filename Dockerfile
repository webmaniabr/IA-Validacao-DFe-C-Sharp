# ===== builder: compila SDK C# e app runner =====
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS builder
WORKDIR /work

# Copiar a pasta src com os arquivos do SDK
COPY src /work/sdk-source

# --- PATCH: make DetectMimeFromBinary public for direct calls if needed ---
RUN if [ -f /work/sdk-source/ValidationClient.cs ]; then \
      sed -i 's/private static string? DetectMimeFromBinary/public static string? DetectMimeFromBinary/' /work/sdk-source/ValidationClient.cs; \
    fi

# compila o SDK
RUN cd /work/sdk-source && \
    (dotnet restore || true) && \
    (dotnet build -c Release || dotnet build)

# cria app runner (console) que usa o SDK
RUN dotnet new console -n runner -o /work/runner --use-program-main true

# escreve Program.cs com validações de negócio
RUN cat <<'EOF' > /work/runner/Program.cs
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;

static string Env(string k, string def = "") {
  var v = Environment.GetEnvironmentVariable(k);
  return string.IsNullOrWhiteSpace(v) ? def : v.Trim();
}

static List<string> ParseCsv(string s) =>
  string.IsNullOrWhiteSpace(s) ? new List<string>() : s.Split(",").Select(x => x.Trim()).Where(x => x.Length > 0).ToList();

static Dictionary<string, object?> ParseOptions() {
  var opts = new Dictionary<string, object?>();
  
  // Formato
  var formato = Env("FORMATO", "json");
  if (!string.IsNullOrEmpty(formato)) opts["formato"] = formato;
  
  // URL de notificação
  var urlNotif = Env("URL_NOTIFICACAO");
  if (!string.IsNullOrEmpty(urlNotif)) opts["url_notificacao"] = urlNotif;
  
  // Formato de notificação
  var formatoNotif = Env("FORMATO_NOTIFICACAO");
  if (!string.IsNullOrEmpty(formatoNotif)) opts["formato_notificacao"] = formatoNotif;
  
  // Assíncrono/Síncrono
  var assincrono = Env("ASSINCRONO");
  var sincrono = Env("SINCRONO");
  
  if (!string.IsNullOrEmpty(assincrono)) {
    if (assincrono.Equals("true", StringComparison.OrdinalIgnoreCase) || assincrono == "1") {
      opts["assincrono"] = true;
    } else if (assincrono.Equals("false", StringComparison.OrdinalIgnoreCase) || assincrono == "0") {
      opts["assincrono"] = false;
    }
  }
  
  if (!string.IsNullOrEmpty(sincrono)) {
    if (sincrono.Equals("true", StringComparison.OrdinalIgnoreCase) || sincrono == "1") {
      opts["sincrono"] = true;
    } else if (sincrono.Equals("false", StringComparison.OrdinalIgnoreCase) || sincrono == "0") {
      opts["sincrono"] = false;
    }
  }
  
  // Modelo (para XML)
  var modelo = Env("MODELO_XML");
  if (!string.IsNullOrEmpty(modelo)) opts["modelo"] = modelo;
  
  return opts;
}

static void ValidateAsyncRequiresNotification(Dictionary<string, object?> opts, int imageCount = 1) {
  var isAsync = false;
  var urlNotif = opts.ContainsKey("url_notificacao") ? opts["url_notificacao"]?.ToString() : null;
  
  // Verificar se é assíncrono
  if (opts.ContainsKey("assincrono") && opts["assincrono"] is bool asyncVal) {
    isAsync = asyncVal;
  } else if (opts.ContainsKey("sincrono") && opts["sincrono"] is bool syncVal) {
    isAsync = !syncVal;
  }
  
  // Se mais de uma imagem, força assíncrono
  if (imageCount > 1) {
    isAsync = true;
    opts["assincrono"] = true;
    if (opts.ContainsKey("sincrono")) opts.Remove("sincrono");
  }
  
  // Se formato texto, força assíncrono
  if (opts.ContainsKey("formato") && opts["formato"]?.ToString() == "texto") {
    isAsync = true;
    opts["assincrono"] = true;
  }
  
  // Validar URL de notificação obrigatória
  if (isAsync && string.IsNullOrEmpty(urlNotif)) {
    Console.Error.WriteLine("ERRO: URL_NOTIFICACAO é obrigatória quando:");
    Console.Error.WriteLine("  - ASSINCRONO=true");
    Console.Error.WriteLine("  - Enviando mais de uma imagem");
    Console.Error.WriteLine("  - FORMATO=texto");
    Console.Error.WriteLine("  - SINCRONO=false");
    Environment.Exit(3);
  }
}

var token = Env("WEBMANIA_TOKEN");
if (string.IsNullOrWhiteSpace(token)) {
  Console.Error.WriteLine("ERRO: Defina WEBMANIA_TOKEN.");
  Environment.Exit(1);
}

var methodToCall = Env("METHOD", "help").ToLower().Replace("_", "").Replace("-", "");
var debug = bool.TryParse(Env("DEBUG","false"), out var dbg) ? dbg : false;

var jsonOpts = new JsonSerializerOptions {
  WriteIndented = true,
  DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
  PropertyNamingPolicy = JsonNamingPolicy.CamelCase
};

try {
  // Carregar SDK
  var sdkDir = "/app/sdk";
  if (!Directory.Exists(sdkDir)) {
    Console.Error.WriteLine("SDK não encontrado em /app/sdk");
    Environment.Exit(10);
  }
  
  var dlls = Directory.GetFiles(sdkDir, "*.dll", SearchOption.AllDirectories);
  if (dlls.Length == 0) {
    Console.Error.WriteLine("Nenhuma DLL do SDK encontrada em /app/sdk");
    Environment.Exit(11);
  }

  Type? clientType = null;
  Type? optionsType = null;
  
  foreach (var dll in dlls) {
    try {
      var asm = Assembly.LoadFrom(dll);
      var types = asm.GetTypes();
      
      var validationClient = types.FirstOrDefault(t => t.Name == "ValidationClient");
      if (validationClient != null) {
        clientType = validationClient;
        if (debug) Console.Error.WriteLine($"DEBUG: ValidationClient encontrado em: {dll}");
      }
      
      var validationOptions = types.FirstOrDefault(t => t.Name == "ValidationClientOptions");
      if (validationOptions != null) {
        optionsType = validationOptions;
      }
    } catch { }
  }
  
  if (clientType == null) {
    Console.Error.WriteLine("Tipo ValidationClient não encontrado no SDK.");
    Environment.Exit(12);
  }

  // Listar métodos disponíveis
  if (methodToCall == "help" || methodToCall == "list") {
    Console.WriteLine("=== SDK WebmaniaBR - Validação de Documentos Fiscais ===\n");
    Console.WriteLine("Métodos disponíveis:\n");
    
    var methods = clientType.GetMethods(BindingFlags.Instance | BindingFlags.Public | BindingFlags.DeclaredOnly)
      .Where(m => !m.Name.StartsWith("get_") && !m.Name.StartsWith("set_") && m.Name != "SetToken" && m.Name != "SetBaseUri")
      .OrderBy(m => m.Name);
    
    foreach (var m in methods) {
      Console.WriteLine($"  • {m.Name}");
    }
    
    Console.WriteLine("\n=== Exemplos de uso ===\n");
    Console.WriteLine("# Validar imagem por URL (síncrono):");
    Console.WriteLine("  docker run --rm \\");
    Console.WriteLine("    -e WEBMANIA_TOKEN=\"seu-token\" \\");
    Console.WriteLine("    -e METHOD=\"ValidateImageByUrlAsync\" \\");
    Console.WriteLine("    -e MODELO=\"nfce\" \\");
    Console.WriteLine("    -e IMAGENS_URLS=\"https://exemplo.com/imagem.jpg\" \\");
    Console.WriteLine("    -e ASSINCRONO=\"false\" \\");
    Console.WriteLine("    webmania/csharp-sdk\n");
    
    Console.WriteLine("# Validar múltiplas imagens (sempre assíncrono):");
    Console.WriteLine("  docker run --rm \\");
    Console.WriteLine("    -e WEBMANIA_TOKEN=\"seu-token\" \\");
    Console.WriteLine("    -e METHOD=\"ValidateImageByUrlAsync\" \\");
    Console.WriteLine("    -e MODELO=\"nfe\" \\");
    Console.WriteLine("    -e IMAGENS_URLS=\"url1.jpg,url2.jpg\" \\");
    Console.WriteLine("    -e URL_NOTIFICACAO=\"https://webhook.site/...\" \\");
    Console.WriteLine("    webmania/csharp-sdk\n");
    
    Console.WriteLine("# Validar com Base64:");
    Console.WriteLine("  docker run --rm \\");
    Console.WriteLine("    -e WEBMANIA_TOKEN=\"seu-token\" \\");
    Console.WriteLine("    -e METHOD=\"ValidateImageByBase64Async\" \\");
    Console.WriteLine("    -e MODELO=\"nfce\" \\");
    Console.WriteLine("    -e IMAGENS_BASE64=\"base64string\" \\");
    Console.WriteLine("    -e ASSINCRONO=\"true\" \\");
    Console.WriteLine("    -e URL_NOTIFICACAO=\"https://webhook.site/...\" \\");
    Console.WriteLine("    webmania/csharp-sdk\n");
    
    Console.WriteLine("# Upload de arquivos locais:");
    Console.WriteLine("  docker run --rm \\");
    Console.WriteLine("    -v /caminho/local:/images:ro \\");
    Console.WriteLine("    -e WEBMANIA_TOKEN=\"seu-token\" \\");
    Console.WriteLine("    -e METHOD=\"ValidateImageUploadAsync\" \\");
    Console.WriteLine("    -e MODELO=\"nfe\" \\");
    Console.WriteLine("    -e FILE_PATHS=\"/images/nota1.jpg,/images/nota2.pdf\" \\");
    Console.WriteLine("    -e URL_NOTIFICACAO=\"https://webhook.site/...\" \\");
    Console.WriteLine("    webmania/csharp-sdk\n");
    
    Console.WriteLine("# Validar XML:");
    Console.WriteLine("  docker run --rm \\");
    Console.WriteLine("    -e WEBMANIA_TOKEN=\"seu-token\" \\");
    Console.WriteLine("    -e METHOD=\"ValidateXmlAsync\" \\");
    Console.WriteLine("    -e XML_CONTENT=\"<xml>...</xml>\" \\");
    Console.WriteLine("    -e MODELO_XML=\"nfe\" \\");
    Console.WriteLine("    -e FORMATO=\"json\" \\");
    Console.WriteLine("    webmania/csharp-sdk\n");
    
    Console.WriteLine("# Consultar status/log:");
    Console.WriteLine("  docker run --rm \\");
    Console.WriteLine("    -e WEBMANIA_TOKEN=\"seu-token\" \\");
    Console.WriteLine("    -e METHOD=\"GetValidationLogAsync\" \\");
    Console.WriteLine("    -e UUID=\"task-uuid\" \\");
    Console.WriteLine("    webmania/csharp-sdk\n");
    
    Console.WriteLine("# Registrar integração:");
    Console.WriteLine("  docker run --rm \\");
    Console.WriteLine("    -e WEBMANIA_TOKEN=\"seu-token\" \\");
    Console.WriteLine("    -e METHOD=\"RegisterIntegrationAsync\" \\");
    Console.WriteLine("    -e PROVIDER=\"sefaz\" \\");
    Console.WriteLine("    -e CRED_API_KEY=\"chave\" \\");
    Console.WriteLine("    -e CRED_SECRET=\"segredo\" \\");
    Console.WriteLine("    webmania/csharp-sdk\n");
    
    Console.WriteLine("=== Regras importantes ===");
    Console.WriteLine("• Quando ASSINCRONO=true, URL_NOTIFICACAO é obrigatória");
    Console.WriteLine("• Múltiplas imagens são sempre processadas de forma assíncrona");
    Console.WriteLine("• FORMATO=texto sempre requer processamento assíncrono");
    Console.WriteLine("• Use DEBUG=true para mais informações de diagnóstico");
    
    Environment.Exit(0);
  }

  // Criar instância do cliente - sempre usar a URL padrão
  object? options = null;
  if (optionsType != null) {
    options = Activator.CreateInstance(optionsType);
    var baseUriProp = optionsType.GetProperty("BaseUri");
    baseUriProp?.SetValue(options, "https://api.webmaniabr.com/2");
  }
  
  var ctor = clientType.GetConstructor(new[] { typeof(string), optionsType })
           ?? clientType.GetConstructor(new[] { typeof(string) });
  
  if (ctor == null) {
    Console.Error.WriteLine("Construtor ValidationClient não encontrado.");
    Environment.Exit(13);
  }
  
  object client;
  if (ctor.GetParameters().Length == 2 && options != null) {
    client = ctor.Invoke(new[] { token, options });
  } else {
    client = ctor.Invoke(new[] { token });
  }
  
  // Executar método baseado na escolha
  object? result = null;
  
  // ValidateImageByUrlAsync
  if (methodToCall.Contains("validateimagebyurl")) {
    var modelo = Env("MODELO");
    if (string.IsNullOrEmpty(modelo)) {
      Console.Error.WriteLine("ERRO: Defina MODELO (nfe, nfce ou nfse).");
      Environment.Exit(2);
    }
    
    var imagens = ParseCsv(Env("IMAGENS_URLS"));
    if (imagens.Count == 0) {
      Console.Error.WriteLine("ERRO: Defina IMAGENS_URLS com 1+ URLs separadas por vírgula.");
      Environment.Exit(2);
    }
    
    var opts = ParseOptions();
    ValidateAsyncRequiresNotification(opts, imagens.Count);
    
    var method = clientType.GetMethod("ValidateImageByUrlAsync");
    if (method == null) {
      Console.Error.WriteLine("Método ValidateImageByUrlAsync não encontrado.");
      Environment.Exit(14);
    }
    
    if (debug) {
      Console.Error.WriteLine($"DEBUG: Modelo: {modelo}");
      Console.Error.WriteLine($"DEBUG: Imagens: {imagens.Count} URL(s)");
      Console.Error.WriteLine($"DEBUG: Opções: {JsonSerializer.Serialize(opts, jsonOpts)}");
    }
    
    result = method.Invoke(client, new object?[] { modelo, imagens, opts.Count > 0 ? opts : null });
  }
  // ValidateImageByBase64Async
  else if (methodToCall.Contains("validateimagebybase64")) {
    var modelo = Env("MODELO");
    if (string.IsNullOrEmpty(modelo)) {
      Console.Error.WriteLine("ERRO: Defina MODELO (nfe, nfce ou nfse).");
      Environment.Exit(2);
    }
    
    var imagensBase64 = ParseCsv(Env("IMAGENS_BASE64"));
    if (imagensBase64.Count == 0) {
      Console.Error.WriteLine("ERRO: Defina IMAGENS_BASE64 com 1+ strings base64 separadas por vírgula.");
      Environment.Exit(2);
    }
    
    var opts = ParseOptions();
    ValidateAsyncRequiresNotification(opts, imagensBase64.Count);
    
    var method = clientType.GetMethod("ValidateImageByBase64Async");
    if (method == null) {
      Console.Error.WriteLine("Método ValidateImageByBase64Async não encontrado.");
      Environment.Exit(14);
    }
    
    if (debug) {
      Console.Error.WriteLine($"DEBUG: Modelo: {modelo}");
      Console.Error.WriteLine($"DEBUG: Imagens: {imagensBase64.Count} base64 string(s)");
      Console.Error.WriteLine($"DEBUG: Opções: {JsonSerializer.Serialize(opts, jsonOpts)}");
    }
    
    result = method.Invoke(client, new object?[] { modelo, imagensBase64, opts.Count > 0 ? opts : null });
  }
  // ValidateImageUploadAsync
  else if (methodToCall.Contains("validateimageupload")) {
    var modelo = Env("MODELO");
    if (string.IsNullOrEmpty(modelo)) {
      Console.Error.WriteLine("ERRO: Defina MODELO (nfe, nfce ou nfse).");
      Environment.Exit(2);
    }
    
    var filePaths = ParseCsv(Env("FILE_PATHS"));
    if (filePaths.Count == 0) {
      Console.Error.WriteLine("ERRO: Defina FILE_PATHS com 1+ caminhos de arquivo separados por vírgula.");
      Console.Error.WriteLine("Lembre-se de montar um volume: -v /local/path:/images:ro");
      Environment.Exit(2);
    }
    
    // Verificar se os arquivos existem
    foreach (var path in filePaths) {
      if (!File.Exists(path)) {
        Console.Error.WriteLine($"ERRO: Arquivo não encontrado: {path}");
        Console.Error.WriteLine("Certifique-se de montar o volume corretamente.");
        Environment.Exit(2);
      }
    }
    
    var opts = ParseOptions();
    ValidateAsyncRequiresNotification(opts, filePaths.Count);
    
    var method = clientType.GetMethod("ValidateImageUploadAsync");
    if (method == null) {
      Console.Error.WriteLine("Método ValidateImageUploadAsync não encontrado.");
      Environment.Exit(14);
    }
    
    if (debug) {
      Console.Error.WriteLine($"DEBUG: Modelo: {modelo}");
      Console.Error.WriteLine($"DEBUG: Arquivos: {string.Join(", ", filePaths)}");
      Console.Error.WriteLine($"DEBUG: Opções: {JsonSerializer.Serialize(opts, jsonOpts)}");
    }
    
    result = method.Invoke(client, new object?[] { modelo, filePaths, opts.Count > 0 ? opts : null });
  }
  // ValidateXmlAsync
  else if (methodToCall.Contains("validatexml")) {
    var xmlContent = Env("XML_CONTENT");
    var xmlFile = Env("XML_FILE");
    
    if (string.IsNullOrEmpty(xmlContent) && string.IsNullOrEmpty(xmlFile)) {
      Console.Error.WriteLine("ERRO: Defina XML_CONTENT ou XML_FILE.");
      Environment.Exit(2);
    }
    
    var xmlInput = !string.IsNullOrEmpty(xmlFile) ? xmlFile : xmlContent;
    
    // Se for arquivo, verificar se existe
    if (!string.IsNullOrEmpty(xmlFile) && !File.Exists(xmlFile)) {
      Console.Error.WriteLine($"ERRO: Arquivo XML não encontrado: {xmlFile}");
      Environment.Exit(2);
    }
    
    var opts = ParseOptions();
    ValidateAsyncRequiresNotification(opts);
    
    var method = clientType.GetMethod("ValidateXmlAsync");
    if (method == null) {
      Console.Error.WriteLine("Método ValidateXmlAsync não encontrado.");
      Environment.Exit(14);
    }
    
    if (debug) {
      Console.Error.WriteLine($"DEBUG: XML: {(string.IsNullOrEmpty(xmlFile) ? "conteúdo direto" : xmlFile)}");
      Console.Error.WriteLine($"DEBUG: Opções: {JsonSerializer.Serialize(opts, jsonOpts)}");
    }
    
    result = method.Invoke(client, new object?[] { xmlInput, opts.Count > 0 ? opts : null });
  }
  // RegisterIntegrationAsync
  else if (methodToCall.Contains("registerintegration")) {
    var provider = Env("PROVIDER");
    if (string.IsNullOrEmpty(provider)) {
      Console.Error.WriteLine("ERRO: Defina PROVIDER.");
      Environment.Exit(2);
    }
    
    var credentials = new Dictionary<string, object?>();
    var vars = Environment.GetEnvironmentVariables();
    foreach (var key in vars.Keys) {
      var keyStr = key.ToString();
      if (keyStr.StartsWith("CRED_")) {
        var credKey = keyStr.Replace("CRED_", "").ToLower();
        credentials[credKey] = vars[key];
      }
    }
    
    if (credentials.Count == 0) {
      Console.Error.WriteLine("ERRO: Defina credenciais com prefixo CRED_ (ex: CRED_API_KEY).");
      Environment.Exit(2);
    }
    
    var method = clientType.GetMethod("RegisterIntegrationAsync");
    if (method == null) {
      Console.Error.WriteLine("Método RegisterIntegrationAsync não encontrado.");
      Environment.Exit(14);
    }
    
    if (debug) {
      Console.Error.WriteLine($"DEBUG: Provider: {provider}");
      Console.Error.WriteLine($"DEBUG: Credenciais: {credentials.Count} campo(s)");
    }
    
    result = method.Invoke(client, new object?[] { provider, credentials });
  }
  // GetIntegrationAsync
  else if (methodToCall.Contains("getintegration")) {
    var provider = Env("PROVIDER");
    if (string.IsNullOrEmpty(provider)) {
      Console.Error.WriteLine("ERRO: Defina PROVIDER.");
      Environment.Exit(2);
    }
    
    var method = clientType.GetMethod("GetIntegrationAsync");
    if (method == null) {
      Console.Error.WriteLine("Método GetIntegrationAsync não encontrado.");
      Environment.Exit(14);
    }
    
    if (debug) Console.Error.WriteLine($"DEBUG: Provider: {provider}");
    
    result = method.Invoke(client, new object?[] { provider });
  }
  // DeleteIntegrationAsync
  else if (methodToCall.Contains("deleteintegration")) {
    var provider = Env("PROVIDER");
    if (string.IsNullOrEmpty(provider)) {
      Console.Error.WriteLine("ERRO: Defina PROVIDER.");
      Environment.Exit(2);
    }
    
    var method = clientType.GetMethod("DeleteIntegrationAsync");
    if (method == null) {
      Console.Error.WriteLine("Método DeleteIntegrationAsync não encontrado.");
      Environment.Exit(14);
    }
    
    if (debug) Console.Error.WriteLine($"DEBUG: Provider: {provider}");
    
    result = method.Invoke(client, new object?[] { provider });
  }
  // GetValidationLogAsync
  else if (methodToCall.Contains("getvalidationlog") || methodToCall.Contains("getstatus")) {
    var uuid = Env("UUID");
    if (string.IsNullOrEmpty(uuid)) {
      Console.Error.WriteLine("ERRO: Defina UUID para consultar o log/status.");
      Environment.Exit(2);
    }
    
    var method = clientType.GetMethod("GetValidationLogAsync");
    if (method == null) {
      Console.Error.WriteLine("Método GetValidationLogAsync não encontrado.");
      Environment.Exit(14);
    }
    
    if (debug) Console.Error.WriteLine($"DEBUG: UUID: {uuid}");
    
    result = method.Invoke(client, new object?[] { uuid });
  }
  else {
    Console.Error.WriteLine($"ERRO: Método '{methodToCall}' não reconhecido.");
    Console.Error.WriteLine("Use METHOD=help para ver métodos disponíveis e exemplos.");
    Environment.Exit(15);
  }
  
  // Processar resultado (pode ser Task)
  if (result is Task task) {
    await task.ConfigureAwait(false);
    var resultProp = task.GetType().GetProperty("Result");
    result = resultProp?.GetValue(task);
  }
  
  // Exibir resultado
  if (result == null) {
    Console.WriteLine("null");
  }
  else if (result is string s) {
    Console.WriteLine(s);
  }
  else {
    try {
      Console.WriteLine(JsonSerializer.Serialize(result, jsonOpts));
    }
    catch {
      Console.WriteLine(result.ToString());
    }
  }
}
catch (TargetInvocationException tex) {
  var inner = tex.InnerException;
  Console.Error.WriteLine("ERRO SDK: " + (inner?.Message ?? tex.Message));
  
  if (debug && inner != null) {
    Console.Error.WriteLine($"DEBUG: Tipo: {inner.GetType().Name}");
    Console.Error.WriteLine($"DEBUG: StackTrace: {inner.StackTrace}");
    
    // Se for ApiException, tentar extrair mais detalhes
    var statusCodeProp = inner.GetType().GetProperty("StatusCode");
    var responseBodyProp = inner.GetType().GetProperty("ResponseBody");
    
    if (statusCodeProp != null || responseBodyProp != null) {
      var statusCode = statusCodeProp?.GetValue(inner);
      var responseBody = responseBodyProp?.GetValue(inner);
      
      if (statusCode != null) Console.Error.WriteLine($"DEBUG: StatusCode: {statusCode}");
      if (responseBody != null) Console.Error.WriteLine($"DEBUG: ResponseBody: {responseBody}");
    }
  }
  
  Environment.Exit(20);
}
catch (Exception ex) {
  Console.Error.WriteLine("ERRO: " + ex.Message);
  if (debug) {
    Console.Error.WriteLine($"DEBUG: Tipo: {ex.GetType().Name}");
    Console.Error.WriteLine($"DEBUG: StackTrace: {ex.StackTrace}");
  }
  Environment.Exit(21);
}
EOF

# publica o runner e copia as DLLs compiladas do SDK
RUN dotnet publish /work/runner/runner.csproj -c Release -o /out && \
    mkdir -p /out/sdk && \
    if [ -d /work/sdk-source/bin ]; then \
      cp -r /work/sdk-source/bin/* /out/sdk/ 2>/dev/null || true; \
    fi && \
    if [ -d /work/sdk-source/obj ]; then \
      find /work/sdk-source/obj -name "*.dll" -exec cp {} /out/sdk/ \; 2>/dev/null || true; \
    fi

# ===== runtime: imagem leve =====
FROM mcr.microsoft.com/dotnet/runtime:8.0 AS runtime
WORKDIR /app

# instalar ca-certificates para HTTPS
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# app + DLLs do SDK (compiladas)
COPY --from=builder /out /app

# Variáveis de ambiente com valores padrão
ENV METHOD="help" \
    WEBMANIA_TOKEN="" \
    DEBUG="false" \
    MODELO="" \
    MODELO_XML="" \
    IMAGENS_URLS="" \
    IMAGENS_BASE64="" \
    FILE_PATHS="" \
    XML_CONTENT="" \
    XML_FILE="" \
    UUID="" \
    PROVIDER="" \
    FORMATO="json" \
    ASSINCRONO="" \
    SINCRONO="" \
    URL_NOTIFICACAO="" \
    FORMATO_NOTIFICACAO=""

ENTRYPOINT ["dotnet", "/app/runner.dll"]