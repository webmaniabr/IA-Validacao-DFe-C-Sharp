using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace WebmaniaBR.AI.Validation;

public class ValidationClient
{
    private static readonly Regex Base64Regex = new("^[A-Za-z0-9+/=]+$", RegexOptions.Compiled);
    private static readonly Regex DataUriRegex = new("^data:([^;]+);base64,(.*)$", RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.Singleline);
    private static readonly Regex[] BlockedHostPatterns =
    {
        new Regex("(^|\\.)localhost$", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new Regex("\\.(local|internal)$", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new Regex("(^|\\.)test$", RegexOptions.IgnoreCase | RegexOptions.Compiled),
    };
    private static readonly HashSet<string> BlockedHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "localhost", "127.0.0.1", "0.0.0.0", "::1", "169.254.169.254"
    };
    private static readonly HashSet<string> ImageAllowedModels = new(StringComparer.OrdinalIgnoreCase) { "nfe", "nfce", "nfse" };
    private static readonly HashSet<string> XmlAllowedModels = new(StringComparer.OrdinalIgnoreCase) { "nfe", "nfce", "cte", "mdfe", "nfse" };
    private static readonly HashSet<string> ImageAllowedFormats = new(StringComparer.OrdinalIgnoreCase) { "json", "texto" };
    private static readonly HashSet<string> XmlAllowedFormats = new(StringComparer.OrdinalIgnoreCase) { "json", "texto" };
    private static readonly HashSet<string> NotificationAllowedFormats = new(StringComparer.OrdinalIgnoreCase) { "url_encoded", "json" };
    private static readonly HashSet<string> AllowedImageMimes = new(StringComparer.OrdinalIgnoreCase) { "image/jpeg", "image/png", "application/pdf" };
    private const int MaxFileSizeBytes = 10 * 1024 * 1024;
    private const int MaxImagesPerRequest = 10;
    private static readonly TimeSpan RemoteHeadTimeout = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan RemoteRangeTimeout = TimeSpan.FromSeconds(20);

    private readonly JsonSerializerOptions _jsonOptions;
    private HttpClient _httpClient;
    private string _token;
    private Uri _baseUri;
    private TimeSpan _timeout;
    private string _userAgent;

    private enum ImageInputSource
    {
        Url,
        Base64
    }

    private sealed class ImageOptionsResult
    {
        public string? Format { get; set; }
        public bool? AsyncValue { get; set; }
        public string? NotificationUrl { get; set; }
        public string? NotificationFormat { get; set; }
    }

    private sealed class XmlOptionsResult
    {
        public string? Model { get; set; }
        public string? Format { get; set; }
        public bool? AsyncValue { get; set; }
        public bool? SyncValue { get; set; }
        public string? NotificationUrl { get; set; }
        public string? NotificationFormat { get; set; }
    }

    private sealed class ValidatedFile
    {
        public string Path { get; }
        public string Mime { get; }

        public ValidatedFile(string path, string mime)
        {
            Path = path;
            Mime = mime;
        }
    }

    private sealed class RemoteFileInfo
    {
        public string? Mime { get; set; }
        public long? Size { get; set; }
    }

    public ValidationClient(string token, ValidationClientOptions? options = null)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            throw new ArgumentException("O token da API deve ser informado.", nameof(token));
        }

        options ??= new ValidationClientOptions();

        _token = token.Trim();
        _baseUri = new Uri(NormalizeBaseUri(options.BaseUri ?? "https://api.webmaniabr.com/2"));
        _timeout = options.Timeout == default ? TimeSpan.FromSeconds(30) : options.Timeout;
        _userAgent = string.IsNullOrWhiteSpace(options.UserAgent)
            ? "WebmaniaAIValidationSDK/1.0 (+https://webmaniabr.com/)"
            : options.UserAgent!;

        _httpClient = new HttpClient
        {
            BaseAddress = _baseUri,
            Timeout = _timeout
        };
        _httpClient.DefaultRequestHeaders.Add("X-Token", _token);
        _httpClient.DefaultRequestHeaders.Add("Accept", "application/json");
        _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd(_userAgent);

        _jsonOptions = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            WriteIndented = false
        };
    }

    public void SetToken(string token)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            throw new ArgumentException("O token da API deve ser informado.", nameof(token));
        }

        _token = token.Trim();
        if (_httpClient.DefaultRequestHeaders.Contains("X-Token"))
        {
            _httpClient.DefaultRequestHeaders.Remove("X-Token");
        }
        _httpClient.DefaultRequestHeaders.Add("X-Token", _token);
    }

    public void SetBaseUri(string baseUri)
    {
        _baseUri = new Uri(NormalizeBaseUri(baseUri));
        _httpClient.BaseAddress = _baseUri;
    }

    public async Task<object?> ValidateImageByUrlAsync(string model, IEnumerable<string> imageUrls, IDictionary<string, object?>? options = null)
    {
        var payload = await BuildImagePayloadAsync(model, imageUrls, options, ImageInputSource.Url).ConfigureAwait(false);
        var response = await SendJsonAsync(HttpMethod.Post, "valida/dfe/imagem", payload).ConfigureAwait(false);
        return ParseBody(response);
    }

    public async Task<object?> ValidateImageByBase64Async(string model, IEnumerable<string> base64Images, IDictionary<string, object?>? options = null)
    {
        var payload = await BuildImagePayloadAsync(model, base64Images, options, ImageInputSource.Base64).ConfigureAwait(false);
        var response = await SendJsonAsync(HttpMethod.Post, "valida/dfe/imagem", payload).ConfigureAwait(false);
        return ParseBody(response);
    }

    public async Task<object?> ValidateImageUploadAsync(string model, IEnumerable<string> filePaths, IDictionary<string, object?>? options = null)
    {
        var normalizedModel = NormalizeImageModel(model);
        var validatedFiles = NormalizeUploadFiles(filePaths, normalizedModel);
        var optionValues = NormalizeImageOptions(options, normalizedModel, validatedFiles.Count);

        var content = new MultipartFormDataContent();
        content.Add(new StringContent(normalizedModel), "modelo");

        if (optionValues.Format != null)
        {
            content.Add(new StringContent(optionValues.Format), "formato");
        }

        if (optionValues.NotificationUrl != null)
        {
            content.Add(new StringContent(optionValues.NotificationUrl), "url_notificacao");
        }

        if (optionValues.AsyncValue.HasValue)
        {
            content.Add(new StringContent(optionValues.AsyncValue.Value ? "true" : "false"), "assincrono");
        }

        if (optionValues.NotificationFormat != null)
        {
            content.Add(new StringContent(optionValues.NotificationFormat), "formato_notificacao");
        }

        var disposables = new List<IDisposable> { content };
        try
        {
            foreach (var file in validatedFiles)
            {
                var stream = File.Open(file.Path, FileMode.Open, FileAccess.Read, FileShare.Read);
                disposables.Add(stream);
                var streamContent = new StreamContent(stream);
                disposables.Add(streamContent);
                streamContent.Headers.ContentType = new MediaTypeHeaderValue(file.Mime);
                content.Add(streamContent, "imagens[]", Path.GetFileName(file.Path));
            }

            var response = await SendAsync(HttpMethod.Post, "valida/dfe/imagem", content).ConfigureAwait(false);
            return ParseBody(response);
        }
        finally
        {
            foreach (var disposable in disposables)
            {
                disposable.Dispose();
            }
        }
    }

    public async Task<object?> ValidateXmlAsync(string xmlContentOrPath, IDictionary<string, object?>? options = null)
    {
        var payload = new Dictionary<string, object?>
        {
            ["xml"] = NormalizeXmlInput(xmlContentOrPath)
        };

        var normalizedOptions = NormalizeXmlOptions(options);
        if (normalizedOptions.Model != null)
        {
            payload["modelo"] = normalizedOptions.Model;
        }
        if (normalizedOptions.Format != null)
        {
            payload["formato"] = normalizedOptions.Format;
        }
        if (normalizedOptions.AsyncValue.HasValue)
        {
            payload["assincrono"] = normalizedOptions.AsyncValue.Value;
        }
        if (normalizedOptions.SyncValue.HasValue)
        {
            payload["sincrono"] = normalizedOptions.SyncValue.Value;
        }
        if (normalizedOptions.NotificationUrl != null)
        {
            payload["url_notificacao"] = normalizedOptions.NotificationUrl;
        }
        if (normalizedOptions.NotificationFormat != null)
        {
            payload["formato_notificacao"] = normalizedOptions.NotificationFormat;
        }

        var response = await SendJsonAsync(HttpMethod.Post, "valida/dfe/xml", payload).ConfigureAwait(false);
        return ParseBody(response);
    }

    public async Task<object?> RegisterIntegrationAsync(string provider, IDictionary<string, object?> credentials)
    {
        if (credentials == null || credentials.Count == 0)
        {
            throw new ArgumentException("As credenciais não podem ser vazias.", nameof(credentials));
        }

        var response = await SendJsonAsync(HttpMethod.Post, $"valida/conexoes/{NormalizeProvider(provider)}", credentials)
            .ConfigureAwait(false);
        return ParseBody(response);
    }

    public async Task<object?> GetIntegrationAsync(string provider)
    {
        var response = await SendAsync(HttpMethod.Get, $"valida/conexoes/{NormalizeProvider(provider)}", null)
            .ConfigureAwait(false);
        return ParseBody(response);
    }

    public async Task<object?> DeleteIntegrationAsync(string provider)
    {
        var response = await SendAsync(HttpMethod.Delete, $"valida/conexoes/{NormalizeProvider(provider)}", null)
            .ConfigureAwait(false);
        return ParseBody(response);
    }

    public async Task<object?> GetValidationLogAsync(string uuid)
    {
        if (string.IsNullOrWhiteSpace(uuid))
        {
            throw new ArgumentException("O UUID não pode ser vazio.", nameof(uuid));
        }

        var response = await SendAsync(HttpMethod.Get, $"valida/logs/{uuid.Trim()}", null).ConfigureAwait(false);
        return ParseBody(response);
    }

    private async Task<string> SendJsonAsync(HttpMethod method, string path, IDictionary<string, object?> payload)
    {
        var json = JsonSerializer.Serialize(payload, _jsonOptions);
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        return await SendAsync(method, path, content).ConfigureAwait(false);
    }

    private async Task<string> SendAsync(HttpMethod method, string path, HttpContent? content)
    {
        var normalizedPath = NormalizeRequestPath(path);
        using var request = new HttpRequestMessage(method, normalizedPath)
        {
            Content = content
        };

        try
        {
            using var response = await _httpClient.SendAsync(request).ConfigureAwait(false);
            var body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                throw new ApiException($"Resposta de erro da API com status {(int)response.StatusCode}", (int)response.StatusCode, body);
            }

            return body;
        }
        catch (TaskCanceledException ex)
        {
            throw new ApiException("Erro durante a requisição HTTP: tempo limite excedido.", null, ex.Message);
        }
        catch (HttpRequestException ex)
        {
            throw new ApiException($"Erro durante a requisição HTTP: {ex.Message}", null, ex.Message);
        }
    }

    private string NormalizeRequestPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException("O caminho da requisição não pode ser vazio.", nameof(path));
        }

        return path.StartsWith('/') ? path.TrimStart('/') : path;
    }

    private async Task<Dictionary<string, object?>> BuildImagePayloadAsync(
        string model,
        IEnumerable<string> images,
        IDictionary<string, object?>? options,
        ImageInputSource source)
    {
        var normalizedModel = NormalizeImageModel(model);
        var normalizedImages = await NormalizeImagesAsync(images, normalizedModel, source).ConfigureAwait(false);
        var optionValues = NormalizeImageOptions(options, normalizedModel, normalizedImages.Count);

        var payload = new Dictionary<string, object?>
        {
            ["modelo"] = normalizedModel,
            ["imagens"] = normalizedImages
        };

        if (optionValues.Format != null)
        {
            payload["formato"] = optionValues.Format;
        }

        if (optionValues.AsyncValue.HasValue)
        {
            payload["assincrono"] = optionValues.AsyncValue.Value;
        }

        if (optionValues.NotificationUrl != null)
        {
            payload["url_notificacao"] = optionValues.NotificationUrl;
        }

        if (optionValues.NotificationFormat != null)
        {
            payload["formato_notificacao"] = optionValues.NotificationFormat;
        }

        return payload;
    }

    private async Task<List<string>> NormalizeImagesAsync(IEnumerable<string> values, string model, ImageInputSource source)
    {
        var list = NormalizeStringList(values, source == ImageInputSource.Url ? "URL de imagem" : "imagem em base64");
        AssertImageCount(list.Count);
        var result = new List<string>(list.Count);
        foreach (var value in list)
        {
            if (source == ImageInputSource.Url)
            {
                result.Add(await NormalizeImageUrlAsync(value, model).ConfigureAwait(false));
            }
            else
            {
                result.Add(NormalizeBase64Image(value, model));
            }
        }
        return result;
    }

    private List<ValidatedFile> NormalizeUploadFiles(IEnumerable<string> filePaths, string model)
    {
        var paths = NormalizeFileList(filePaths);
        AssertImageCount(paths.Count);
        var allowedMimes = GetAllowedImageMimes(model);
        var files = new List<ValidatedFile>(paths.Count);

        foreach (var path in paths)
        {
            var info = new FileInfo(path);
            if (!info.Exists || info.Length <= 0)
            {
                throw new ArgumentException("Arquivo inválido: " + info.Name);
            }
            if (info.Length > MaxFileSizeBytes)
            {
                throw new ArgumentException("Arquivo excede o limite de 10MB: " + info.Name);
            }
            var mime = GetFileMime(path);
            if (mime == null || !allowedMimes.Contains(mime))
            {
                throw new ArgumentException("Tipo de arquivo não suportado para o arquivo: " + info.Name);
            }
            files.Add(new ValidatedFile(path, mime));
        }

        return files;
    }

    private List<string> NormalizeStringList(IEnumerable<string> values, string label)
    {
        if (values == null)
        {
            throw new ArgumentException($"É necessário informar ao menos uma {label}.");
        }
        var list = values.Select(v => v?.Trim() ?? string.Empty).ToList();
        if (list.Count == 0)
        {
            throw new ArgumentException($"É necessário informar ao menos uma {label}.");
        }
        foreach (var value in list)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                throw new ArgumentException($"Cada {label} deve ser uma string não vazia.");
            }
        }
        return list;
    }

    private List<string> NormalizeFileList(IEnumerable<string> paths)
    {
        if (paths == null)
        {
            throw new ArgumentException("É necessário informar ao menos um arquivo de imagem.");
        }

        var list = new List<string>();
        foreach (var path in paths)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                throw new ArgumentException("Cada caminho de arquivo deve ser uma string não vazia.");
            }
            var fullPath = Path.GetFullPath(path);
            if (!File.Exists(fullPath))
            {
                throw new ArgumentException("Arquivo de imagem não encontrado: " + path);
            }
            try
            {
                using var stream = File.Open(fullPath, FileMode.Open, FileAccess.Read, FileShare.Read);
            }
            catch
            {
                throw new ArgumentException("Arquivo de imagem sem permissão de leitura: " + path);
            }
            list.Add(fullPath);
        }

        if (list.Count == 0)
        {
            throw new ArgumentException("É necessário informar ao menos um arquivo de imagem.");
        }

        return list;
    }

    private string NormalizeImageModel(string model)
    {
        if (string.IsNullOrWhiteSpace(model))
        {
            throw new ArgumentException("Informe o modelo do documento (nfe, nfce ou nfse).", nameof(model));
        }
        var normalized = model.Trim().ToLowerInvariant();
        if (!ImageAllowedModels.Contains(normalized))
        {
            throw new ArgumentException("Modelo inválido para validação de imagens. Use nfe, nfce ou nfse.");
        }
        return normalized;
    }

    private async Task<string> NormalizeImageUrlAsync(string urlValue, string model)
    {
        if (!Uri.TryCreate(urlValue?.Trim(), UriKind.Absolute, out var uri))
        {
            throw new ArgumentException("Informe URLs válidas com protocolo HTTP ou HTTPS.");
        }
        if (!string.Equals(uri.Scheme, "http", StringComparison.OrdinalIgnoreCase) && !string.Equals(uri.Scheme, "https", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("As URLs de imagem devem utilizar HTTP ou HTTPS.");
        }
        if (string.IsNullOrWhiteSpace(uri.Host) || !IsHostSafe(uri.Host))
        {
            throw new ArgumentException("A URL de imagem informada não é permitida.");
        }

        var info = await FetchRemoteFileInfoAsync(uri).ConfigureAwait(false);
        if (!info.Size.HasValue || info.Size.Value <= 0)
        {
            throw new ArgumentException("Não foi possível determinar o tamanho do arquivo na URL informada.");
        }
        if (info.Size.Value > MaxFileSizeBytes)
        {
            throw new ArgumentException("Arquivo excede o limite de 10MB na URL informada.");
        }
        if (info.Mime == null || !GetAllowedImageMimes(model).Contains(info.Mime))
        {
            throw new ArgumentException("Tipo de arquivo não suportado na URL informada.");
        }
        return uri.ToString();
    }

    private string NormalizeBase64Image(string value, string model)
    {
        if (value == null)
        {
            throw new ArgumentException("As imagens em base64 não podem ser vazias.");
        }
        var trimmed = value.Trim();
        if (trimmed.Length == 0)
        {
            throw new ArgumentException("As imagens em base64 não podem ser vazias.");
        }

        string? mime = null;
        string base64 = trimmed;
        var isDataUri = false;
        var match = DataUriRegex.Match(trimmed);
        if (match.Success)
        {
            mime = NormalizeMime(match.Groups[1].Value);
            base64 = match.Groups[2].Value;
            isDataUri = true;
        }

        var cleaned = Regex.Replace(base64, "\\s+", string.Empty);
        if (!Base64Regex.IsMatch(cleaned))
        {
            throw new ArgumentException("Imagem em base64 inválida.");
        }

        byte[] binary;
        try
        {
            binary = Convert.FromBase64String(cleaned);
        }
        catch (FormatException)
        {
            throw new ArgumentException("Imagem em base64 inválida.");
        }

        if (binary.Length == 0)
        {
            throw new ArgumentException("A imagem em base64 está vazia.");
        }

        if (binary.Length > MaxFileSizeBytes)
        {
            throw new ArgumentException("Arquivo excede o limite de 10MB.");
        }

        mime ??= DetectMimeFromBinary(binary);
        if (mime == null || !GetAllowedImageMimes(model).Contains(mime))
        {
            throw new ArgumentException("Não foi possível identificar o tipo da imagem fornecida.");
        }

        return isDataUri ? $"data:{mime};base64,{cleaned}" : cleaned;
    }

    private ImageOptionsResult NormalizeImageOptions(IDictionary<string, object?>? options, string model, int imageCount)
    {
        options ??= new Dictionary<string, object?>();
        var result = new ImageOptionsResult();

        if (options.TryGetValue("format", out var formatObj) || options.TryGetValue("formato", out formatObj))
        {
            var format = formatObj?.ToString()?.Trim().ToLowerInvariant();
            if (format != null && !ImageAllowedFormats.Contains(format))
            {
                throw new ArgumentException("O campo formato deve ser \"json\" ou \"texto\".");
            }
            result.Format = format;
        }

        if (options.TryGetValue("notification_format", out var notificationFormatObj) || options.TryGetValue("formato_notificacao", out notificationFormatObj))
        {
            var candidate = notificationFormatObj?.ToString()?.Trim().ToLowerInvariant();
            if (string.IsNullOrEmpty(candidate))
            {
                throw new ArgumentException("O campo formato_notificacao não pode ser vazio.");
            }
            if (!NotificationAllowedFormats.Contains(candidate))
            {
                throw new ArgumentException("O campo formato_notificacao deve ser \"url_encoded\" ou \"json\".");
            }
            result.NotificationFormat = candidate;
        }

        if (options.TryGetValue("async", out var asyncObj))
        {
            result.AsyncValue = NormalizeBooleanOption(asyncObj, "async");
        }
        else if (options.TryGetValue("assincrono", out asyncObj))
        {
            result.AsyncValue = NormalizeBooleanOption(asyncObj, "assincrono");
        }

        if (!result.AsyncValue.HasValue && imageCount > 1)
        {
            result.AsyncValue = true;
        }

        if (options.TryGetValue("notification_url", out var urlObj) || options.TryGetValue("url_notificacao", out urlObj))
        {
            result.NotificationUrl = NormalizeNotificationUrl(urlObj?.ToString());
        }

        var needsNotification = (result.Format == "texto") || result.AsyncValue == true || imageCount > 1;
        if (needsNotification && result.NotificationUrl == null)
        {
            throw new ArgumentException("O campo url_notificacao é obrigatório quando formato=texto, assincrono=true ou quando houver mais de uma imagem.");
        }

        if (result.NotificationFormat != null && result.NotificationUrl == null)
        {
            throw new ArgumentException("Defina url_notificacao ao informar formato_notificacao.");
        }

        return result;
    }

    private XmlOptionsResult NormalizeXmlOptions(IDictionary<string, object?>? options)
    {
        options ??= new Dictionary<string, object?>();
        var result = new XmlOptionsResult();

        if (options.TryGetValue("model", out var modelObj) || options.TryGetValue("modelo", out modelObj))
        {
            var model = modelObj?.ToString()?.Trim().ToLowerInvariant();
            if (!string.IsNullOrEmpty(model) && !XmlAllowedModels.Contains(model))
            {
                throw new ArgumentException("Modelo inválido para validação de XML.");
            }
            result.Model = string.IsNullOrEmpty(model) ? null : model;
        }

        if (options.TryGetValue("format", out var formatObj) || options.TryGetValue("formato", out formatObj))
        {
            var format = formatObj?.ToString()?.Trim().ToLowerInvariant();
            if (format != null && !XmlAllowedFormats.Contains(format))
            {
                throw new ArgumentException("O campo formato deve ser \"json\" ou \"texto\".");
            }
            result.Format = format;
        }

        if (options.TryGetValue("async", out var asyncObj) || options.TryGetValue("assincrono", out asyncObj))
        {
            result.AsyncValue = NormalizeBooleanOption(asyncObj, "assincrono");
        }

        if (options.TryGetValue("sync", out var syncObj) || options.TryGetValue("sincrono", out syncObj))
        {
            result.SyncValue = NormalizeBooleanOption(syncObj, "sincrono");
        }

        if (options.TryGetValue("notification_url", out var urlObj) || options.TryGetValue("url_notificacao", out urlObj))
        {
            result.NotificationUrl = NormalizeNotificationUrl(urlObj?.ToString());
        }

        if (options.TryGetValue("notification_format", out var notificationFormatObj) || options.TryGetValue("formato_notificacao", out notificationFormatObj))
        {
            var candidate = notificationFormatObj?.ToString()?.Trim().ToLowerInvariant();
            if (string.IsNullOrEmpty(candidate))
            {
                throw new ArgumentException("O campo formato_notificacao não pode ser vazio.");
            }
            if (!NotificationAllowedFormats.Contains(candidate))
            {
                throw new ArgumentException("O campo formato_notificacao deve ser \"url_encoded\" ou \"json\".");
            }
            result.NotificationFormat = candidate;
        }

        if (result.AsyncValue == true && result.NotificationUrl == null)
        {
            throw new ArgumentException("url_notificacao é obrigatória quando assincrono=true.");
        }

        if (result.SyncValue == false && result.NotificationUrl == null)
        {
            throw new ArgumentException("url_notificacao é obrigatória quando sincrono=false.");
        }

        if (result.NotificationFormat != null && result.NotificationUrl == null)
        {
            throw new ArgumentException("Defina url_notificacao ao informar formato_notificacao.");
        }

        return result;
    }

    private string NormalizeXmlInput(string xml)
    {
        if (xml == null)
        {
            throw new ArgumentException("O conteúdo do XML deve ser informado.", nameof(xml));
        }

        var trimmed = xml.Trim();
        if (trimmed.Length == 0)
        {
            throw new ArgumentException("O conteúdo do XML não pode ser vazio.", nameof(xml));
        }

        if (File.Exists(trimmed))
        {
            var info = new FileInfo(trimmed);
            if (info.Length > MaxFileSizeBytes)
            {
                throw new ArgumentException("O XML informado excede 10MB.");
            }
            var content = File.ReadAllText(trimmed, Encoding.UTF8);
            return NormalizeXmlInput(content);
        }

        if (trimmed.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || trimmed.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("O XML deve ser enviado em base64 ou como arquivo local, URLs não são suportadas.");
        }

        var match = DataUriRegex.Match(trimmed);
        if (match.Success)
        {
            var base64 = Regex.Replace(match.Groups[2].Value, "\\s+", string.Empty);
            if (!Base64Regex.IsMatch(base64))
            {
                throw new ArgumentException("O XML em data URI está vazio ou inválido.");
            }
            var decoded = Convert.FromBase64String(base64);
            if (decoded.Length > MaxFileSizeBytes)
            {
                throw new ArgumentException("O XML informado excede 10MB.");
            }
            return $"data:application/xml;base64,{base64}";
        }

        var compact = Regex.Replace(trimmed, "\\s+", string.Empty);
        if (Base64Regex.IsMatch(compact))
        {
            var decoded = Convert.FromBase64String(compact);
            if (decoded.Length > MaxFileSizeBytes)
            {
                throw new ArgumentException("O XML informado excede 10MB.");
            }
            return $"data:application/xml;base64,{compact}";
        }

        if (trimmed.Contains('<') && trimmed.Contains('>'))
        {
            var bytes = Encoding.UTF8.GetBytes(trimmed);
            if (bytes.Length > MaxFileSizeBytes)
            {
                throw new ArgumentException("O XML informado excede 10MB.");
            }
            return $"data:application/xml;base64,{Convert.ToBase64String(bytes)}";
        }

        throw new ArgumentException("Informe o XML como conteúdo base64, data URI ou arquivo válido.");
    }

    private string NormalizeNotificationUrl(string? url)
    {
        if (url == null)
        {
            return null;
        }
        var trimmed = url.Trim();
        if (trimmed.Length == 0)
        {
            throw new ArgumentException("O campo url_notificacao não pode ser vazio.");
        }
        if (!Uri.TryCreate(trimmed, UriKind.Absolute, out var uri))
        {
            throw new ArgumentException("Informe uma url_notificacao válida.");
        }
        if (!string.Equals(uri.Scheme, "http", StringComparison.OrdinalIgnoreCase) && !string.Equals(uri.Scheme, "https", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("A url_notificacao deve utilizar HTTP ou HTTPS.");
        }
        if (string.IsNullOrWhiteSpace(uri.Host) || !IsHostSafe(uri.Host))
        {
            throw new ArgumentException("A url_notificacao informada não é permitida.");
        }
        return uri.ToString();
    }

    private bool NormalizeBooleanOption(object? value, string field)
    {
        if (value is bool b)
        {
            return b;
        }
        if (value is int i)
        {
            return i != 0;
        }
        if (value is long l)
        {
            return l != 0L;
        }
        if (value is string s)
        {
            var normalized = s.Trim().ToLowerInvariant();
            if (normalized is "true" or "1" or "yes" or "sim")
            {
                return true;
            }
            if (normalized is "false" or "0" or "no" or "nao" or "não")
            {
                return false;
            }
        }
        throw new ArgumentException($"O campo {field} deve ser booleano.");
    }

    private HashSet<string> GetAllowedImageMimes(string model)
    {
        if (model.Equals("nfce", StringComparison.OrdinalIgnoreCase))
        {
            return new HashSet<string>(new[] { "image/jpeg", "image/png" }, StringComparer.OrdinalIgnoreCase);
        }
        return new HashSet<string>(AllowedImageMimes, StringComparer.OrdinalIgnoreCase);
    }

    private void AssertImageCount(int count)
    {
        if (count <= 0)
        {
            throw new ArgumentException("É necessário informar ao menos uma imagem.");
        }
        if (count > MaxImagesPerRequest)
        {
            throw new ArgumentException($"Envie no máximo {MaxImagesPerRequest} imagens por requisição.");
        }
    }

    private async Task<RemoteFileInfo> FetchRemoteFileInfoAsync(Uri uri)
    {
        var info = await HeadRemoteFileAsync(uri).ConfigureAwait(false);
        if (!info.Size.HasValue || info.Size.Value <= 0 || info.Mime == null)
        {
            var fallback = await RangeRemoteFileAsync(uri).ConfigureAwait(false);
            if (info.Mime == null)
            {
                info.Mime = fallback.Mime;
            }
            if (!info.Size.HasValue || info.Size.Value <= 0)
            {
                info.Size = fallback.Size;
            }
        }
        return info;
    }

    private async Task<RemoteFileInfo> HeadRemoteFileAsync(Uri uri)
    {
        using var client = CreatePlainHttpClient(RemoteHeadTimeout);
        using var request = new HttpRequestMessage(HttpMethod.Head, uri);
        request.Headers.UserAgent.ParseAdd(_userAgent);
        var info = new RemoteFileInfo();
        try
        {
            using var response = await client.SendAsync(request).ConfigureAwait(false);
            if (response.IsSuccessStatusCode)
            {
                if (response.Content.Headers.ContentType != null)
                {
                    info.Mime = NormalizeMime(response.Content.Headers.ContentType.MediaType ?? string.Empty);
                }
                if (response.Content.Headers.ContentLength.HasValue)
                {
                    info.Size = response.Content.Headers.ContentLength.Value;
                }
            }
            return info;
        }
        catch
        {
            return info;
        }
    }

    private async Task<RemoteFileInfo> RangeRemoteFileAsync(Uri uri)
    {
        using var client = CreatePlainHttpClient(RemoteRangeTimeout);
        using var request = new HttpRequestMessage(HttpMethod.Get, uri);
        request.Headers.UserAgent.ParseAdd(_userAgent);
        request.Headers.Range = new RangeHeaderValue(0, MaxFileSizeBytes);

        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw new ArgumentException("Não foi possível acessar a URL informada.");
        }

        var info = new RemoteFileInfo();
        if (response.Content.Headers.ContentLength.HasValue)
        {
            info.Size = response.Content.Headers.ContentLength.Value;
        }
        else if (response.Content.Headers.ContentRange?.Length.HasValue == true)
        {
            info.Size = response.Content.Headers.ContentRange.Length;
        }

        if (!info.Size.HasValue || info.Size.Value <= 0)
        {
            throw new ArgumentException("Não foi possível determinar o tamanho do arquivo informado.");
        }

        if (info.Size.Value > MaxFileSizeBytes)
        {
            throw new ArgumentException("Arquivo excede o limite de 10MB na URL informada.");
        }

        if (response.Content.Headers.ContentType != null)
        {
            info.Mime = NormalizeMime(response.Content.Headers.ContentType.MediaType ?? string.Empty);
        }

        // Drain response to free connection
        using (var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false))
        {
            var buffer = new byte[8192];
            while (await stream.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false) > 0) { }
        }

        return info;
    }

    private HttpClient CreatePlainHttpClient(TimeSpan timeout)
    {
        var handler = new HttpClientHandler
        {
            AllowAutoRedirect = false
        };
        return new HttpClient(handler)
        {
            Timeout = timeout
        };
    }

    private bool IsHostSafe(string host)
    {
        var normalized = host.Trim().ToLowerInvariant();
        if (normalized.Length == 0)
        {
            return false;
        }

        if (BlockedHosts.Contains(normalized))
        {
            return false;
        }

        foreach (var pattern in BlockedHostPatterns)
        {
            if (pattern.IsMatch(normalized))
            {
                return false;
            }
        }

        if (IPAddress.TryParse(normalized, out var literalAddress))
        {
            return IsIpAddressAllowed(literalAddress);
        }

        try
        {
            var resolvedAddresses = Dns.GetHostAddresses(normalized);
            if (resolvedAddresses == null || resolvedAddresses.Length == 0)
            {
                return false;
            }

            foreach (var address in resolvedAddresses)
            {
                if (!IsIpAddressAllowed(address))
                {
                    return false;
                }
            }

            return true;
        }
        catch (SocketException)
        {
            return false;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    private bool IsIpAddressAllowed(IPAddress address)
    {
        if (IPAddress.Any.Equals(address) || IPAddress.IPv6Any.Equals(address))
        {
            return false;
        }

        if (IPAddress.IsLoopback(address))
        {
            return false;
        }

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var bytes = address.GetAddressBytes();
            if (bytes[0] == 10 || bytes[0] == 127 || bytes[0] == 0)
            {
                return false;
            }
            if (bytes[0] == 169 && bytes[1] == 254)
            {
                return false;
            }
            if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
            {
                return false;
            }
            if (bytes[0] == 192 && bytes[1] == 168)
            {
                return false;
            }

            return true;
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (address.IsIPv6LinkLocal || address.IsIPv6Multicast || address.IsIPv6SiteLocal)
            {
                return false;
            }

            var text = address.ToString().ToLowerInvariant();
            if (text == "::1")
            {
                return false;
            }

            if (text.StartsWith("::ffff:" , StringComparison.Ordinal))
            {
                var mappedText = text.Substring(7);
                if (IPAddress.TryParse(mappedText, out var mappedAddress))
                {
                    return IsIpAddressAllowed(mappedAddress);
                }
            }

            if (text.StartsWith("fe80", StringComparison.Ordinal) || text.StartsWith("fc", StringComparison.Ordinal) || text.StartsWith("fd", StringComparison.Ordinal))
            {
                return false;
            }

            return true;
        }

        return false;
    }

    private string? NormalizeMime(string? mime)
    {
        if (string.IsNullOrWhiteSpace(mime))
        {
            return null;
        }
        var normalized = mime.Trim().ToLowerInvariant();
        return normalized switch
        {
            "image/jpg" or "image/pjpeg" => "image/jpeg",
            "image/x-png" => "image/png",
            "application/x-pdf" => "application/pdf",
            _ => normalized
        };
    }

    private static string? DetectMimeFromBinary(byte[] binary)
    {
        if (binary.Length >= 4)
        {
            if (binary[0] == 0x25 && binary[1] == 0x50 && binary[2] == 0x44 && binary[3] == 0x46)
            {
                return "application/pdf";
            }
            if (binary[0] == 0xFF && binary[1] == 0xD8 && binary[2] == 0xFF)
            {
                return "image/jpeg";
            }
            if (binary[0] == 0x89 && binary[1] == 0x50 && binary[2] == 0x4E && binary[3] == 0x47)
            {
                return "image/png";
            }
        }
        return null;
    }

    private string NormalizeProvider(string provider)
    {
        if (string.IsNullOrWhiteSpace(provider))
        {
            throw new ArgumentException("O identificador do provedor não pode ser vazio.", nameof(provider));
        }
        return provider.Trim().ToLowerInvariant();
    }

    private string NormalizeBaseUri(string baseUri)
    {
        if (string.IsNullOrWhiteSpace(baseUri))
        {
            throw new ArgumentException("A base URL não pode ser vazia.", nameof(baseUri));
        }
        var trimmed = baseUri.Trim();
        return trimmed.TrimEnd('/') + "/";
    }

    private static string? GetFileMime(string path)
    {
        var extension = Path.GetExtension(path);
        if (!string.IsNullOrWhiteSpace(extension))
        {
            switch (extension.ToLowerInvariant())
            {
                case ".jpg":
                case ".jpeg":
                    return "image/jpeg";
                case ".png":
                    return "image/png";
                case ".pdf":
                    return "application/pdf";
            }
        }

        try
        {
            using var stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            var buffer = new byte[4];
            var read = stream.Read(buffer, 0, buffer.Length);
            if (read <= 0)
            {
                return null;
            }
            if (read < buffer.Length)
            {
                Array.Resize(ref buffer, read);
            }
            return DetectMimeFromBinary(buffer);
        }
        catch
        {
            return null;
        }
    }

    private object? ParseBody(string body)
    {
        if (string.IsNullOrWhiteSpace(body))
        {
            return null;
        }

        try
        {
            return JsonSerializer.Deserialize<JsonElement>(body, _jsonOptions);
        }
        catch
        {
            return body;
        }
    }
}
