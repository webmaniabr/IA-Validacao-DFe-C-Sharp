# Validação de Documentos Fiscais com IA - SDK para C#/.NET

[![NuGet](https://img.shields.io/nuget/v/WebmaniaBR.AI.Validation.svg)](https://www.nuget.org/packages/WebmaniaBR.AI.Validation/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![.NET](https://img.shields.io/badge/.NET-6.0%2B-512BD4)](https://dotnet.microsoft.com/download)

SDK oficial em C#/.NET para consumir a API de Validação de Documentos Fiscais com IA da WebmaniaBR. Valide NFe, NFCe, NFSe, CTe e MDFe através de imagens ou XML com tecnologia de inteligência artificial.

## 📋 Índice

- [Instalação](#-instalação)
  - [Via NuGet](#via-nuget)
  - [Via Docker](#via-docker)
- [Configuração Inicial](#-configuração-inicial)
- [Métodos Disponíveis](#-métodos-disponíveis)
- [Exemplos de Uso](#-exemplos-de-uso)
  - [Validação de Imagens](#validação-de-imagens)
  - [Validação de XML](#validação-de-xml)
  - [Gerenciamento de Integrações](#gerenciamento-de-integrações)
  - [Consulta de Status](#consulta-de-status)
- [Docker](#-docker)
  - [Build e Execução](#build-e-execução)
  - [Exemplos com Docker](#exemplos-com-docker)
- [Regras de Negócio](#-regras-de-negócio)
- [Tratamento de Erros](#-tratamento-de-erros)
- [Requisitos](#-requisitos)
- [Suporte](#-suporte)
- [Licença](#-licença)

## 🚀 Instalação

### Via NuGet

```bash
# Package Manager
Install-Package WebmaniaBR.AI.Validation

# .NET CLI
dotnet add package WebmaniaBR.AI.Validation

# PackageReference
<PackageReference Include="WebmaniaBR.AI.Validation" Version="1.0.0" />
```

### Via Docker

```bash
# Clone o repositório
git clone https://github.com/webmaniabr/IA-Validacao-DFe-C-Sharp.git
cd IA-Validacao-DFe-C-Sharp

# Build da imagem
docker build -t webmania/csharp-sdk .

# Executar
docker run --rm webmania/csharp-sdk
```

## ⚙️ Configuração Inicial

```csharp
using WebmaniaBR.AI.Validation;

// Configuração básica
var client = new ValidationClient("SEU_TOKEN_API");

// Configuração com opções personalizadas
var client = new ValidationClient("SEU_TOKEN_API", new ValidationClientOptions
{
    Timeout = TimeSpan.FromSeconds(60)  // Timeout personalizado
});
```

## 📦 Métodos Disponíveis

| Método | Descrição |
|--------|-----------|
| `ValidateImageByUrlAsync` | Valida documentos fiscais através de URLs de imagens |
| `ValidateImageByBase64Async` | Valida documentos fiscais através de imagens em Base64 |
| `ValidateImageUploadAsync` | Valida documentos fiscais através de upload de arquivos |
| `ValidateXmlAsync` | Valida documentos fiscais através de XML |
| `RegisterIntegrationAsync` | Registra integração com provedores externos |
| `GetIntegrationAsync` | Consulta integração registrada |
| `DeleteIntegrationAsync` | Remove integração registrada |
| `GetValidationLogAsync` | Consulta status de validação por UUID |

## 💡 Exemplos de Uso

### Validação de Imagens

#### Por URL (Síncrono - Uma Imagem)
```csharp
var resultado = await client.ValidateImageByUrlAsync(
    "nfce", 
    new[] { "https://exemplo.com/nota-fiscal.jpg" },
    new Dictionary<string, object?>
    {
        ["formato"] = "json",
        ["assincrono"] = false
    }
);
```

#### Por URL (Assíncrono - Múltiplas Imagens)
```csharp
var resultado = await client.ValidateImageByUrlAsync(
    "nfe", 
    new[] { 
        "https://exemplo.com/nota1.jpg",
        "https://exemplo.com/nota2.jpg" 
    },
    new Dictionary<string, object?>
    {
        ["formato"] = "json",
        ["url_notificacao"] = "https://seu-webhook.com/callback"
    }
);
```

#### Por Base64
```csharp
var base64Image = Convert.ToBase64String(File.ReadAllBytes("nota.jpg"));

var resultado = await client.ValidateImageByBase64Async(
    "nfce",
    new[] { base64Image },
    new Dictionary<string, object?>
    {
        ["assincrono"] = true,
        ["url_notificacao"] = "https://seu-webhook.com/callback"
    }
);
```

#### Por Upload de Arquivo
```csharp
var resultado = await client.ValidateImageUploadAsync(
    "nfe",
    new[] { 
        "/caminho/para/nota1.pdf",
        "/caminho/para/nota2.jpg" 
    },
    new Dictionary<string, object?>
    {
        ["url_notificacao"] = "https://seu-webhook.com/callback"
    }
);
```

### Validação de XML

```csharp
// Via arquivo
var resultado = await client.ValidateXmlAsync(
    "/caminho/para/nfe.xml",
    new Dictionary<string, object?>
    {
        ["modelo"] = "nfe",
        ["formato"] = "json"
    }
);

// Via conteúdo XML direto
var xmlContent = @"<?xml version=""1.0""?><NFe>...</NFe>";
var resultado = await client.ValidateXmlAsync(
    xmlContent,
    new Dictionary<string, object?>
    {
        ["modelo"] = "nfe"
    }
);
```

### Gerenciamento de Integrações

```csharp
// Registrar integração
var cadastro = await client.RegisterIntegrationAsync(
    "sefaz",
    new Dictionary<string, object?>
    {
        ["api_key"] = "sua_chave",
        ["api_secret"] = "seu_segredo"
    }
);

// Consultar integração
var integracao = await client.GetIntegrationAsync("sefaz");

// Remover integração
var remocao = await client.DeleteIntegrationAsync("sefaz");
```

### Consulta de Status

```csharp
// Consultar status de validação assíncrona
var status = await client.GetValidationLogAsync("uuid-da-validacao");
```

## 🐳 Docker

### Build e Execução

```bash
# Build da imagem
docker build -t webmania/csharp-sdk .

# Ver instruções de uso
docker run --rm webmania/csharp-sdk

# Executar com token
docker run --rm \
  -e WEBMANIA_TOKEN="seu-token" \
  -e METHOD="help" \
  webmania/csharp-sdk
```

### Exemplos com Docker

#### Validar Imagem por URL

```bash
# Validação síncrona (uma imagem)
docker run --rm \
  -e WEBMANIA_TOKEN="seu-token" \
  -e METHOD="ValidateImageByUrlAsync" \
  -e MODELO="nfce" \
  -e IMAGENS_URLS="https://exemplo.com/nota.jpg" \
  -e ASSINCRONO="false" \
  webmania/csharp-sdk

# Validação assíncrona (múltiplas imagens)
docker run --rm \
  -e WEBMANIA_TOKEN="seu-token" \
  -e METHOD="ValidateImageByUrlAsync" \
  -e MODELO="nfe" \
  -e IMAGENS_URLS="url1.jpg,url2.jpg,url3.jpg" \
  -e URL_NOTIFICACAO="https://webhook.site/..." \
  webmania/csharp-sdk
```

#### Validar com Base64

```bash
docker run --rm \
  -e WEBMANIA_TOKEN="seu-token" \
  -e METHOD="ValidateImageByBase64Async" \
  -e MODELO="nfce" \
  -e IMAGENS_BASE64="base64_string_aqui" \
  -e ASSINCRONO="true" \
  -e URL_NOTIFICACAO="https://webhook.site/..." \
  webmania/csharp-sdk
```

#### Upload de Arquivos Locais

```bash
docker run --rm \
  -v /seu/caminho/local:/images:ro \
  -e WEBMANIA_TOKEN="seu-token" \
  -e METHOD="ValidateImageUploadAsync" \
  -e MODELO="nfe" \
  -e FILE_PATHS="/images/nota1.jpg,/images/nota2.pdf" \
  -e URL_NOTIFICACAO="https://webhook.site/..." \
  webmania/csharp-sdk
```

#### Validar XML

```bash
# Com conteúdo XML direto
docker run --rm \
  -e WEBMANIA_TOKEN="seu-token" \
  -e METHOD="ValidateXmlAsync" \
  -e XML_CONTENT="<NFe>...</NFe>" \
  -e MODELO_XML="nfe" \
  -e FORMATO="json" \
  webmania/csharp-sdk

# Com arquivo XML montado
docker run --rm \
  -v /caminho/para/xml:/data:ro \
  -e WEBMANIA_TOKEN="seu-token" \
  -e METHOD="ValidateXmlAsync" \
  -e XML_FILE="/data/nota.xml" \
  -e MODELO_XML="nfe" \
  webmania/csharp-sdk
```

#### Consultar Status

```bash
docker run --rm \
  -e WEBMANIA_TOKEN="seu-token" \
  -e METHOD="GetValidationLogAsync" \
  -e UUID="uuid-da-validacao" \
  webmania/csharp-sdk
```

#### Modo Debug

```bash
docker run --rm \
  -e WEBMANIA_TOKEN="seu-token" \
  -e METHOD="ValidateImageByUrlAsync" \
  -e MODELO="nfce" \
  -e IMAGENS_URLS="https://exemplo.com/nota.jpg" \
  -e DEBUG="true" \
  webmania/csharp-sdk
```

### Variáveis de Ambiente Docker

| Variável | Descrição | Obrigatório |
|----------|-----------|------------|
| `WEBMANIA_TOKEN` | Token de autenticação da API | ✅ |
| `METHOD` | Método do SDK a ser executado | ✅ |
| `MODELO` | Modelo do documento (nfe, nfce, nfse) | Depende do método |
| `IMAGENS_URLS` | URLs das imagens (separadas por vírgula) | Para ValidateImageByUrl |
| `IMAGENS_BASE64` | Imagens em Base64 (separadas por vírgula) | Para ValidateImageByBase64 |
| `FILE_PATHS` | Caminhos dos arquivos (separados por vírgula) | Para ValidateImageUpload |
| `XML_CONTENT` | Conteúdo XML direto | Para ValidateXml |
| `XML_FILE` | Caminho do arquivo XML | Para ValidateXml |
| `UUID` | UUID da validação | Para GetValidationLog |
| `PROVIDER` | Nome do provedor de integração | Para integrações |
| `URL_NOTIFICACAO` | URL para callback de notificação | Para async=true |
| `ASSINCRONO` | Processamento assíncrono (true/false) | Opcional |
| `FORMATO` | Formato de resposta (json/texto) | Opcional |
| `DEBUG` | Modo debug (true/false) | Opcional |

## 📝 Regras de Negócio

### Processamento Assíncrono

- **Uma imagem**: Pode escolher entre síncrono ou assíncrono
- **Múltiplas imagens**: Sempre processado de forma assíncrona
- **Formato texto**: Sempre requer processamento assíncrono
- **Assíncrono = true**: Requer `url_notificacao`

### Limites

- Máximo de **10 imagens** por requisição
- Tamanho máximo por arquivo: **10 MB**
- Formatos aceitos: **JPEG, PNG, PDF**
- Modelos aceitos para imagens: **nfe, nfce, nfse**
- Modelos aceitos para XML: **nfe, nfce, cte, mdfe, nfse**

## 🔧 Tratamento de Erros

```csharp
try
{
    var resultado = await client.ValidateImageByUrlAsync(
        "nfce", 
        new[] { "https://exemplo.com/nota.jpg" }
    );
}
catch (ApiException ex)
{
    Console.WriteLine($"Erro API: {ex.Message}");
    Console.WriteLine($"Status: {ex.StatusCode}");
    Console.WriteLine($"Resposta: {ex.ResponseBody}");
}
catch (ArgumentException ex)
{
    Console.WriteLine($"Erro de validação: {ex.Message}");
}
catch (Exception ex)
{
    Console.WriteLine($"Erro geral: {ex.Message}");
}
```

## ✅ Requisitos

- **.NET 6.0** ou superior
- **Docker** (opcional, para uso containerizado)
- Token de API válido da WebmaniaBR

## 📞 Suporte

- **Documentação da API**: [https://webmaniabr.com/docs/](https://webmaniabr.com/docs/)
- **Suporte técnico**: [https://webmaniabr.com/painel/](https://webmaniabr.com/painel/)
- **Issues**: [GitHub Issues](https://github.com/webmaniabr/IA-Validacao-DFe-C-Sharp/issues)

## 📄 Licença

Este projeto está licenciado sob a licença MIT - veja o arquivo [LICENSE](LICENSE) para detalhes.

---

**WebmaniaBR** © 2025 - Todos os direitos reservados
