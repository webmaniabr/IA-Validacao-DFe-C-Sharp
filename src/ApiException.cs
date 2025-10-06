namespace WebmaniaBR.AI.Validation;

public class ApiException : Exception
{
    public int? StatusCode { get; }
    public string? ResponseBody { get; }

    public ApiException(string message) : base(message)
    {
    }

    public ApiException(string message, int? statusCode, string? responseBody) : base(message)
    {
        StatusCode = statusCode;
        ResponseBody = responseBody;
    }
}
