namespace WebmaniaBR.AI.Validation;

public class ValidationClientOptions
{
    public string? BaseUri { get; set; }
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);
    public string? UserAgent { get; set; }
}
