namespace HRAuthAPI.Middleware;

public class RequestLoggingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<RequestLoggingMiddleware> _logger;

    public RequestLoggingMiddleware(RequestDelegate next, ILogger<RequestLoggingMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var start = DateTime.UtcNow;

        await _next(context);

        var duration = (DateTime.UtcNow - start).TotalMilliseconds;
        var userId = context.User?.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value ?? "anonymous";

        _logger.LogInformation(
            "{Method} {Path} → {StatusCode} | User: {UserId} | {Duration}ms",
            context.Request.Method,
            context.Request.Path,
            context.Response.StatusCode,
            userId,
            duration);
    }
}