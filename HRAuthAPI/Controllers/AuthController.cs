using HRAuthAPI.Models;
using HRAuthAPI.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace HRAuthAPI.Controllers;

[ApiController]
[Route("api/[controller]")]
[Produces("application/json")]
public class AuthController : ControllerBase
{
    private readonly AuthService _authService;
    private readonly JwtTokenService _jwtService;
    private readonly ILogger<AuthController> _logger;

    public AuthController(AuthService authService, JwtTokenService jwtService,
        ILogger<AuthController> logger)
    {
        _authService = authService;
        _jwtService = jwtService;
        _logger = logger;
    }


    [HttpPost("login")]
    [AllowAnonymous]
    public async Task<IActionResult> Login([FromBody] Models.LoginRequest request)
    {
        if (!ModelState.IsValid)
            return BadRequest(ApiResponse<object>.Fail("Invalid request data."));

        var (success, user, message) = await _authService.LoginAsync(
            request.UserId, request.Password);

        if (!success || user is null)
        {
            _logger.LogWarning("Login failed for user: {UserId}", request.UserId);
            return Unauthorized(ApiResponse<object>.Fail(message));
        }

        // Generate tokens
        var accessToken = _jwtService.GenerateAccessToken(user);
        var refreshToken = _jwtService.GenerateRefreshToken(user.UserId);

        var expiryMinutes = int.Parse(
            HttpContext.RequestServices
                .GetRequiredService<IConfiguration>()
                .GetSection("JwtSettings")["ExpiryInMinutes"] ?? "480");

        _logger.LogInformation("Login successful for user: {UserId}, Type: {UserType}",
            user.UserId, user.UserType);

        return Ok(ApiResponse<LoginResponse>.Ok(new LoginResponse
        {
            Success = true,
            Message = message,
            Token = accessToken,
            RefreshToken = refreshToken,
            ExpiresAt = DateTime.UtcNow.AddMinutes(expiryMinutes),
            User = user
        }));
    }

  
    [HttpPost("refresh")]
    [AllowAnonymous]
    public IActionResult RefreshToken([FromBody] RefreshTokenRequest request)
    {
        var record = _jwtService.ValidateRefreshToken(request.RefreshToken);
        if (record is null)
            return Unauthorized(ApiResponse<object>.Fail("Invalid or expired refresh token."));

        
        var principal = _jwtService.GetPrincipalFromExpiredToken(
            HttpContext.Request.Headers["Authorization"].ToString().Replace("Bearer ", ""));

        if (principal is null)
            return Unauthorized(ApiResponse<object>.Fail("Invalid access token."));

        var user = BuildUserFromClaims(principal);

      
        _jwtService.RevokeRefreshToken(request.RefreshToken);
        var newAccessToken = _jwtService.GenerateAccessToken(user);
        var newRefreshToken = _jwtService.GenerateRefreshToken(user.UserId);

        return Ok(ApiResponse<object>.Ok(new
        {
            Token = newAccessToken,
            RefreshToken = newRefreshToken
        }));
    }

  
    [HttpPost("logout")]
    [Authorize]
    public IActionResult Logout([FromBody] RefreshTokenRequest request)
    {
        _jwtService.RevokeRefreshToken(request.RefreshToken);
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        _logger.LogInformation("User logged out: {UserId}", userId);
        return Ok(ApiResponse<object>.Ok(null, "Logged out successfully."));
    }


    [HttpGet("me")]
    [Authorize]
    public IActionResult GetCurrentUser()
    {
        var user = BuildUserFromClaims(User);
        return Ok(ApiResponse<UserInfo>.Ok(user));
    }

    
    [HttpPost("change-password")]
    [Authorize]
    public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest request)
    {
        if (request.NewPassword != request.ConfirmNewPassword)
            return BadRequest(ApiResponse<object>.Fail("New passwords do not match."));

        if (request.NewPassword.Length < 6)
            return BadRequest(ApiResponse<object>.Fail("Password must be at least 6 characters."));

        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier)!;
        var userType = User.FindFirstValue(ClaimTypes.Role) ?? "";

        var (success, message) = await _authService.ChangePasswordAsync(
            userId, userType, request.OldPassword, request.NewPassword);

        if (!success)
            return BadRequest(ApiResponse<object>.Fail(message));

        return Ok(ApiResponse<object>.Ok(null, message));
    }


    private static UserInfo BuildUserFromClaims(ClaimsPrincipal principal) => new()
    {
        UserId = principal.FindFirstValue(ClaimTypes.NameIdentifier) ?? "",
        UserName = principal.FindFirstValue(ClaimTypes.Name) ?? "",
        UserType = principal.FindFirstValue(ClaimTypes.Role) ?? "",
        BranchCode = principal.FindFirstValue("branch_code") ?? "",
        BranchName = principal.FindFirstValue("branch_name") ?? "",
        AdminType = principal.FindFirstValue("admin_type") ?? "",
        EmployeeId = principal.FindFirstValue("employee_id") ?? ""
    };
}