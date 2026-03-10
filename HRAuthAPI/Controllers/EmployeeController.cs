using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using HRAuthAPI.Models;

namespace HRAuthAPI.Controllers;


[ApiController]
[Route("api/[controller]")]
[Authorize]  
public class EmployeeController : ControllerBase
{
 
    [HttpGet("dashboard")]
    public IActionResult GetDashboard()
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        var userType = User.FindFirstValue(ClaimTypes.Role);
        var branchCode = User.FindFirstValue("branch_code");

        return Ok(ApiResponse<object>.Ok(new
        {
            Message = $"Welcome {userId}!",
            UserType = userType,
            BranchCode = branchCode
        }));
    }


    [HttpGet("admin-only")]
    [Authorize(Roles = "ADMIN")]  
    public IActionResult AdminOnlyEndpoint()
    {
        return Ok(ApiResponse<object>.Ok(new
        {
            Message = "You have Admin access.",
            Timestamp = DateTime.Now
        }));
    }

    [HttpGet("branch-data")]
    [Authorize(Roles = "ADMIN,Branch")]
    public IActionResult GetBranchData()
    {
        var branchCode = User.FindFirstValue("branch_code");
        return Ok(ApiResponse<object>.Ok(new
        {
            BranchCode = branchCode,
            Data = "Branch specific data..."
        }));
    }
}