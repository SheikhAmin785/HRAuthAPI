using HRAuthAPI.Data;
using HRAuthAPI.Models;

namespace HRAuthAPI.Services;

public class AuthService
{
    private readonly OracleDbService _db;
    private readonly ILogger<AuthService> _logger;

    public AuthService(OracleDbService db, ILogger<AuthService> logger)
    {
        _db = db;
        _logger = logger;
    }

    private static string Sanitize(string input)
    {
        return input
            .Replace("=", "")
            .Replace("'", "")
            .Replace("\"", "")
            .Replace("%", "")
            .Trim();
    }

    public async Task<(bool Success, UserInfo? User, string Message)> LoginAsync(
        string userId, string password)
    {
        userId = Sanitize(userId);
        password = Sanitize(password);

        if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(password))
            return (false, null, "User ID and Password are required.");

        _logger.LogInformation("Login attempt — UserId: {UserId}", userId);

        
        try
        {
            
            var adminSql = @"SELECT DISTINCT ""admin_code"", ""uid"", ""uid"", ""user_type""
                             FROM meghnahr.""hr_user_master""
                             WHERE ""uid"" = :p_uid AND ""pwd"" = :p_pwd";

            var adminDt = await _db.QueryAsync(adminSql, "HR", new Dictionary<string, object>
            {
                { "p_uid", userId   },
                { "p_pwd", password }
            });

            if (adminDt.Rows.Count > 0)
            {
                var row = adminDt.Rows[0];
                var user = new UserInfo
                {
                    UserId = row[1]?.ToString() ?? userId,
                    UserName = row[2]?.ToString() ?? userId,
                    UserType = row[3]?.ToString() ?? "ADMIN",
                    BranchCode = "0",
                    BranchName = "Head Office",
                    AdminType = row[0]?.ToString() ?? "",
                    EmployeeId = ""
                };

                await LogLoginAsync(userId);
                return (true, user, "Login successful.");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Admin login query failed for user: {UserId}", userId);
        }

      
        try
        {
            var empSql = @"SELECT DISTINCT 
                               ""Employee ID"", 
                               ""User ID"", 
                               ""Password"",
                               (SELECT b.""Branch Name"" 
                                FROM meghnahr.""branch"" b 
                                WHERE b.""branch_id"" = e.""Appointment Branch"") AS branch_name,
                               ""Appointment Branch"",
                               ""Employee Name""
                           FROM meghnahr.""employee"" e
                           WHERE ""User ID""  = :p_uid 
                             AND ""Password"" = :p_pwd 
                             AND ""status""   = 'Active'
                             AND ""sep_code"" IS NULL";

            var empDt = await _db.QueryAsync(empSql, "HR", new Dictionary<string, object>
            {
                { "p_uid", userId   },
                { "p_pwd", password }
            });

            if (empDt.Rows.Count > 0)
            {
                var row = empDt.Rows[0];
                var user = new UserInfo
                {
                    UserId = row[1]?.ToString() ?? userId,
                    UserName = row[5]?.ToString() ?? userId,
                    UserType = "Employee",
                    BranchCode = row[4]?.ToString() ?? "",
                    BranchName = row[3]?.ToString() ?? "",
                    AdminType = "",
                    EmployeeId = row[0]?.ToString() ?? ""
                };

                await LogLoginAsync(userId);
                return (true, user, "Login successful.");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Employee login query failed for user: {UserId}", userId);
        }

        return (false, null, "Invalid User ID or Password.");
    }

    private async Task LogLoginAsync(string userId)
    {
        try
        {
            var logSql = @"INSERT INTO meghna.login_log 
                               (""user_id"", ""login_date"", ""log_type"") 
                           VALUES 
                               (:p_uid, :p_date, 'Login')";

            await _db.ExecuteAsync(logSql, "MAIN", new Dictionary<string, object>
            {
                { "p_uid",  userId      },
                { "p_date", DateTime.Now }
            });
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to log login for: {UserId}", userId);
        }
    }

    public async Task<(bool Success, string Message)> ChangePasswordAsync(
        string userId, string userType, string oldPassword, string newPassword)
    {
        userId = Sanitize(userId);
        oldPassword = Sanitize(oldPassword);
        newPassword = Sanitize(newPassword);

        if (userType.ToUpper() == "ADMIN")
        {
            var count = await _db.ScalarAsync(
                @"SELECT COUNT(*) FROM meghnahr.""hr_user_master"" 
                  WHERE ""uid"" = :p_uid AND ""pwd"" = :p_pwd",
                "HR",
                new Dictionary<string, object> { { "p_uid", userId }, { "p_pwd", oldPassword } });

            if (int.Parse(count) == 0)
                return (false, "Old password is incorrect.");

            await _db.ExecuteAsync(
                @"UPDATE meghnahr.""hr_user_master"" 
                  SET ""pwd"" = :p_newpwd 
                  WHERE ""uid"" = :p_uid AND ""pwd"" = :p_oldpwd",
                "HR",
                new Dictionary<string, object>
                {
                    { "p_newpwd", newPassword },
                    { "p_uid",    userId      },
                    { "p_oldpwd", oldPassword }
                });
        }
        else
        {
            var count = await _db.ScalarAsync(
                @"SELECT COUNT(*) FROM meghnahr.""employee"" 
                  WHERE ""User ID"" = :p_uid AND ""Password"" = :p_pwd",
                "HR",
                new Dictionary<string, object> { { "p_uid", userId }, { "p_pwd", oldPassword } });

            if (int.Parse(count) == 0)
                return (false, "Old password is incorrect.");

            await _db.ExecuteAsync(
                @"UPDATE meghnahr.""employee"" 
                  SET ""Password"" = :p_newpwd 
                  WHERE ""User ID"" = :p_uid AND ""Password"" = :p_oldpwd",
                "HR",
                new Dictionary<string, object>
                {
                    { "p_newpwd", newPassword },
                    { "p_uid",    userId      },
                    { "p_oldpwd", oldPassword }
                });
        }

        return (true, "Password changed successfully.");
    }
}