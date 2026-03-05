using Oracle.ManagedDataAccess.Client;
using System.Data;

namespace HRAuthAPI.Data;

public class OracleDbService
{
    private readonly string _hrConn;
    private readonly string _mainConn;
    private readonly string _supportConn;
    private readonly ILogger<OracleDbService> _logger;

    public OracleDbService(IConfiguration config, ILogger<OracleDbService> logger)
    {
        _hrConn = config.GetConnectionString("OracleHR")
            ?? throw new InvalidOperationException("OracleHR connection string missing");
        _mainConn = config.GetConnectionString("OracleMain") ?? _hrConn;
        _supportConn = config.GetConnectionString("OracleSupport") ?? _hrConn;
        _logger = logger;
    }

    private string GetConn(string key) => key.ToUpper() switch
    {
        "MAIN" => _mainConn,
        "SUPPORT" => _supportConn,
        _ => _hrConn   // default: HR
    };

   
    public async Task<DataTable> QueryAsync(string sql, string connKey = "HR",
        Dictionary<string, object>? parameters = null)
    {
        var dt = new DataTable();
        try
        {
            await using var conn = new OracleConnection(GetConn(connKey));
            await conn.OpenAsync();

            await using var cmd = new OracleCommand(sql, conn);
            cmd.BindByName = true;  

            if (parameters != null)
            {
                foreach (var p in parameters)
                {
               
                    var paramName = p.Key.TrimStart(':');
                    var param = new OracleParameter(paramName, p.Value ?? DBNull.Value);
                    cmd.Parameters.Add(param);
                }
            }

            using var adapter = new OracleDataAdapter(cmd);
            adapter.Fill(dt);

            _logger.LogInformation("QueryAsync OK — rows: {Count}", dt.Rows.Count);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "QueryAsync failed. SQL: {Sql}", sql);
            throw;
        }
        return dt;
    }

  
    public async Task<int> ExecuteAsync(string sql, string connKey = "HR",
        Dictionary<string, object>? parameters = null)
    {
        try
        {
            await using var conn = new OracleConnection(GetConn(connKey));
            await conn.OpenAsync();

            await using var cmd = new OracleCommand(sql, conn);
            cmd.BindByName = true;

            if (parameters != null)
            {
                foreach (var p in parameters)
                {
                    var paramName = p.Key.TrimStart(':');
                    cmd.Parameters.Add(new OracleParameter(paramName, p.Value ?? DBNull.Value));
                }
            }

            return await cmd.ExecuteNonQueryAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "ExecuteAsync failed. SQL: {Sql}", sql);
            throw;
        }
    }

    
    public async Task<long> ExecuteWithReturnAsync(string sql, string outParamName,
        string connKey = "MAIN", Dictionary<string, object>? parameters = null)
    {
        try
        {
            await using var conn = new OracleConnection(GetConn(connKey));
            await conn.OpenAsync();

            await using var cmd = new OracleCommand(sql, conn);
            cmd.BindByName = true;

            if (parameters != null)
            {
                foreach (var p in parameters)
                {
                    var paramName = p.Key.TrimStart(':');
                    cmd.Parameters.Add(new OracleParameter(paramName, p.Value ?? DBNull.Value));
                }
            }

            var returnParam = new OracleParameter(outParamName.TrimStart(':'), OracleDbType.Int64)
            {
                Direction = ParameterDirection.Output
            };
            cmd.Parameters.Add(returnParam);

            await cmd.ExecuteNonQueryAsync();
            return Convert.ToInt64(returnParam.Value.ToString());
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "ExecuteWithReturnAsync failed. SQL: {Sql}", sql);
            throw;
        }
    }

  
    public async Task<string> ScalarAsync(string sql, string connKey = "HR",
        Dictionary<string, object>? parameters = null)
    {
        var dt = await QueryAsync(sql, connKey, parameters);
        if (dt.Rows.Count > 0 && dt.Columns.Count > 0)
            return dt.Rows[0][0]?.ToString() ?? string.Empty;
        return string.Empty;
    }
}