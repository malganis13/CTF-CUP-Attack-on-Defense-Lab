// Demo fixture: deliberately vulnerable. Never compiled or run.
using System.Data.SqlClient;
using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace Vulnbox.Support;

[ApiController]
public class SupportController : ControllerBase
{
    private readonly string connectionString;

    [HttpGet("/ticket")]
    public string Ticket(string id)
    {
        var command = new SqlCommand("SELECT body FROM tickets WHERE id = " + id, new SqlConnection(connectionString));
        return command.ExecuteScalar()?.ToString() ?? "";
    }

    [HttpGet("/convert")]
    public string Convert(string name)
    {
        Process.Start("/usr/bin/convert", name);
        return "ok";
    }
}
