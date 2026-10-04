using System.Data.SqlClient;
using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

public class UserController : Controller
{
    public IActionResult Find(string name)
    {
        var conn = new SqlConnection("Server=.;Database=app;");
        var cmd = new SqlCommand("SELECT * FROM users WHERE name = '" + name + "'", conn);
        cmd.ExecuteReader();
        return Ok();
    }

    public IActionResult Ping(string host)
    {
        Process.Start("cmd.exe", "/c ping " + host);
        return Ok();
    }
}
