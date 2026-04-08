using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Antiforgery;
using Npgsql;
using SecureEmployeeAPI.Models;

namespace SecureEmployeeAPI.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [EnableRateLimiting("api-limit")]   // DoS Protection
    public class EmployeesController : ControllerBase
    {
        private readonly string _conn;
        private readonly IAntiforgery _antiforgery;

        public EmployeesController(IConfiguration config, IAntiforgery antiforgery)
        {
            _conn = config.GetConnectionString("PostgresConnection");
            _antiforgery = antiforgery;
        }
        // Generate CSRF Token 
        // ✅ Generate CSRF Token
        [HttpGet("token")]
        public IActionResult GetToken()
        {
            var tokens = _antiforgery.GetAndStoreTokens(HttpContext);
            return Ok(tokens.RequestToken);
        }

        // ✅ SQL Injection Safe GET
        [HttpGet]
        public IActionResult GetEmployee(string name)
        {
            string sql = "SELECT * FROM employees WHERE name = @name";

            using var conn = new NpgsqlConnection(_conn);
            using var cmd = new NpgsqlCommand(sql, conn);
            cmd.Parameters.AddWithValue("@name", name);

            conn.Open();
            var reader = cmd.ExecuteReader();

            List<Employee> list = new();

            while (reader.Read())
            {
                list.Add(new Employee
                {
                    Id = reader.GetInt32(0),
                    Name = reader.GetString(1),
                    Department = reader.GetString(2)
                });
            }

            return Ok(list);
        }
        //this api for the validdaeantiforgerytoekn
        // ✅ CSRF Protected POST
        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult AddEmployee(Employee emp)
        {
            string sql = "INSERT INTO employees(name, department) VALUES(@name, @dept)";

            using var conn = new NpgsqlConnection(_conn);
            using var cmd = new NpgsqlCommand(sql, conn);
            cmd.Parameters.AddWithValue("@name", emp.Name);
            cmd.Parameters.AddWithValue("@dept", emp.Department);
            
    // Open Connection to using the connection object with the relevant parameter
            conn.Open();
            cmd.ExecuteNonQuery();

            return Ok("Employee Added Securely");
        }
    }
}


