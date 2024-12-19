using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using RentaVehiculosAPI.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace RentaVehiculosAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly IAuditService _auditService;
        private readonly AppDbContext _context;

        public AuthController(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration, IAuditService auditService, AppDbContext context)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _auditService = auditService;
            _context = context;
        }

        [Authorize(Roles = "administrador")]
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            var user = new IdentityUser { UserName = model.Username, Email = model.Email };
            var result = await _userManager.CreateAsync(user, model.Password);

            if (!result.Succeeded)
                return BadRequest(result.Errors);

            if (!string.IsNullOrEmpty(model.Role))
            {
                if (!await _roleManager.RoleExistsAsync(model.Role))
                    await _roleManager.CreateAsync(new IdentityRole(model.Role));

                await _userManager.AddToRoleAsync(user, model.Role);
            }

            // Registrar la auditoría
            await _auditService.LogAsync(user.Id, model.Username, "CREATE", "User", $"Usuario {model.Username} registrado con rol {model.Role}.");

            return Ok("Usuario registrado con éxito.");
        }



        [Authorize(Roles = "administrador")]
        [HttpGet("users")]
        public IActionResult GetUsers()
        {
            var users = _userManager.Users.ToList();
            return Ok(users.Select(u => new
            {
                u.Id,
                u.UserName,
                u.Email
            }));
        }



        [Authorize(Roles = "administrador")]
        [HttpPut("edit-user/{id}")]
        public async Task<IActionResult> EditUser(string id, [FromBody] EditUserModel model)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
                return NotFound("Usuario no encontrado.");

            user.UserName = model.Username;
            user.Email = model.Email;

            var result = await _userManager.UpdateAsync(user);
            if (!result.Succeeded)
                return BadRequest(result.Errors);

            return Ok("Usuario actualizado con éxito.");
        }



        [Authorize(Roles = "administrador")]
        [HttpDelete("delete-user/{id}")]
        public async Task<IActionResult> DeleteUser(string id)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
                return NotFound("Usuario no encontrado.");

            var result = await _userManager.DeleteAsync(user);

            if (!result.Succeeded)
                return BadRequest(result.Errors);

            // Registrar auditoría
            await _auditService.LogAsync(user.Id, user.UserName, "DELETE", "User", $"Usuario {user.UserName} eliminado.");

            return Ok("Usuario eliminado con éxito.");
        }



        [AllowAnonymous]
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            var user = await _userManager.FindByNameAsync(model.Username);
            if (user == null || !await _userManager.CheckPasswordAsync(user, model.Password))
                return Unauthorized("Credenciales inválidas.");

            // Generar token JWT
            var authClaims = new List<Claim>
    {
        new Claim(ClaimTypes.Name, user.UserName),
        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
    };

            var userRoles = await _userManager.GetRolesAsync(user);
            authClaims.AddRange(userRoles.Select(role => new Claim(ClaimTypes.Role, role)));

            var token = GenerateToken(authClaims);
            return Ok(new
            {
                token = new JwtSecurityTokenHandler().WriteToken(token),
                expiration = token.ValidTo
            });
        }



        [Authorize(Roles = "administrador")]
        [HttpPost("create-role")]
        public async Task<IActionResult> CreateRole([FromBody] string roleName)
        {
            if (await _roleManager.RoleExistsAsync(roleName))
                return BadRequest($"El rol '{roleName}' ya existe.");

            var result = await _roleManager.CreateAsync(new IdentityRole(roleName));

            if (!result.Succeeded)
                return BadRequest(result.Errors);

            return Ok($"Rol '{roleName}' creado exitosamente.");
        }



        [Authorize]
        [HttpGet("get-roles/{username}")]
        public async Task<IActionResult> GetRoles(string username)
        {
            var user = await _userManager.FindByNameAsync(username);
            if (user == null)
                return NotFound($"El usuario '{username}' no existe.");

            var roles = await _userManager.GetRolesAsync(user);
            return Ok(roles);
        }



        [Authorize(Roles = "administrador")]
        [HttpPost("assign-role")]
        public async Task<IActionResult> AssignRole([FromBody] RoleAssignmentModel model)
        {
            var user = await _userManager.FindByNameAsync(model.Username);
            if (user == null)
                return NotFound($"El usuario '{model.Username}' no existe.");

            if (!await _roleManager.RoleExistsAsync(model.Role))
                return BadRequest($"El rol '{model.Role}' no existe.");

            var result = await _userManager.AddToRoleAsync(user, model.Role);

            if (!result.Succeeded)
                return BadRequest(result.Errors);

            // Registrar auditoría
            await _auditService.LogAsync(user.Id, model.Username, "ASSIGN_ROLE", "User", $"Rol '{model.Role}' asignado al usuario '{model.Username}'.");

            return Ok($"Rol '{model.Role}' asignado al usuario '{model.Username}'.");
        }



        [Authorize]
        [HttpGet("my-roles")]
        public async Task<IActionResult> GetMyRoles()
        {
            var username = User.Identity?.Name; // Extraer el nombre del usuario desde el token
            if (string.IsNullOrEmpty(username))
                return NotFound("El token no contiene un nombre de usuario.");

            var user = await _userManager.FindByNameAsync(username);
            if (user == null)
                return NotFound("Usuario no encontrado.");

            var roles = await _userManager.GetRolesAsync(user);
            return Ok(roles);
        }



        [Authorize(Roles = "administrador")]
        [HttpGet("audit-logs")]
        public IActionResult GetAuditLogs()
        {
            var logs = _context.AuditLogs
                .OrderByDescending(a => a.Timestamp)
                .ToList();

            return Ok(logs);
        }








        private JwtSecurityToken GenerateToken(List<Claim> authClaims)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
            return new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                expires: DateTime.Now.AddHours(3),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
            );
        }






        public class RoleAssignmentModel
        {
            public string Username { get; set; }
            public string Role { get; set; }
        }

        public class EditUserModel
        {
            public string Username { get; set; }
            public string Email { get; set; }
        }
    }

    public class RegisterModel
    {
        public string Username { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
        public string Role { get; set; }
    }

    public class LoginModel
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }
}
