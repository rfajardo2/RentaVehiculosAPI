using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
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

        public AuthController(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }
        
        [Authorize(Roles = "administrador")]
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            var user = new IdentityUser { UserName = model.Username, Email = model.Email };
            var result = await _userManager.CreateAsync(user, model.Password);

            if (!result.Succeeded)
                return BadRequest(result.Errors);

            // Asignar rol
            if (!string.IsNullOrEmpty(model.Role))
            {
                if (!await _roleManager.RoleExistsAsync(model.Role))
                    await _roleManager.CreateAsync(new IdentityRole(model.Role));

                await _userManager.AddToRoleAsync(user, model.Role);
            }

            return Ok("Usuario registrado con éxito.");
        }

        [AllowAnonymous]
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            var user = await _userManager.FindByNameAsync(model.Username);
            if (user == null || !await _userManager.CheckPasswordAsync(user, model.Password))
                return Unauthorized();

            // Generar token JWT
            var authClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var userRoles = await _userManager.GetRolesAsync(user);
            authClaims.AddRange(userRoles.Select(role => new Claim(ClaimTypes.Role, role)));

            var token = GenerateToken(authClaims);
            return Ok(new { token = new JwtSecurityTokenHandler().WriteToken(token), expiration = token.ValidTo });
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




        public class RoleAssignmentModel
        {
            public string Username { get; set; }
            public string Role { get; set; }
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
