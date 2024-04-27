using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Projet2.Models;
using System.Diagnostics.Eventing.Reader;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Projet2.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly UserDbContext _userDbContext;
        private readonly IConfiguration _configuration;

        public UserController(IConfiguration configuration, UserDbContext userDbContext)
        {
            _userDbContext = userDbContext;
            _configuration = configuration;

        }

        [HttpGet]
        [Route("get-users")]
        public async Task<ActionResult<IEnumerable<User>>> GetUser()
        {
            if (_userDbContext == null)
            {
                return NotFound();
            }
            return await _userDbContext.User.ToListAsync();
        }

        [HttpGet]
        [Route("get-user-by-id")]
        public async Task<IActionResult> GetUserByIdAsync(int UserId)
        {
            var user = await _userDbContext.User.FindAsync(UserId);
            if (user == null)
            {
                return NotFound("User not found");
            }
            return Ok(user);
        }

        /*[HttpPost]
        [Route("create-user")]
        public async Task<IActionResult> PostAsync(User user)
        {
            _userDbContext.User.Add(user);
            await _userDbContext.SaveChangesAsync();
            return Created($"/get-user-by-id/{user.userID}", user);
        }*/
        /*[HttpPut]
        [Route("update-user")]
        public async Task<IActionResult> PutAsync(User userToUpdate)
        {
            _userDbContext.User.Update(userToUpdate);
            await _userDbContext.SaveChangesAsync();
            return NoContent();
        }*/

        [HttpPut]
        [Route("update-user")]
        public async Task<IActionResult> PutAsync(User userToUpdate)
        {
            var existingUser = await _userDbContext.User.FindAsync(userToUpdate.userID);

            if (existingUser == null)
            {
                return NotFound();
            }

            if (!string.IsNullOrEmpty(userToUpdate.password))
            {
                
                var hashedPassword = BCrypt.Net.BCrypt.HashPassword(userToUpdate.password);

                existingUser.password = hashedPassword;
            }

            existingUser.name = userToUpdate.name;
            existingUser.email = userToUpdate.email;


            _userDbContext.User.Update(existingUser);
            await _userDbContext.SaveChangesAsync();

            return NoContent();
        }

        [HttpDelete]
        [Route("delete-user/{UserId}")]
        public async Task<IActionResult> DeleteAsync(int UserId)
        {
            var userToDelete = await _userDbContext.User.FindAsync(UserId);
            if (userToDelete == null)
            {
                return NotFound("User not found");
            }
            _userDbContext.User.Remove(userToDelete);
            await _userDbContext.SaveChangesAsync();
            return NoContent();
        }

        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> RegisterAsync(User newUser)
        {
            if (await _userDbContext.User.AnyAsync(u => u.email == newUser.email))
            {
                return BadRequest("Email already exists.");
            }

            newUser.password = BCrypt.Net.BCrypt.HashPassword(newUser.password);

            _userDbContext.User.Add(newUser);
            await _userDbContext.SaveChangesAsync();

            return Created($"/api/user/{newUser.userID}", newUser);

        }

        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> LoginAsync(LoginModel loginModel)
        {
            var user = await _userDbContext.User.FirstOrDefaultAsync(u => u.email == loginModel.email);

            if (user == null)
            {
                return Unauthorized("Email does not exist"); 
            }

            if (!BCrypt.Net.BCrypt.Verify(loginModel.password, user.password))
            {
                return Unauthorized("Incorrect password");
            }

            string token = CreateToken(user);

            return Ok(token);


  
        }


        private string CreateToken(User user)
        {
            List<Claim> claims = new List<Claim> {
                new Claim(ClaimTypes.Email, user.email),
              
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(
                _configuration.GetSection("AppSettings:Token").Value!));

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            var token = new JwtSecurityToken(
                    claims: claims,
                    expires: DateTime.Now.AddDays(1),
                    signingCredentials: creds
                );

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        }



    }
}
