using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;

namespace VerifyEmailForgotResetPasswordApp.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly Context _context;
        public UserController(Context context)
        {
            _context = context;
        }
        [HttpPost("register")]
        public async Task<IActionResult> Register(UserRegisterRequest model)
        {
            if (_context.Users.Any(x => x.Email == model.Email))
            {
                return BadRequest("User already exist... EMAIL");
            }
            CreatePasswordHash(model.Password,
                out byte[] passwordHash,
                out byte[] passwordSalt);
            var user = new User
            {
                Email = model.Email,
                PasswordHash = passwordHash,
                PasswordSalt = passwordSalt,
                VerificationToken = CreateRandomToken()
            };
            _context.Users.Add(user);
            await _context.SaveChangesAsync();
            return Ok("User successfully registered...");
        }
        [HttpPost("login")]
        public async Task<IActionResult> Login(UserLoginRequest model)
        {
            if (_context.Users.Any(x => x.Email == model.Email))
            {
                var user = await _context.Users.FirstOrDefaultAsync(x => x.Email == model.Email);
                if (!VerifyPasswordHash(model.Password, user.PasswordHash, user.PasswordSalt))
                {
                    return BadRequest("Password wrong! ");
                }
                if (user?.VerifiedAt == null)
                {
                    return BadRequest("Not Verify");
                }

                return Ok($"Welcome Back, {user.Email}! :");
            }
            else
            {
                return BadRequest("User not found... EMAIL");
            }
        }
        [HttpPost("verify")]
        public async Task<IActionResult> Verify(string token)
        {
            var user = await _context.Users.FirstOrDefaultAsync(x => x.VerificationToken == token);
            if (user == null)
            {
                return BadRequest("Invalid");
            }
            user.VerifiedAt = DateTime.Now;
            await _context.SaveChangesAsync();

            return Ok("User verified");

        }
        [HttpPost("forgotpassword")]
        public async Task<IActionResult> ForgotPassword(string email)
        {
            var user = await _context.Users.FirstOrDefaultAsync(x => x.Email == email);
            if (user == null)
            {
                return BadRequest("User Not Found");
            }
            user.PasswordResetToken = CreateRandomToken();
            user.ResetTokenExpires= DateTime.Now.AddDays(1);
            await _context.SaveChangesAsync();

            return Ok("You may reset password now.");

        }
        [HttpPost("resetpassword")]
        public async Task<IActionResult> ResetPassword(ResetPasswordRequest model)
        {
            var user = await _context.Users.FirstOrDefaultAsync(x => x.PasswordResetToken == model.Token);
            if (user == null)
            {
                return BadRequest("User Not Found");
            }
            CreatePasswordHash(model.Password,
                out byte[] passwordHash,
                out byte[] passwordSalt);
            user.PasswordHash = passwordHash;
            user.PasswordSalt=passwordSalt;
            user.PasswordResetToken = null;
            await _context.SaveChangesAsync();

            return Ok("Your password successfully reset");

        }

        private bool VerifyPasswordHash(string password, byte[] hash, byte[] salt)
        {
            using (var hmac = new HMACSHA512(salt))
            {
                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return computedHash.SequenceEqual(hash);
            }
        }
        private void CreatePasswordHash(string password, out byte[] hash, out byte[] salt)
        {
            using (var hmac = new HMACSHA512())
            {
                salt = hmac.Key;
                hash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }
        private string CreateRandomToken()
        {
            return Convert.ToHexString(RandomNumberGenerator.GetBytes(64));
        }
    }
}
