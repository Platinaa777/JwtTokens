using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualBasic;
using StudentApi.Configuration;
using StudentApi.Data;
using StudentApi.DTOs;
using StudentApi.Models;

namespace StudentApi.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly IConfiguration _configuration;
    private readonly DataContext _context;
    private readonly TokenValidationParameters _parameters;

    public AuthController(
        UserManager<IdentityUser> userManager,
        IConfiguration configuration,
        DataContext context,
        TokenValidationParameters parameters)
    {
        _userManager = userManager;
        _configuration = configuration;
        _context = context;
        _parameters = parameters;
    }

    [HttpPost]
    [Route("Register")]
    public async Task<IActionResult> Register([FromBody] UserRegistrationRequestDto request)
    {
        // validate incoming request
        if (ModelState.IsValid)
        {
            // we need to check if the email already exist
            var user_exist = await _userManager.FindByEmailAsync(request.Email);

            if (user_exist != null)
            {
                // user already exist
                return BadRequest(new AuthResult()
                {
                    Result = false,
                });
            }

            var user = new IdentityUser()
            {
                Email = request.Email,
                UserName = request.Email,
            };

            var is_created = await _userManager.CreateAsync(user, request.Password);

            if (is_created.Succeeded)
            {
                // generate token
                var token = GenerateJwtToken(user);

                return Ok(token.Result);
            }

            return BadRequest(new AuthResult()
            {
                Result = false,
            });
        }

        return BadRequest();
    }

    [Route("Login")]
    [HttpPost]
    public async Task<IActionResult> Login([FromBody] UserLoginRequestDto request)
    {
        if (ModelState.IsValid)
        {
            // checking if the user exist
            var existing_user = await _userManager.FindByEmailAsync(request.Email);

            if (existing_user == null)
            {
                return BadRequest();
            }


            var isCorrect = await  _userManager.CheckPasswordAsync(existing_user, request.Password);

            if (!isCorrect)
                return BadRequest();

            var jwtToken = await GenerateJwtToken(existing_user);

            return Ok(jwtToken);
        }

        return BadRequest(new AuthResult()
        {
            Result = false,
        });
    }
    private async Task<AuthResult> GenerateJwtToken(IdentityUser user)
    {
        var jwtTokenHandler = new JwtSecurityTokenHandler();

        var key = Encoding.UTF8.GetBytes(_configuration.GetSection("JwtConfig:Secret").Value);
        
        // Token descriptor
        var tokenDescriptor = new SecurityTokenDescriptor()
        {
            Subject = new ClaimsIdentity(new []
            {
                new Claim("Id", user.Id),
                new Claim(JwtRegisteredClaimNames.Sub, user.Email),
                new Claim(JwtRegisteredClaimNames.Email, value:user.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Iat, DateTime.Now.ToUniversalTime().ToString())
            }),
            
            Expires = DateTime.UtcNow.Add(TimeSpan.Parse(_configuration.GetSection("JwtConfig:ExpiryTime").Value)),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature), 
        };

        var token = jwtTokenHandler.CreateToken(tokenDescriptor);
        var jwtToken = jwtTokenHandler.WriteToken(token);

        var refreshToken = new RefreshToken()
        {
            JwtId = token.Id,
            Token = RandomString(22),
            ExpiryDate = DateTime.UtcNow.AddMonths(6),
            AddedDate = DateTime.UtcNow,
            IsRevoked = false,
            IsUsed = false,
            UserId = user.Id,
        };

        await _context.RefreshTokens.AddAsync(refreshToken);
        await _context.SaveChangesAsync();
        
        var result = new AuthResult()
        {
            Token = jwtToken,
            RefreshToken = refreshToken.Token,
            Result = true,
        };
        
        return result;
    }

    [HttpPost]
    [Route("RefreshToken")]
    public async Task<IActionResult> RefreshToken([FromBody] TokenRequestDto request)
    {
        if (ModelState.IsValid)
        {
            var result = VerifyAndGenerateToken(request);

            if (result == null)
                return BadRequest();

            return Ok(result);
        }

        return BadRequest();
    }

    private async Task<AuthResult> VerifyAndGenerateToken(TokenRequestDto request)
    {
        var jwtTokenHandler = new JwtSecurityTokenHandler();

        try
        {
            _parameters.ValidateLifetime = false;

            var tokenVarification = 
                jwtTokenHandler.ValidateToken(request.Token, _parameters, out var validatedToken);

            if (validatedToken is JwtSecurityToken jwtSecurityToken)
            {
                var result = 
                    jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256Signature,
                    StringComparison.CurrentCultureIgnoreCase);

                if (!result)
                {
                    return null;
                }

                var utcExpiryDate = long.Parse(tokenVarification.Claims.FirstOrDefault(x =>
                    x.Type == JwtRegisteredClaimNames.Exp).Value);

                var expiryDate = UnixTimeStampToDateTime(utcExpiryDate);

                if (expiryDate > DateTime.Now)
                {
                    // expired token
                    return new AuthResult()
                    {
                        Result = false,
                    };
                }

                var storedToken = await _context.RefreshTokens.FirstOrDefaultAsync(x => x.Token == request.RefreshToken);

                if (storedToken == null)
                {
                    return new AuthResult()
                    {
                        Result = false,
                    };
                }
                
                if (storedToken.IsUsed)
                    return new AuthResult()
                    {
                        Result = false,
                    };
                
                if (storedToken.IsRevoked)
                    return new AuthResult()
                    {
                        Result = false,
                    };

                var jti = tokenVarification.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Jti).Value;

                if (storedToken.JwtId != jti)
                {
                    return new AuthResult()
                    {
                        Result = false,
                    };
                }

                if (storedToken.ExpiryDate < DateTime.UtcNow)
                {
                    return new AuthResult()
                    {
                        Result = false,
                    };
                }
                
                
                // generate new token
                storedToken.IsUsed = true;
                _context.RefreshTokens.Update(storedToken);
                await _context.SaveChangesAsync();

                var dbUser = await _userManager.FindByIdAsync(storedToken.UserId);

                return await GenerateJwtToken(dbUser);
            }
        }
        catch (Exception e)
        {
            return new AuthResult()
            {
                Result = false,
            };
        }
        return new AuthResult()
        {
            Result = false,
        };
    }

    private DateTime UnixTimeStampToDateTime(long ticks)
    {
        var dateTimeVal = 
            new DateTime(1970, 1, 1, 0, 0 ,0, 0,
                DateTimeKind.Utc);
        dateTimeVal = dateTimeVal.AddSeconds(ticks).ToUniversalTime();

        return dateTimeVal;
    }
    
    private string RandomString(int len)
    {
        var random = new Random();
        var chars = "ABCDEEFRGTHNGFN1234567890";

        return new string(Enumerable.Repeat(chars, len).Select(s => s[random.Next(s.Length)]).ToArray());
    }
}