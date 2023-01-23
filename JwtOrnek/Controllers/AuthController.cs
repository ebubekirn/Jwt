using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JwtOrnek.Controllers
{
	[Route("api/[controller]")]
	[ApiController]
	[Authorize] // Bunu sayesinde sadece authorize olan kullanıcılar bunu görebilir.
	public class AuthController : ControllerBase
	{
		string signingKey = "BuBenimSigningKeyim"; // Bu anahtar ile şifreleme çözülür.

		[HttpGet]
		public string Get(string userName, string password)
		{
			// claims => payload
			var claims = new[]
			{
				new Claim(ClaimTypes.Name, userName),
				new Claim(JwtRegisteredClaimNames.Email, userName)
			};

			var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signingKey)); 
			var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
			var jwtSecurityToken = new JwtSecurityToken(
				issuer: "https://www.abcd.com",
				audience: "BenimAudienceDegerim",
				claims: claims,
				expires: DateTime.Now.AddDays(15),
				notBefore: DateTime.Now,
				signingCredentials: credentials
			);

			var token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
			return token;
		}

		[HttpGet("ValidateToken")]
		public bool ValidateToken(string token)
		{
			var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signingKey));
			try
			{
				JwtSecurityTokenHandler handler = new();
				handler.ValidateToken(token, new TokenValidationParameters()
				{
					ValidateIssuerSigningKey= true,
					IssuerSigningKey = securityKey,
					ValidateLifetime = true,
					ValidateAudience = false,
					ValidateIssuer = false
				}, out SecurityToken validateToken);
				var jwtToken = (JwtSecurityToken)validateToken;

				return true;var claims = jwtToken.Claims.ToList();
			}
			catch (Exception)
			{
				return false;
			}
		}
	}
}
