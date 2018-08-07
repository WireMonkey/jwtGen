using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Web.Http.Controllers;
using Microsoft.IdentityModel.Tokens;

namespace JwtGenerator.Authorization
{
    public class JwtUtilities
    {
        public static string FetchFromHeader(HttpActionContext actionContext)
        {
            string requestToken = null;

            var authRequest = actionContext.Request.Headers.Authorization;
            if (authRequest != null)
            {
                requestToken = authRequest.Parameter;
            }

            return requestToken;
        }

        public static string GetFromClaimToken(HttpRequestMessage request, string claim)
        {
            var handler = new JwtSecurityTokenHandler();
            var authRequest = request.Headers.Authorization.Parameter;

            var token = handler.ReadJwtToken(authRequest);
            return token.Claims.FirstOrDefault(x => x.Type == claim).Value;
        }

        public static string GenerateToken(Dictionary<string, string> payloadContents, string secretKey, string encryptionAlgorithm = "HS256")
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
            var signingCredentials = new SigningCredentials(securityKey, encryptionAlgorithm);

            var payloadClaims = payloadContents.Select(c => new Claim(c.Key, c.Value));

            var payload = new JwtPayload(payloadClaims);
            var header = new JwtHeader(signingCredentials);
            var securityToken = new JwtSecurityToken(header, payload);
            var handler = new JwtSecurityTokenHandler();
            return handler.WriteToken(securityToken);
        }

        public static string RefreshToken(string jwt, string secretKey, string encryptionAlgorithm = "HS256")
        {
            var handler = new JwtSecurityTokenHandler();
            var token = handler.ReadJwtToken(jwt);

            //Get all payload contents except for the exp date
            var claims = token.Claims.Where(x => x.Type != "exp").ToDictionary(x => x.Type, x => x.Value);

            //add new exp date
            claims.Add("exp", DateTimeOffset.Now.AddMinutes(5).ToUnixTimeSeconds().ToString());

            return GenerateToken(claims, secretKey, encryptionAlgorithm);
        }

        public static DateTime GetExpireTime(HttpRequestMessage request)
        {
            var handler = new JwtSecurityTokenHandler();
            var authRequest = request.Headers.Authorization.Parameter;

            var token = handler.ReadJwtToken(authRequest);

            return token.ValidTo;
        }
    }
}
