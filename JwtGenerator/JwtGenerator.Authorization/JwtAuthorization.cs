using System;
using System.Configuration;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Web.Http.Controllers;
using System.Web.Http.Filters;
using Microsoft.IdentityModel.Tokens;

namespace JwtGenerator.Authorization
{
    public class JwtAuthorization : AuthorizationFilterAttribute
    {
        public override void OnAuthorization(HttpActionContext actionContext)
        {
            if (!ValidateToken(JwtUtilities.FetchFromHeader(actionContext)))
            {
                ShowAuthenticationError(actionContext);
            }

            base.OnAuthorization(actionContext);
        }

        private static bool ValidateToken(string jwt)
        {
            var handler = new JwtSecurityTokenHandler();
            var secret = ConfigurationManager.AppSettings["Jwtsecret"];
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
            var signingCredentials = new SigningCredentials(securityKey, "HS256");

            var validParms = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret)),
                ValidateLifetime = true,
                ValidateActor = false,
                ValidateIssuer = false,
                ValidateAudience = false
            };
            try
            {
                var x = handler.ValidateToken(jwt, validParms, out var token);
            }
            catch (Exception e)
            {
                return false;
            }

            return true;
        }

        private static void ShowAuthenticationError(HttpActionContext filterContext)
        {
            filterContext.Response =
                filterContext.Request.CreateResponse(HttpStatusCode.Unauthorized,
                    "Not authorized.");
        }

    }
}
