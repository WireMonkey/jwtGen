using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;
using System.Web.Http.Description;
using JwtGenerator.Authorization;

namespace JwtGenerator.Controllers
{
    [RoutePrefix("api/Authorize")]
    public class AuthorizeController : ApiController
    {
        /// <summary>
        /// Generates a jwt token
        /// </summary>
        /// <param name="clientKey"></param>
        /// <returns></returns>
        [ApiExplorerSettings(IgnoreApi = true)]
        [HttpPost]
        public HttpResponseMessage GetToken([FromBody]string clientKey)
        {
            try
            {
                if (clientKey != ConfigurationManager.AppSettings["clientKey"])
                {
                    throw new Exception("Key does not match");
                }

                var claims = new Dictionary<string, string>
                {
                    {"clientKey", clientKey},
                    {"exp", DateTimeOffset.Now.AddMinutes(5).ToUnixTimeSeconds().ToString()}
                };
                return Request.CreateResponse(HttpStatusCode.Accepted,
                    JwtUtilities.GenerateToken(claims, ConfigurationManager.AppSettings["Jwtsecret"]));
            }
            catch (Exception e)
            {
                return Request.CreateErrorResponse(HttpStatusCode.InternalServerError, e);
            }
        }

        /// <summary>
        /// Refresh jwt token
        /// </summary>
        /// <returns></returns>
        [ApiExplorerSettings(IgnoreApi = true)]
        [Route("Refresh")]
        [HttpGet]
        [JwtAuthorization]
        public HttpResponseMessage RefreshToken()
        {
            try
            {
                var token = JwtUtilities.FetchFromHeader(ActionContext);
                return Request.CreateResponse(HttpStatusCode.Accepted,
                    JwtUtilities.RefreshToken(token, ConfigurationManager.AppSettings["Jwtsecret"]));
            }
            catch (Exception e)
            {
                return Request.CreateErrorResponse(HttpStatusCode.InternalServerError, e);
            }
        }

        /// <summary>
        /// Test to see if the jwt is valid and for how long
        /// </summary>
        /// <returns></returns>
        [Route("Test")]
        [HttpGet]
        [JwtAuthorization]
        public HttpResponseMessage TestToken()
        {
            try
            {
                var exp = JwtUtilities.GetExpireTime(Request);
                var x = new
                {
                    status = true,
                    validFor = (exp - DateTime.UtcNow).TotalSeconds
                };

                return Request.CreateResponse(HttpStatusCode.OK, x);

            }
            catch (Exception e)
            {
                return Request.CreateErrorResponse(HttpStatusCode.InternalServerError, e);
            }
        }
    }
}
