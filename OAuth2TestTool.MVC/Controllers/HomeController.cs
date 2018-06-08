using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using OAuth2TestTool.MVC.Models;
using RestSharp;
using System.Web;
using RestSharp.Authenticators;
using Newtonsoft.Json;

namespace OAuth2TestTool.MVC.Controllers
{
	public class TokenResponse
	{
		[JsonProperty("access_token")]
		public string AccessToken { get; set; }

		[JsonProperty("refresh_token")]
		public string RefreshToken { get; set; }

		[JsonProperty("token_type")]
		public string TokenType { get; set; }

		[JsonProperty("expires_in")]
		public int? ExpiresIn { get; set; }
	}

	public class HomeController : Controller
	{
		private const string AuthBaseUri = "https://auth.brightspace.com";
		private const string AuthorizationEndpoint = "oauth2/auth"; //https://auth.brightspace.com/oauth2/auth
		private const string TokenEndpoint = "core/connect/token";  //https://auth.brightspace.com/core/connect/token
		private const string Scope = "core:*:*";

		// App Specific
		private const string RedirectUri = "https://localhost:44311/";
		private const string ClientID = "6c0638b1-65bf-4018-9a29-6c65d05acffc";
		private const string ClientSecret = "oRqAuGefHeULcd65bzZKKw2zLwSiEfOMny2CmnY2UAo";

		/// <summary>
		/// 
		/// </summary>
		/// <param name="code">Authorization code will be provided by the IDP when redirecting back to this page following the authorization request.</param>
		/// <returns></returns>
		public IActionResult Index(string code, string state)
		{
			// If this request is coming back from the auth provder on the authorization request (i.e. due to the redirect_uri being THIS page, 
			// the auth code will be a query parameter in the request url. Let's send it to the view.
			ViewData["code"] = code;

			if (state != null)
			{
				// Request came from OAuth provider.
				if (state != Request.Cookies["State"])
				{
					throw new Exception("State sent to OAuth provider did not match response state.");
				}
			}
			
			// Prepopulate form data from cookie. Cookies have NOTHING to do with the authentication process, they are just used here to maintain the state
			// of the form when bouncing back and forth from the auth provider.
			var model = new AuthorizationViewModel
			{
				AuthorizationEndpoint = Request.Cookies["AuthorizationEndpoint"],
				RedirectURI = "https://" + Request.Host.Value + "/",
				ClientId = Request.Cookies["ClientId"],
				Scope = Request.Cookies["Scope"],
				State = Request.Cookies["State"] ?? Guid.NewGuid().ToString("N")
			};

			// State, generate a random state variable. The idea is that you pass the state along with the request, then the auth server returns
			// it in the response, you must verify that it has not changed, i.e. no-one has intercepted the request and transformed it. 
			//string state = Guid.NewGuid().ToString("N");

			return View(model);
		}

		/// <summary>
		/// Refirect to auth server to authenticate user and return with auth code.
		/// </summary>
		/// <returns></returns>
		[HttpPost]
		public IActionResult GetAuthorizationCode(AuthorizationViewModel model)
		{
			// Dump view model to cookie.
			Response.Cookies.Append("AuthorizationEndpoint", model.AuthorizationEndpoint);
			Response.Cookies.Append("ClientId", model.ClientId);
			Response.Cookies.Append("Scope", model.Scope);
			Response.Cookies.Append("State", model.State);

			// RELEVANT CODE

			// First redirect to the authorization endpoint. A user must be logged into Brightspace for this to work, or will be redirected to
			// Brightspace login for one time sign in. This should be done by a service level Brightspace account.

			// Build authorization code request.
			string authCodeRequest = AuthBaseUri
				+ "/"
				+ AuthorizationEndpoint
				+ "?response_type=code"
				+ "&redirect_uri=" + model.RedirectURI.Trim()
				+ "&client_id=" + model.ClientId.Trim()
				+ "&scope=" + model.Scope.Trim()
				+ "&state=" + model.State.Trim();

			return Redirect(authCodeRequest);
		}

		/// <summary>
		/// Trade authorization code for access token and refresh token.
		/// </summary>
		/// <param name="code"></param>
		/// <returns></returns>
		[HttpGet]
		public JsonResult GetTokens(string code)
		{
			var client = new RestClient(AuthBaseUri);

			// Prepare POST request to the token endpoint.
			var tokenRequest = new RestRequest(TokenEndpoint, Method.POST);

			// Send as form.
			tokenRequest.AddHeader("content-type", "application/x-www-form-urlencoded");

			// Add credentials to the header.
			client.Authenticator = new HttpBasicAuthenticator(ClientID, ClientSecret);

			// Or alternatively:
			//tokenRequest.AddParameter("client_id", ClientID);
			//tokenRequest.AddParameter("client_secret", ClientSecret);	
			
			// Since this is a POST request, RestSharp will add these to the payload (request body).	
			tokenRequest.AddParameter("grant_type", "authorization_code");
			tokenRequest.AddParameter("redirect_uri", RedirectUri);
			tokenRequest.AddParameter("code", code);

			IRestResponse response = client.Execute(tokenRequest);

			// Deserialize JSON response.
			var tokenResponse = JsonConvert.DeserializeObject<TokenResponse>(response.Content);

			return Json(tokenResponse);
		}

		public IActionResult Error()
		{
			return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
		}
	}
}
