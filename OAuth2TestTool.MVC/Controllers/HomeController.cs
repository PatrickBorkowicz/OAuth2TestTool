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
	public class HomeController : Controller
	{
		#region Actions

		/// <summary>
		/// Loads the inital view and is also the callback when performing the authentication request.
		/// </summary>
		/// <param name="code">Authorization code will be provided by the IDP when redirecting back to this page following the authorization request.</param>
		/// <param name="state">Returned state string from the IDP for verification.</param>
		/// <param name="reset">Boolean to determine whether to clear cookies.</param>
		/// <param name="clear">Boolean to determine whether to clear token values from cookies.</param>
		/// <returns></returns>
		public IActionResult Index(string code, string state, bool reset, bool clear)
		{
			// Clear cookies.
			if (reset)
			{
				foreach (var cookie in Request.Cookies.Keys)
					Response.Cookies.Delete(cookie);

				return View(GetViewModel(true));
			}

			var model = GetViewModel();

			// Clear codes / tokens.
			if (clear)
			{
				model.AuthorizationCode = null;
				model.AccessToken = null;
				model.RefreshToken = null;
				model.Focus = null;
				model.RawResponse = null;
				model.State = Guid.NewGuid().ToString("N");

				SetViewModel(model);

				return View(model);
			}

			// Authorization response.
			// If this request is coming back from the auth provider on the authorization request (i.e. due to the redirect_uri being THIS page, 
			// the auth code will be a query parameter in the request url.
			if (!String.IsNullOrWhiteSpace(code))
			{
				// Check state.
				// State is a randomly generated string (whatever you like).The idea is that you pass the state along with the request, then the auth server returns
				// it in the response, you must verify that it has not changed, i.e. no-one has intercepted the request and transformed it.
				if (state == null || state.Trim() != Request.Cookies["State"])
				{
					model.ErrorMessage = "State sent to OAuth provider did not match response state.";
				}
				else
				{
					model.AuthorizationCode = code;
					model.Focus = "user-tokens";
				}

				SetViewModel(model);
			}

			return View(model);
		}

		/// <summary>
		/// Refirect to auth server to authenticate user and return with auth code.
		/// </summary>
		/// <returns></returns>
		[HttpPost]
		public IActionResult GetAuthorizationCode(AuthorizationViewModel viewModel)
		{
			var model = GetViewModel();

			model.AuthorizationEndpoint = viewModel.AuthorizationEndpoint?.Trim();
			model.ClientId = viewModel.ClientId?.Trim();
			model.Scope = viewModel.Scope?.Trim();
			model.State = viewModel.State?.Trim();

			if (!ModelState.IsValid)
				return View("Index", model);

			model.RawResponse = null;
			model.AuthorizationCode = null;
			model.Focus = "auth-code";

			SetViewModel(model);

			// Redirect to the authorization endpoint. A user must be logged into the IDP for this to work or they will be redirected to
			// to the IDP login page for one time sign in. For headless applications, it makes sense for this to be a service account.

			// Build authorization code request.
			string authCodeRequestUri = model.AuthorizationEndpoint
				+ "?response_type=code"
				+ "&redirect_uri=" + model.RedirectURI.Trim()
				+ "&client_id=" + model.ClientId.Trim()
				+ "&scope=" + model.Scope.Trim()
				+ "&state=" + model.State.Trim();

			return Redirect(authCodeRequestUri);
		}

		/// <summary>
		/// Trade authorization code for access token and refresh token.
		/// </summary>
		/// <param name="code"></param>
		/// <returns></returns>
		[HttpPost]
		public IActionResult GetTokens(TokenViewModel viewModel)
		{
			var model = GetViewModel();		

			model.TokenEndpoint = viewModel.TokenEndpoint?.Trim();
			model.AuthorizationCode = viewModel.AuthorizationCode?.Trim();
			model.ClientId = viewModel.ClientId?.Trim();
			model.ClientSecret = viewModel.ClientSecret?.Trim();

			if (!ModelState.IsValid)
				return View("Index", model);

			model.Focus = "user-tokens";
			model.AccessToken = null;
			model.RefreshToken = null;

			var client = new RestClient(model.TokenEndpoint);

			// Prepare POST request to the token endpoint.
			var tokenRequest = new RestRequest(model.TokenEndpoint, Method.POST);

			// Send as form.
			tokenRequest.AddHeader("content-type", "application/x-www-form-urlencoded");

			// Add credentials to the header.
			// This will have the effect of creating this header:
			// Authorization: Basic hsjksjkhfhfsjk324yfdsuiyruiwryew=
			// the client id and secret will be appear as myclientid:myclientsecret and endcoded in base64 (note the colon seperating the two before encoding).
			client.Authenticator = new HttpBasicAuthenticator(model.ClientId, model.ClientSecret);

			// Supposedly you can place the client id and secret in the request url as query parameters instead of the Authorization header, but this does not always work.
			//tokenRequest.AddParameter("client_id", model.ClientId);
			//tokenRequest.AddParameter("client_secret", model.ClientSecret);	

			// Since this is a POST request, RestSharp will add these to the payload (request body).	
			tokenRequest.AddParameter("grant_type", "authorization_code");
			tokenRequest.AddParameter("redirect_uri", model.RedirectURI);
			tokenRequest.AddParameter("code", model.AuthorizationCode);

			IRestResponse response = client.Execute(tokenRequest);

			model.RawResponse = response.Content;

			if (response.IsSuccessful)
			{
				// Deserialize JSON response.
				var tokenResponse = JsonConvert.DeserializeObject<TokenResponseModel>(response.Content);

				model.AuthorizationCode = "(Used) " + model.AuthorizationCode; // Auth code is now invalid.		
				model.AccessToken = tokenResponse.AccessToken;
				model.RefreshToken = tokenResponse.RefreshToken;
				model.Focus = "refresh-token";

				SetViewModel(model);

				return RedirectToAction("Index");
			}
			else
			{
				// There was an error.
				SetViewModel(model);
		
				model.ErrorMessage = response.Content;
				return View("Index", model);
			}	
		}

		[HttpPost]
		public IActionResult RefreshTokens(RefreshTokenViewModel viewModel)
		{
			var model = GetViewModel();

			model.RefreshTokenEndpoint = viewModel.RefreshTokenEndpoint?.Trim();
			model.RefreshToken = viewModel.RefreshToken?.Trim();
			model.ClientId = viewModel.ClientId?.Trim();
			model.ClientSecret = viewModel.ClientSecret?.Trim();
			model.Scope = viewModel.Scope?.Trim();

			if (!ModelState.IsValid)
				return View("Index", model);

			model.AccessToken = null;

			var client = new RestClient(model.RefreshTokenEndpoint);

			// Prepare POST request to the token endpoint.
			var tokenRequest = new RestRequest(model.RefreshTokenEndpoint, Method.POST);

			// Send as form.
			tokenRequest.AddHeader("content-type", "application/x-www-form-urlencoded");
			client.Authenticator = new HttpBasicAuthenticator(model.ClientId, model.ClientSecret);

			// Since this is a POST request, RestSharp will add these to the payload (request body).	
			tokenRequest.AddParameter("grant_type", "refresh_token"); // grant type is now refresh token!
			tokenRequest.AddParameter("refresh_token", model.RefreshToken);
			tokenRequest.AddParameter("scope", model.Scope);

			IRestResponse response = client.Execute(tokenRequest);

			model.RawResponse = response.Content;

			if (response.IsSuccessful)
			{
				// Deserialize JSON response.
				var tokenResponse = JsonConvert.DeserializeObject<TokenResponseModel>(response.Content);

				model.AccessToken = tokenResponse.AccessToken;
				model.RefreshToken = tokenResponse.RefreshToken;
				model.Focus = "refresh-token";

				SetViewModel(model);

				return RedirectToAction("Index");
			}
			else
			{
				// There was an error.
				model.RefreshToken = "(Invalid) " + model.RefreshToken;			
				SetViewModel(model);

				model.ErrorMessage = response.Content;
				return View("Index", model);
			}	
		}

		public IActionResult Error()
		{
			return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
		}
		#endregion

		#region Helpers
		/// <summary>
		/// Create the view model from cookie data. Note that cookies have NOTHING to do with the authentication process, they are just used here to maintain form state.
		/// </summary>
		/// <returns></returns>
		private OAuth2ViewModel GetViewModel(bool clean = false)
		{
			if (clean)
			{
				return new OAuth2ViewModel
				{
					RedirectURI = "https://" + Request.Host.Value + "/",
					State = Guid.NewGuid().ToString("N")
				};
			}
			else
			{
				return new OAuth2ViewModel
				{
					AccessToken = Request.Cookies["AccessToken"],
					AuthorizationCode = Request.Cookies["AuthorizationCode"],
					AuthorizationEndpoint = Request.Cookies["AuthorizationEndpoint"],
					ClientId = Request.Cookies["ClientId"],
					ClientSecret = Request.Cookies["ClientSecret"],
					Focus = Request.Cookies["Focus"],
					RawResponse = Request.Cookies["RawResponse"],
					RedirectURI = "https://" + Request.Host.Value + "/",
					RefreshToken = Request.Cookies["RefreshToken"],
					RefreshTokenEndpoint = Request.Cookies["RefreshTokenEndpoint"],
					Scope = Request.Cookies["Scope"],
					State = Request.Cookies["State"] ?? Guid.NewGuid().ToString("N"),
					TokenEndpoint = Request.Cookies["TokenEndpoint"]
				};
			}
		}

		/// <summary>
		/// Create a view model object from cookie data.
		/// </summary>
		/// <param name="model"></param>
		private void SetViewModel(OAuth2ViewModel model)
		{
			Response.Cookies.Append("AccessToken", model.AccessToken ?? "");
			Response.Cookies.Append("AuthorizationCode", model.AuthorizationCode ?? "");
			Response.Cookies.Append("AuthorizationEndpoint", model.AuthorizationEndpoint ?? "");
			Response.Cookies.Append("ClientId", model.ClientId ?? "");
			Response.Cookies.Append("ClientSecret", model.ClientSecret ?? "");
			Response.Cookies.Append("Focus", model.Focus ?? "");
			Response.Cookies.Append("RawResponse", model.RawResponse ?? "");
			Response.Cookies.Append("RedirectURI", "https://" + Request.Host.Value + "/");
			Response.Cookies.Append("RefreshToken", model.RefreshToken ?? "");
			Response.Cookies.Append("RefreshTokenEndpoint", model.RefreshTokenEndpoint ?? "");
			Response.Cookies.Append("Scope", model.Scope ?? "");
			Response.Cookies.Append("State", model.State ?? "");
			Response.Cookies.Append("TokenEndpoint", model.TokenEndpoint ?? "");
		}
		#endregion
	}
}
