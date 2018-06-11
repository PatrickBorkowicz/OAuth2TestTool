﻿using System;
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
		/// <summary>
		/// 
		/// </summary>
		/// <param name="code">Authorization code will be provided by the IDP when redirecting back to this page following the authorization request.</param>
		/// <returns></returns>
		public IActionResult Index(string code, string state)
		{
			// Prepopulate form data from cookie. Cookies have NOTHING to do with the authentication process, they are just used here to maintain the state
			// of the form when bouncing back and forth from the auth provider.
			var model = new AuthorizationViewModel
			{
				AuthorizationEndpoint = Request.Cookies["AuthorizationEndpoint"],
				RefreshTokenEndpoint = Request.Cookies["RefreshTokenEndpoint"],
				AuthorizationCode = Request.Cookies["AuthorizationCode"] ?? code,
				TokenEndpoint = Request.Cookies["TokenEndpoint"],
				RedirectURI = "https://" + Request.Host.Value + "/",
				ClientId = Request.Cookies["ClientId"],
				ClientSecret = Request.Cookies["ClientSecret"],
				Scope = Request.Cookies["Scope"],
				State = Request.Cookies["State"] ?? Guid.NewGuid().ToString("N")
			};

			// State, generate a random state variable. The idea is that you pass the state along with the request, then the auth server returns
			// it in the response, you must verify that it has not changed, i.e. no-one has intercepted the request and transformed it. 
			//string state = Guid.NewGuid().ToString("N");

			// If this request is coming back from the auth provder on the authorization request (i.e. due to the redirect_uri being THIS page, 
			// the auth code will be a query parameter in the request url. Let's send it to the view.
			if (code != null)
			{
				ViewData["code"] = code;

				// Request came from OAuth provider.
				if (state == null || state != Request.Cookies["State"])
				{
					throw new Exception("State sent to OAuth provider did not match response state.");
				}

				Response.Cookies.Append("Focus", "user-tokens");
				model.Focus = "user-tokens";

			}

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
			Response.Cookies.Append("RedirectURI", model.RedirectURI);
			Response.Cookies.Append("ClientId", model.ClientId);
			Response.Cookies.Append("Scope", model.Scope);
			Response.Cookies.Append("State", model.State);
			Response.Cookies.Append("Focus", "auth-code");
			Response.Cookies.Delete("AuthorizationCode");

			// RELEVANT CODE

			// First redirect to the authorization endpoint. A user must be logged into Brightspace for this to work, or will be redirected to
			// Brightspace login for one time sign in. This should be done by a service level Brightspace account.

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
		public IActionResult GetTokens(AuthorizationViewModel model)
		{
			// Dump view model to cookie.
			Response.Cookies.Append("TokenEndpoint", model.TokenEndpoint);
			Response.Cookies.Append("AuthorizationCode", model.AuthorizationCode);
			Response.Cookies.Append("ClientId", model.ClientId);
			Response.Cookies.Append("ClientSecret", model.ClientSecret);
			Response.Cookies.Append("Focus", "user-tokens");
			Response.Cookies.Delete("AccessToken");
			Response.Cookies.Delete("RefreshToken");

			model.Focus = "user-tokens";

			// RELEVANT CODE

			var client = new RestClient(model.TokenEndpoint.Trim());

			// Prepare POST request to the token endpoint.
			var tokenRequest = new RestRequest(model.TokenEndpoint.Trim(), Method.POST);

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
			tokenRequest.AddParameter("code", model.AuthorizationCode.Trim());

			IRestResponse response = client.Execute(tokenRequest);


			if (response.IsSuccessful)
			{
				// Deserialize JSON response.
				var tokenResponse = JsonConvert.DeserializeObject<TokenResponseModel>(response.Content);


				model.AuthorizationCode = "(Used) " + model.AuthorizationCode; // Auth code is now invalid.
				model.RawResponse = response.Content;
				model.AccessToken = tokenResponse.AccessToken;
				model.RefreshToken = tokenResponse.RefreshToken;
				model.Focus = "refresh-token";

				Response.Cookies.Append("AuthorizationCode", model.AuthorizationCode);
				Response.Cookies.Append("AccessToken", model.AccessToken);
				Response.Cookies.Append("RefreshToken", model.RefreshToken);
				Response.Cookies.Append("Focus", model.Focus);

				return RedirectToAction("Index");
			}
			else
			{
				return RedirectToAction("Index");
			}
			
			//return PartialView("_Tokens", model);
		}

		[HttpPost]
		public IActionResult RefreshTokens(AuthorizationViewModel model)
		{
			// Dump view model to cookie.
			Response.Cookies.Append("RefreshTokenEndpoint", model.RefreshTokenEndpoint);
			Response.Cookies.Append("ClientId", model.ClientId);
			Response.Cookies.Append("ClientSecret", model.ClientSecret);
			Response.Cookies.Append("Scope", model.Scope);

			// RELEVANT CODE

			var client = new RestClient(model.RefreshTokenEndpoint.Trim());

			// Prepare POST request to the token endpoint.
			var tokenRequest = new RestRequest(model.RefreshTokenEndpoint.Trim(), Method.POST);

			// Send as form.
			tokenRequest.AddHeader("content-type", "application/x-www-form-urlencoded");
			client.Authenticator = new HttpBasicAuthenticator(model.ClientId, model.ClientSecret);

			// Since this is a POST request, RestSharp will add these to the payload (request body).	
			tokenRequest.AddParameter("grant_type", "refresh_token"); // grant type is now refresh token!
			tokenRequest.AddParameter("refresh_token", model.RefreshToken.Trim());

			IRestResponse response = client.Execute(tokenRequest);

			// Deserialize JSON response.
			var tokenResponse = JsonConvert.DeserializeObject<TokenResponseModel>(response.Content);

			model.RawResponse = response.Content;
			model.AccessToken = tokenResponse.AccessToken;
			model.RefreshToken = tokenResponse.RefreshToken;

			return PartialView("_Tokens", model);

			//return Json(new { });
		}

		public IActionResult ClearCookies()
		{
			foreach (var cookie in Request.Cookies.Keys)
				Response.Cookies.Delete(cookie);

			return View("Index");
		}

		public IActionResult Error()
		{
			return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
		}
	}
}
