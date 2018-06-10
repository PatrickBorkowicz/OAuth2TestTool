using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OAuth2TestTool.MVC.Models
{
    public class AuthorizationViewModel
    {
		public string AuthorizationEndpoint { get; set; }
		public string TokenEndpoint { get; set; }
		public string RefreshTokenEndpoint { get; set; }
		public string RedirectURI { get; set; }
		public string ClientId { get; set; }
		public string ClientSecret { get; set; }
		public string Scope { get; set; }
		public string State { get; set; }
		public string AuthorizationCode { get; set; }
		public string AccessToken { get; set; }
		public string RefreshToken { get; set; }
		public string RawResponse { get; set; }
	}
}
