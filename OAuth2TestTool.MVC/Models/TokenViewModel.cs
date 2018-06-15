using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace OAuth2TestTool.MVC.Models
{
    public class TokenViewModel
    {
		[Required(ErrorMessage = "Authorization Code is required.")]
		public string AuthorizationCode { get; set; }

		[Required(ErrorMessage = "Client ID is required.")]
		public string ClientId { get; set; }

		[Required(ErrorMessage = "Client Secret is required.")]
		public string ClientSecret { get; set; }

		[Required(ErrorMessage = "Redirect URI is required.")]
		public string RedirectURI { get; set; }

		[Required(ErrorMessage = "Token Endpoint is required.")]
		public string TokenEndpoint { get; set; }
	}
}
