using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace OAuth2TestTool.MVC.Models
{
    public class RefreshTokenViewModel
    {
		[Required(ErrorMessage = "Client ID is required.")]
		public string ClientId { get; set; }

		[Required(ErrorMessage = "Client Secret is required.")]
		public string ClientSecret { get; set; }

		public string Scope { get; set; }

		[Required(ErrorMessage = "Refresh Token is required.")]
		public string RefreshToken { get; set; }

		[Required(ErrorMessage = "Refresh Token Endpoint is required.")]
		public string RefreshTokenEndpoint { get; set; }
	}
}
