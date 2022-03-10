using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Identity.Client;

namespace Equinor.GetAccessTokenFromCertificate
{
    public static class TransformCertificateToJwtToken
    {
        [FunctionName("TransformCertificateToJwtToken")]
        public static async Task<IActionResult> RunAsync([HttpTrigger(AuthorizationLevel.Function, "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            log.LogInformation("C# HTTP trigger function processed a request");

            var requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            var data = Payload.FromJson(requestBody);
            if (data == null) return new BadRequestObjectResult("Body missing or not able to read");
            if (string.IsNullOrEmpty(data.CertificateString)) return new BadRequestObjectResult("`certificate` missing or not able to read");
            if (string.IsNullOrEmpty(data.Scope)) return new BadRequestObjectResult("`scope` missing or not able to read");
            if (string.IsNullOrEmpty(data.ClientId)) return new BadRequestObjectResult("`client` missing or not able to read");
            if (string.IsNullOrEmpty(data.TenantId)) return new BadRequestObjectResult("`tenantId` missing or not able to read");

            var x509Cert = data.GetCertificate();
            var confidentialClientApp = ConfidentialClientApplicationBuilder.
                Create(data.ClientId).
                WithTenantId(data.TenantId).
                WithCertificate(x509Cert).
                Build();

            //request a token for scope for client
            var scope = $"{data.Scope}/.default";
            var token = await confidentialClientApp
                .AcquireTokenForClient(new[] { scope })
                .WithSendX5C(true)
                .ExecuteAsync();

            return new JsonResult(new {token.AccessToken});
        }
    }
    public class Payload
    {
        [JsonPropertyName("certificate")]
        public string CertificateString { get; set; }
        [JsonPropertyName("clientId")]
        public string ClientId { get; set; }
        [JsonPropertyName("scope")]
        public string Scope { get; set; }
        [JsonPropertyName("tenant")]
        public string TenantId { get; set; }

        public static Payload FromJson(string json)
            => JsonSerializer.Deserialize<Payload>(json);

        public X509Certificate2 GetCertificate()
            => new X509Certificate2(Convert.FromBase64String(CertificateString));
    }
}
