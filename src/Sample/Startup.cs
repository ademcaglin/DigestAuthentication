using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Authentication.Digest;
using System.Security.Claims;
using System.Text.Encodings.Web;

namespace Sample
{
    public class Startup
    {
        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit http://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddAuthentication();
            services.AddMemoryCache();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
            loggerFactory.AddConsole();

            app.Map("/protected", builder =>
            {
                builder.UseDigestAuthentication(new DigestAuthenticationOptions
                {
                    SecretKey = "abc670d15a584f4baf0ba48455d3b155",
                    AppId = "jDEf7bMcJVFnqrPd599aSIbhC0IasxLBpGAJeW3Fzh4=",
                    AutomaticAuthenticate = true,
                    UserService = new FakeService()
                });
                builder.Run(async (context) =>
                {
                    if (!context.User.Identity.IsAuthenticated)
                    {
                        await context.Authentication.ChallengeAsync(DigestAuthenticationDefaults.AuthenticationScheme);
                    }
                    else
                    {
                        await WriteHtmlAsync(context.Response, async response =>
                        {
                            await WriteTableHeader(response, new string[] { "Claim Type", "Value" }, context.User.Claims.Select(c => new string[] { c.Type, c.Value }));

                        });
                    }
                });
            });
        }
        private static async Task WriteHtmlAsync(HttpResponse response, Func<HttpResponse, Task> writeContent)
        {
            var bootstrap = "<link rel=\"stylesheet\" href=\"https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css\" integrity=\"sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u\" crossorigin=\"anonymous\">";

            response.ContentType = "text/html";
            await response.WriteAsync($"<html><head>{bootstrap}</head><body><div class=\"container\">");
            await writeContent(response);
            await response.WriteAsync("</div></body></html>");
        }
        private static async Task WriteTableHeader(HttpResponse response, IEnumerable<string> columns, IEnumerable<IEnumerable<string>> data)
        {
            await response.WriteAsync("<table class=\"table table-condensed\">");
            await response.WriteAsync("<tr>");
            foreach (var column in columns)
            {
                await response.WriteAsync($"<th>{HtmlEncode(column)}</th>");
            }
            await response.WriteAsync("</tr>");
            foreach (var row in data)
            {
                await response.WriteAsync("<tr>");
                foreach (var column in row)
                {
                    await response.WriteAsync($"<td>{HtmlEncode(column)}</td>");
                }
                await response.WriteAsync("</tr>");
            }
            await response.WriteAsync("</table>");
        }
        private static string HtmlEncode(string content) =>
            string.IsNullOrEmpty(content) ? string.Empty : HtmlEncoder.Default.Encode(content);
    }

    public class FakeService : IDigestUserService
    {
        public IEnumerable<Claim> GetClaims(string userName)
        {
            var list = new List<Claim>();
            list.Add(new Claim("test", "test"));
            return list;
        }

        public string GetPassword(string userName)
        {
            if(userName == "bob")
            {
                return "bob";
            }
            return null;
        }
    }
}
