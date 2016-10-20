﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Authentication.Digest;

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
                    AutomaticAuthenticate = true
                });
                builder.Run(async (context) =>
                {
                    if (!context.User.Identity.IsAuthenticated)
                    {
                        await context.Authentication.ChallengeAsync(DigestAuthenticationDefaults.AuthenticationScheme);
                    }
                    await context.Response.WriteAsync("adad");
                });
            });
        }
    }
}