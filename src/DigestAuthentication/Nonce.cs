using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace DigestAuthentication
{
    public class Nonce
    {
        private static ConcurrentDictionary<string, Tuple<int, DateTime>>
        nonces = new ConcurrentDictionary<string, Tuple<int, DateTime>>();

        public static string Generate()
        {
            byte[] bytes = new byte[16];
            RandomNumberGenerator rng = RandomNumberGenerator.Create();
            rng.GetBytes(bytes);

            string nonce = bytes.ToMD5Hash();

            nonces.TryAdd(nonce, new Tuple<int, DateTime>
                        (0, DateTime.Now.AddMinutes(10)));

            return nonce;
        }

        public static bool IsValid(string nonce, string nonceCount)
        {
            Tuple<int, DateTime> cachedNonce = null;
            nonces.TryGetValue(nonce, out cachedNonce);

            if (cachedNonce != null) // nonce is found
            {
                // nonce count is greater than the one in record
                if (Int32.Parse(nonceCount) > cachedNonce.Item1)
                {
                    // nonce has not expired yet
                    if (cachedNonce.Item2 > DateTime.Now)
                    {
                        // update the dictionary to reflect the nonce
                        // count just received in this request
                        nonces[nonce] = new Tuple<int, DateTime>
                          (cachedNonce.Item1 + 1, cachedNonce.Item2);

                        // every thing seems to be fine
                        // server nonce is fresh and nonce count seems
                        // to be incremented. Does not look like replay.
                        return true;
                    }
                }
            }

            return false;
        }
    }

    public static class HashExtension
    {
        public static string ToMD5Hash(this byte[] bytes)
        {
            StringBuilder hash = new StringBuilder();
            MD5 md5 = MD5.Create();

            md5.ComputeHash(bytes)
                  .ToList()
                  .ForEach(b => hash.AppendFormat("{0:x2}", b));

            return hash.ToString();
        }

        public static string ToMD5Hash(this string inputString)
        {
            return Encoding.UTF8.GetBytes(inputString).ToMD5Hash();
        }
    }

    public class Header
    {
        public Header() { }

        public Header(string header, string method)
        {
            string keyValuePairs = header.Replace("\"", String.Empty);

            foreach (string keyValuePair in keyValuePairs.Split(','))
            {
                int index = keyValuePair.IndexOf("=");
                string key = keyValuePair.Substring(0, index);
                string value = keyValuePair.Substring(index + 1);

                switch (key)
                {
                    case "username": this.UserName = value; break;
                    case "realm": this.Realm = value; break;
                    case "nonce": this.Nonce = value; break;
                    case "uri": this.Uri = value; break;
                    case "nc": this.NounceCounter = value; break;
                    case "cnonce": this.Cnonce = value; break;
                    case "response": this.Response = value; break;
                    case "method": this.Method = value; break;
                }
            }

            if (String.IsNullOrEmpty(this.Method))
                this.Method = method;
        }

        public string Cnonce { get; private set; }
        public string Nonce { get; private set; }
        public string Realm { get; private set; }
        public string UserName { get; private set; }
        public string Uri { get; private set; }
        public string Response { get; private set; }
        public string Method { get; private set; }
        public string NounceCounter { get; private set; }

        // This property is used by the handler to generate a
        // nonce and get it ready to be packaged in the
        // WWW-Authenticate header, as part of 401 response
        //public static Header UnauthorizedResponseHeader
        //{
        //    get
        //    {
        //        return new Header()
        //        {
        //            Realm = "RealmOfBadri",
        //            Nonce = DigestAuthN.Nonce.Generate()
        //        };
        //    }
        //}

        public override string ToString()
        {
            StringBuilder header = new StringBuilder();
            header.AppendFormat("realm=\"{0}\"", Realm);
            header.AppendFormat(", nonce=\"{0}\"", Nonce);
            header.AppendFormat(", qop=\"{0}\"", "auth");
            return header.ToString();
        }
    }
}
