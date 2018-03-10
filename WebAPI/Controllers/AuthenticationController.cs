using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Web.Http;

namespace WebAPI.Controllers
{
    public class AuthenticationController : ApiController
    {
        string oauth_callback = "http://obp.sckhoo.com/";
        // Use your own callback URL
        string oauth_consumer_key = "jwakcuuwkdqmnkrmxq1zbd45xqoum10ragw15f1d";
        // Use your own oauth_consumer_key
        string oauth_nonce = Guid.NewGuid().ToString();
        // Use your own oauth_nonce
        string oauth_signature = "HYz74tZeISQEG27FJYhC%2b89kEhM%3d";
        // Leave this blank for now
        string oauth_signature_method = "HMAC-SHA1";
        // "HMAC-SHA1" or "HMAC-SHA256"
        string oauth_timestamp = "1520690400";
        // Use your own oauth_timestamp
        string oauth_version = "1.0";
        // "1.0" or "1"
        string oauth_consumer_secret = "gr2dfs2at43kyosfntpc0w41baw3u20wufxm32ze";
        // Use your own oauth_consumer_secret
        string method = "POST";
        //use uri
        string uri = "https://bnpparibas-api.openbankproject.com/oauth/initiate";
        //oauth token 
        string oauth_token = "";
        //oauth token secret
        string oauth_token_secret = "";
        //
        int oauth_verifier = 0; 
        /// <summary>
        /// 
        /// </summary>
        [HttpGet]
        public void GetFirstToken()
        {
            // Create a list of OAuth parameters
            List<KeyValuePair<string, string>> oauthparameters = new List<KeyValuePair<string, string>>();
            oauthparameters.Add(new KeyValuePair<string, string>("oauth_callback", oauth_callback));
            oauthparameters.Add(new KeyValuePair<string, string>("oauth_consumer_key", oauth_consumer_key));
            oauthparameters.Add(new KeyValuePair<string, string>("oauth_nonce", oauth_nonce));
            oauthparameters.Add(new KeyValuePair<string, string>
                ("oauth_signature_method", oauth_signature_method));
            oauthparameters.Add(new KeyValuePair<string, string>("oauth_timestamp", oauth_timestamp));
            oauthparameters.Add(new KeyValuePair<string, string>("oauth_version", oauth_version));

            // Sort the OAuth parameters on the key
            oauthparameters.Sort((x, y) => x.Key.CompareTo(y.Key));

            // Construct the Base String
            string basestring = method.ToUpper() + "&" + HttpUtility.UrlEncode(uri) + "&";
            foreach (KeyValuePair<string, string> pair in oauthparameters)
            {
                basestring += pair.Key + "%3D" + HttpUtility.UrlEncode(pair.Value) + "%26";
            }
            basestring = basestring.Substring(0, basestring.Length - 3);
            //Gets rid of the last "%26" added by the foreach loop

            // Makes sure all the Url encoding gives capital letter hexadecimal 
            // i.e. "=" is encoded to "%3D", not "%3d"
            char[] basestringchararray = basestring.ToCharArray();
            for (int i = 0; i < basestringchararray.Length - 2; i++)
            {
                if (basestringchararray[i] == '%')
                {
                    basestringchararray[i + 1] = char.ToUpper(basestringchararray[i + 1]);
                    basestringchararray[i + 2] = char.ToUpper(basestringchararray[i + 2]);
                }
            }
            basestring = new string(basestringchararray);

            // Encrypt with either SHA1 or SHA256, creating the Signature
            var enc = Encoding.ASCII;
            if (oauth_signature_method == "HMAC-SHA1")
            {
                HMACSHA1 hmac = new HMACSHA1(enc.GetBytes(oauth_consumer_secret + "&"));
                hmac.Initialize();
                byte[] buffer = enc.GetBytes(basestring);
                string hmacsha1 = BitConverter.ToString(hmac.ComputeHash(buffer)).Replace("-", "").ToLower();
                byte[] resultantArray = new byte[hmacsha1.Length / 2];
                for (int i = 0; i < resultantArray.Length; i++)
                {
                    resultantArray[i] = Convert.ToByte(hmacsha1.Substring(i * 2, 2), 16);
                }
                string base64 = Convert.ToBase64String(resultantArray);
                oauth_signature = HttpUtility.UrlEncode(base64);
            }
            else if (oauth_signature_method == "HMAC-SHA256")
            {
                HMACSHA256 hmac = new HMACSHA256(enc.GetBytes(oauth_consumer_secret + "&"));
                hmac.Initialize();
                byte[] buffer = enc.GetBytes(basestring);
                string hmacsha256 = BitConverter.ToString(hmac.ComputeHash(buffer)).Replace("-", "")
                    .ToLower();
                byte[] resultantArray = new byte[hmacsha256.Length / 2];
                for (int i = 0; i < resultantArray.Length; i++)
                {
                    resultantArray[i] = Convert.ToByte(hmacsha256.Substring(i * 2, 2), 16);
                }
                string base64 = Convert.ToBase64String(resultantArray);
                oauth_signature = HttpUtility.UrlEncode(base64);
            }

            // Create the Authorization string for the WebRequest header
            string authorizationstring = "";
            foreach (KeyValuePair<string, string> pair in oauthparameters)
            {
                authorizationstring += pair.Key;
                authorizationstring += "=";
                authorizationstring += pair.Value;
                authorizationstring += ",";
            }
            authorizationstring += "oauth_signature=" + oauth_signature;

            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(uri);
            request.Method = method;
            request.Headers.Add("Authorization", "OAuth " + authorizationstring);
            HttpWebResponse response = (HttpWebResponse)request.GetResponse();
            Stream dataStream = response.GetResponseStream();
            StreamReader reader = new StreamReader(dataStream);
            string responseFromServer = reader.ReadToEnd();
            string[] temp = responseFromServer.Split('&');
            oauth_token = temp[0];
            oauth_token_secret = temp[1];
            var redirect = Redirect("https://bnpparibas.openbankproject.com/oauth/authorize?oauth_token=" + oauth_token);
            reader.Close();
            dataStream.Close();
            response.Close();
        }
    }
}
