#########################################################################################
#
# TPLink-PoSH
#
# Powershell implemntation of controlling TP-Link HS100 and HS110.
# Author Chris Burns (chris@sortmy.it)
#
# Progam provided using information gleened by the great work done by
# Lubomir Stroetmann, Consultant and Tobias Esser, Consultant
# https://www.softscheck.com/en/reverse-engineering-tp-link-hs110/
#
########################################################################################


[ipaddress]$ip = "192.168.1.127"

[int]$port = 9999 # Should not need to change this as it is hard set

#Commands From https://github.com/softScheck/tplink-smartplug/blob/master/tplink-smarthome-commands.txt

#$Body = '{"system":{"get_sysinfo":null}}'

##### More Examples
#$Body = '{"system":{"set_relay_state":{"state":1}}}'
#$Body = '{"system":{"reboot":{"delay":1}}}'
$Body = '{"emeter":{"get_realtime":{}}}'
#$Body = '{"emeter":{"get_daystat":{"month":9,"year":2017}}}'
#$Body = '{"emeter":{"get_monthstat":{"month":9,"year":2017}}}'
#####



###########################################################################################

# Let's build the Encryption routine for TP-Link and return the byte array
function Encode-ForTPlink {

[CmdletBinding()]
param (
    # Get the string we need to byte Encode.
    [Parameter(
        Mandatory = $true,
        HelpMessage = 'Body to Encode'
    )]
    [String]$Body
    )

        
    $enc = [system.Text.Encoding]::UTF8
    # Now lets use the encoding method to return the un-encrypted byte array
    $bytes = $enc.GetBytes($Body) 
    # Tplink uses a dummy first 4 bytes so we just pass four 0's back
    for($i = 0; $i -lt 3;$i++){

        write-output 0

    }
    Write-Output 42
    #The first encryption key for the bxor method is 171
    [byte]$key = 171
    # Loop through the byte array then use the next character byte value as the key
    for($i=0; $i -lt $bytes.count ; $i++)
    {
        $a = $key -bxor $bytes[$i]
        $key = $a
        # Return the 'encrypted' byte
        write-output $a
    }
    
}

# Lets decrypt the message using the reverse method
function Decode-ForTPlink {

[CmdletBinding()]
param (
    [Parameter(
        Mandatory = $true,
        HelpMessage = 'Body to Decode'
    )]
    [byte[]]$Body,
    # Include Bytes is really used for debug to show the unencrypted message and the encrypted byte array together.
    [switch]$IncludeBytes = $false
    )
    [byte]$key = 171
    for($i=4; $i -lt $body.count ; $i++)
    {
        $a = $key -bxor $Body[$i]
        $key = $body[$i]
        [string]$origret += "$([string]$a),"
        $return += $([char]$a)
        
    }
  
    Write-Output $return
    if($includeBytes){Write-Output $origret}

}






#$Body = '{"system":{"set_relay_state":{"state":1}}}'
#$ByteReturn = $(Encode-ForTPlink -Body $Body)
#$ByteReturn







# needs to return 00:00:00:2a:d0:f2:81:f8:8b:ff:9a:f7:d5:ef:94:b6:c5:a0:d4:8b:f9:9c:f0:91:e8:b7:c4:b0:d1:a5:c0:e2:d8:a3:81:f2:86:e7:93:f6:d4:ee:df:a2:df:a2 for on
# nedds to return 00:00:00:2d:d0:f2:81:f8:8b:ff:9a:f7:d5:ef:94:b6:c5:a0:d4:8b:f9:9c:f0:91:e8:b7:c4:b0:d1:a5:c0:e2:d8:a3:81:e4:96:e4:bb:d8:b7:d3:b6:94:ae:9e:e3:9e:e3
# needs to return 00:00:00:1e:d0:f2:97:fa:9f:eb:8e:fc:de:e4:9f:bd:da:bf:cb:94:e6:83:e2:8e:fa:93:fe:9b:b9:83:f8:85:f8:85 for system state
# Converted for convienece - this is an encrypted byte array - $payload = 0x00,0x00,0x00,0x2a,0xd0,0xf2,0x81,0xf8,0x8b,0xff,0x9a,0xf7,0xd5,0xef,0x94,0xb6,0xc5,0xa0,0xd4,0x8b,0xf9,0x9c,0xf0,0x91,0xe8,0xb7,0xc4,0xb0,0xd1,0xa5,0xc0,0xe2,0xd8,0xa3,0x81,0xf2,0x86,0xe7,0x93,0xf6,0xd4,0xee,0xdf,0xa2,0xdf,0xa2
# Converted for convienece - this is an encrypted byte array - $payload = 0x00,0x00,0x00,0x2d,0xd0,0xf2,0x81,0xf8,0x8b,0xff,0x9a,0xf7,0xd5,0xef,0x94,0xb6,0xc5,0xa0,0xd4,0x8b,0xf9,0x9c,0xf0,0x91,0xe8,0xb7,0xc4,0xb0,0xd1,0xa5,0xc0,0xe2,0xd8,0xa3,0x81,0xe4,0x96,0xe4,0xbb,0xd8,0xb7,0xd3,0xb6,0x94,0xae,0x9e,0xe3,0x9e,0xe3
# Converted for convienece - this is an encrypted byte array - $payload = 0x00,0x00,0x00,0x1e,0xd0,0xf2,0x97,0xfa,0x9f,0xeb,0x8e,0xfc,0xde,0xe4,0x9f,0xbd,0xda,0xbf,0xcb,0x94,0xe6,0x83,0xe2,0x8e,0xfa,0x93,0xfe,0x9b,0xb9,0x83,0xf8,0x85,0xf8,0x85




    $Tcpclient = New-Object System.Net.Sockets.TcpClient($IP, $port)
    $Stream = $Tcpclient.GetStream()


        
    $ByteReturn = $(Encode-ForTPlink -Body $Body)
    $Stream.write($ByteReturn,0,$ByteReturn.Length)
    $Stream.Flush()

    If($tcpClient.Available -lt 7){
        # As crazy as this sounds, we need to wait for a reply from the switch before responding, otherwise the script terminates before the switch has time to respond
        start-sleep 1
    }

    # Use the below to see if there is any data in the buffer
    $tcpClient.Available
    
    # Lets cretae a variable to get the response back from the plug    
    $bindResponseBuffer = New-Object Byte[] -ArgumentList $tcpClient.Available
    
    

    # Loop through the buffer till we get the full JSON response    
    while ($TCPClient.Connected){
            $Read = $stream.Read($bindResponseBuffer, 0, $bindResponseBuffer.Length)
            if( $Read -eq 0){break}                  
            else{            
                [Array]$Bytesreceived += $bindResponseBuffer[0..($Read -1)]
                [Array]::Clear($bindResponseBuffer, 0, $Read)
            }
     }
    #Write-Output $Bytesreceived
    If( $null -eq $Bytesreceived){
        Write-output "No data received back from the plug"
    }else{
     
        # Now lets store that Encrypted ByteArray so we can clean up the netwrok stack
        $ReceivedMessage = $Bytesreceived
        $Obj = ConvertFrom-Json (Decode-ForTPlink $ReceivedMessage)
        Write-output $Obj
    }
    # Clean up the network stack
       
    $Bytesreceived = $null
    $stream.flush()
    $Tcpclient.Dispose()
    $Tcpclient.Close()
    
   



    
##############################################################################################################
#
# Useful for Debugging to see what the Hex representation is of the Byte Array - Not used in the program
#
# Commandline : Convert-ByteArrayToHexString -ByteArray $(Encode-ForTPlink -Body $Body)
#
##############################################################################################################

function Convert-ByteArrayToHexString
{
################################################################
#.Synopsis
# Returns a hex representation of a System.Byte[] array as
# one or more strings. Hex format can be changed.
#.Parameter ByteArray
# System.Byte[] array of bytes to put into the file. If you
# pipe this array in, you must pipe the [Ref] to the array.
# Also accepts a single Byte object instead of Byte[].
#.Parameter Width
# Number of hex characters per line of output.
#.Parameter Delimiter
# How each pair of hex characters (each byte of input) will be
# delimited from the next pair in the output. The default
# looks like "0x41,0xFF,0xB9" but you could specify "\x" if
# you want the output like "\x41\xFF\xB9" instead. You do
# not have to worry about an extra comma, semicolon, colon
# or tab appearing before each line of output. The default
# value is ",0x".
#.Parameter Prepend
# An optional string you can prepend to each line of hex
# output, perhaps like '$x += ' to paste into another
# script, hence the single quotes.
#.Parameter AddQuotes
# A switch which will enclose each line in double-quotes.
#.Example
# [Byte[]] $x = 0x41,0x42,0x43,0x44
# Convert-ByteArrayToHexString $x
#
# 0x41,0x42,0x43,0x44
#.Example
# [Byte[]] $x = 0x41,0x42,0x43,0x44
# Convert-ByteArrayToHexString $x -width 2 -delimiter "\x" -addquotes
#
# "\x41\x42"
# "\x43\x44"
################################################################
[CmdletBinding()] Param (
[Parameter(Mandatory = $True, ValueFromPipeline = $True)] [System.Byte[]] $ByteArray,
[Parameter()] [Int] $Width = 100,
[Parameter()] [String] $Delimiter = ",0x",
[Parameter()] [String] $Prepend = "",
[Parameter()] [Switch] $AddQuotes )
 
if ($Width -lt 1) { $Width = 1 }
if ($ByteArray.Length -eq 0) { Return }
$FirstDelimiter = $Delimiter -Replace "^[\,\:\t]",""
$From = 0
$To = $Width - 1
Do
{
$String = [System.BitConverter]::ToString($ByteArray[$From..$To])
$String = $FirstDelimiter + ($String -replace "\-",$Delimiter)
if ($AddQuotes) { $String = '"' + $String + '"' }
if ($Prepend -ne "") { $String = $Prepend + $String }
$String
$From += $Width
$To += $Width
} While ($From -lt $ByteArray.Length)
}
