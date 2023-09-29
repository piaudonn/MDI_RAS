#Creating enum just because it looks nice when it's being used
#Only creating items that we use/parse later
enum RadiusAttributeType
{
    AttributeAcctStatusType = 0x28
    AttributeAcctSessionID = 0x2c
    AttributeUserName = 0x1
    AttributeVendorSpecific = 0x1a
    AttributeTunnelClientEndpoint = 0x42
    AttributeFramedIPAddress = 0x8
    AttributeNASIdentifier = 0x20
    AttributeNasIPAddress = 0x4
}
enum RadiusAttributeTypeVendor
{
    Microsoft = 0x00000137
}
enum RadiusAttributeTypeVendorType
{
    ClientName = 0x22
}
enum AcctStatusType
{
    Start = 0x1
}

#It's only for Radius accounting
class RadiusAccountPacket
{
    [byte[]] $Type
    [byte[]] $Identifier
    [byte[]] $Length
    [byte[]] $Authenticator
    [bool] $AuthenticatorChecked = $false
    [byte[]] $Attributes

    #Empty constructor, just because \_(^^)_/
    RadiusAccountPacket()
    {}
    
    RadiusAccountPacket( [byte[]] $_Stream )
    {
        #Tribute to Pascal, do not process in the constructor
        $this.ParseRadiusAccountPacket( $_Stream )
    }

    RadiusAccountPacket( [byte[]] $_Stream, [string] $_Secret )
    {
        $this.ParseRadiusAccountPacket( $_Stream )
        $this.AuthenticatorChecked = $this.CheckAuthenticator($_Secret)
    }  
    #Parsing just to be able to read the response
    [void] hidden ParseRadiusAccountPacket( [byte[]] $_Stream )
    {
        $this.Type = $_Stream[0]
        $this.Identifier = $_Stream[1]
        $this.Length = $_Stream[2..3]
        $this.Authenticator = $_Stream[4..19]
        $this.Attributes = $_Stream[20..([System.BitConverter]::ToInt16($this.Length,0))]
    }
    #Function to check if the md5 we received is correct, I mean, we don't need it but whatev
    #Note that this function does't work as-is to check the authenticator of the response
    [bool] CheckAuthenticator( [string] $_Secret )
    {
        [byte[]] $_Stream = $this.Type + `
            [byte[]] $this.Identifier + `
            [byte[]] $this.Length + `
            [byte[]] (New-Object byte[] 16) + `
            [byte[]] $this.Attributes + `
            [byte[]] [System.Text.Encoding]::UTF8.GetBytes($_Secret)
        $_md5 = New-Object System.Security.Cryptography.MD5CryptoServiceProvider
        return ( [System.BitConverter]::ToString( $_md5.ComputeHash($_Stream) ) -eq [System.BitConverter]::ToString( $this.Authenticator ) )
    }
    [bool] CheckResponseAuthenticator( [string] $_Secret, [byte[]] $_ReceivedAuthenticator )
    {
        [byte[]] $_Stream = $this.Type + `
            [byte[]] $this.Identifier + `
            [byte[]] $this.Length + `
            [byte[]] $this.Authenticator + `
            [byte[]] [System.Text.Encoding]::UTF8.GetBytes($_Secret)
        $_md5 = New-Object System.Security.Cryptography.MD5CryptoServiceProvider
        return ( [System.BitConverter]::ToString( $_md5.ComputeHash($_Stream) ) -eq [System.BitConverter]::ToString( $_ReceivedAuthenticator ) )
    }
    [byte[]] GetStream()
    {
        $this.Length = [System.BitConverter]::GetBytes( [char] ( $this.Attributes.Length + 20 ) )[1..0]
        return $this.Type + $this.Identifier + $this.Length + (New-Object byte[] 16) + $this.Attributes
    }
    [byte[]] GetStream( [string] $_Secret )
    {
        $this.Length = [System.BitConverter]::GetBytes( [char] ( $this.Attributes.Length + 20) )[1..0]
        $_md5 = New-Object System.Security.Cryptography.MD5CryptoServiceProvider
        $_Stream = $this.Type + $this.Identifier + $this.Length + (New-Object byte[] 16) + $this.Attributes + [System.Text.Encoding]::UTF8.GetBytes($_Secret)
        return $this.Type + $this.Identifier + $this.Length + $_md5.ComputeHash($_Stream) + $this.Attributes
    }
    [string] GetString()
    {
        return [System.BitConverter]::ToString( $this.GetStream() )
    }
    [string] GetString( [string] $_Secret )
    {
        return [System.BitConverter]::ToString( $this.GetStream( $_Secret ) )
    }    
}

class RadiusAttribute
{
    [byte[]] $Type
    [byte[]] $Length
    [byte[]] $Data

    RadiusAttribute( [RadiusAttributeType] $_Type, $_Data )
    {
        $this.Type = [int] $_Type.value__
        switch ( $_Data.GetType() )
        {
            ([System.String]) {
                if ( $this.Type -eq 0x4 -or $this.Type -eq 0x8 ) #Those are IP addresses in bytes
                {
                    $this.AddByteArrayAttribute( ([IPAddress] $_Data).GetAddressBytes() )
                } else {
                    $this.AddStringAttribute( $_Data )
                }
            }
            ([Int]) {
                $this.AddIntAttribute( $_Data ) #Hu?
            }
            ([System.Byte[]]) {
                $this.AddByteArrayAttribute( $_Data )
            }
        }
    }
    RadiusAttribute( [RadiusAttributeType] $_Type, [AcctStatusType] $_StatusType )
    {
        if ( $_Type.value__ -ne 0x28 )
        {
            throw "Cannot create a radius attribute $_Type with an AcctStatusType parameter."
        }
        $this.Type = $_Type.value__
        $this.Length = 0x6
        $this.AddIntAttribute($_StatusType.value__) 
    }    
    RadiusAttribute( [RadiusAttributeType] $_Type, [RadiusAttributeTypeVendor] $_TypeVendor, [RadiusAttributeTypeVendorType] $_TypeVendorType, $_Data )
    {
        $this.Type = $_Type.value__
        $this.Data = [System.BitConverter]::GetBytes([int] $_TypeVendor)[3..0]
        switch ( $_TypeVendorType.value__)
        {
            0x22 {
                $this.Data += ([byte[]] 0x22)
                $this.Data += [char] ($_Data.Length + 2)
                $this.Data += [System.Text.Encoding]::UTF8.GetBytes( $_Data )
            }
        }
        $this.Length = [char] ( $this.Data.Length + 2 )
    }
    [void] hidden AddStringAttribute( [string] $_Data )
    {
        $this.Data = [System.Text.Encoding]::UTF8.GetBytes( $_Data )
        $this.Length = [char] ($this.Data.Length + 2)
    } 
    [void] hidden AddIntAttribute( [int] $_Data )
    {
        $this.Data = [System.BitConverter]::GetBytes( $_Data )[3..0]
        $this.Length = [char] ($this.Data.Length + 2)
    }
    [void] hidden AddByteArrayAttribute( [byte[]] $_Data )
    {
        $this.Data = $_Data
        $this.Length = [char] ( $_Data.Length + 2 ) 
    }
    [byte[]] GetStream()
    {
        return $this.Type + $this.Length + $this.Data
    }
}

<#
.Synopsis
    Sends a Radius Accounting request packet to a listening Radius accounting server.
.DESCRIPTION
    This was created to simulate VPN connexions for the Microsoft Defender for Identity sensors when Radius accounting integration is enabled (https://learn.microsoft.com/en-us/defender-for-identity/vpn-integration).
.EXAMPLE
    Test-RadiusAccounting -Server SERVER1 -Secret "Secret" -Username "CONTOSO\Bob" -Machine "WORKSTATION1" -IP "1.2.3.4"
.INPUTS
    -Server
        IP address or FQDN of the server listening to Radius Accounting packets. In Microsoft Defender for Identity, it is any domain controller with the sensor deployed.
    
    -Port
        The port used for Radius accounting, default is 1813.
        
    -Secret
        The Radius secret to calculate the authenticator of the Radius accounting request.
        
    -Username
        The username in the DOMAIN\sAMAccountName fortmat or UserPrincipalName format.
        
    -Machine
        The NetBIOS name of the machine from which the client is connected.
        
    -IP
        The egress IP address of the client (Internet IP address).

    -FrameIPAddress
        The client IP address as seen by the VPN server.
        
    -NASIPaddress
        The IP address of the VPN server.
        
    -NASIdentifier
        The name of the VPN server.
        
    -SessionID
        The Radius session ID. Default is generated randomly.

.NOTES
    2022/12/12 - Version 1
        - Needs to implement params validation
        - Needs to implement Accounting Response authenticator check
#>
function Test-RadiusAccounting {
    param(
        $Server ,
        $Port = 1813,
        $Secret,
        $Username,
        $Machine,
        $IP,
        $SessionID = (Get-Random -Minimum 10000 -Maximum 15000),
        $FrameIPAddress, #Client local IP address
        $NASIPAddress, 
        $NASIdentifier #VPN Server name
    )
    begin {
        $UDPClient = New-Object Net.Sockets.UdpClient(0)
        Write-Host "[+] Using local port: $($UDPClient.Client.LocalEndPoint.Port)"
        $IPEndpoint = New-Object Net.IPEndPoint([Net.IPAddress]::any, 0)
        Write-Host "[+] Targeting server: $Server"
        $Identifier = 1
    }
    process {
        
        $Packet = [RadiusAccountPacket]::new()
        $Packet.Type = 0x4
        $Packet.Identifier = $Identifier++
        $Attributes  = [RadiusAttribute]::new([RadiusAttributeType]::AttributeAcctStatusType, [AcctStatusType]::Start ).GetStream()
        $Attributes += [RadiusAttribute]::new([RadiusAttributeType]::AttributeAcctSessionID, $SessionID ).GetStream()
        Write-Host "[-] SessionID: $SessionID"
        $Attributes += [RadiusAttribute]::new([RadiusAttributeType]::AttributeUserName, $Username ).GetStream()
        Write-Host "[-] Username: $Username"
        $Attributes += [RadiusAttribute]::new([RadiusAttributeType]::AttributeVendorSpecific, [RadiusAttributeTypeVendor]::Microsoft, [RadiusAttributeTypeVendorType]::ClientName, $Machine ).GetStream()
        Write-Host "[-] Machine: $Machine"
        $Attributes += [RadiusAttribute]::new([RadiusAttributeType]::AttributeTunnelClientEndpoint, $IP ).GetStream()
        Write-Host "[-] IP: $IP"
        if ( $FrameIPAddress )
        {
            $Attributes += [RadiusAttribute]::new([RadiusAttributeType]::AttributeFramedIPAddress, $FrameIPAddress ).GetStream()
            Write-Host "[-] FramedIPAddress: $FrameIPAddress"
        }
        if ( $NASIPAddress )
        {
            $Attributes += [RadiusAttribute]::new([RadiusAttributeType]::AttributeNasIPAddress, $NASIPAddress ).GetStream()
            Write-Host "[-] NASIPAddress: $NASIPAddress"
        }
        if ( $NASIdentifier )
        {
            $Attributes += [RadiusAttribute]::new([RadiusAttributeType]::AttributeNASIdentifier, $NASIdentifier ).GetStream()
            Write-Host "[-] NASIdentifier: $NASIdentifier"
        }
        $Packet.Attributes = $Attributes
        $Stream = $Packet.GetStream($Secret)
        Write-Host "[+] Packet sent!"
        Write-Verbose "[+] Data: $($Packet.GetString($Secret))"
        [void] $UDPClient.send($Stream, $Stream.length, $Server, $Port)
        $Response = $UDPClient.receive([ref]$IPEndpoint)
        Write-Host "[+] Packet received!"
        Write-Verbose "[+] Data: $([System.BitConverter]::ToString($Response))"
    }
    end {
        $UDPClient.Close()
        Write-Host "[+] UDP Client closed."
    }
}

Export-ModuleMember -Function Test-RadiusAccounting
