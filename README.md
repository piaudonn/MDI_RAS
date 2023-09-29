## Microsoft Defender for Identity - Radius Accounting Simulator
### What is it?
This is a PowerShell module that allow you to test the [VPN log integration in Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/vpn-integration). 

Once imported, the module add the following cmdlet `Test-RadiusAccounting` that you would use this way:

```PowerShell
Test-RadiusAccounting
  -Server SERVER1 `
  -Secret "Secret" `
  -Username "CONTOSO\Bob" `
  -Machine "WORKSTATION1" `
  -IP "1.2.3.4"
```

The `Server` here is the IP address or the name of a domain controller where the MDI sensor is installed.
The `IP` is the source IP address you want MDI to think your user `Username` is connecting from. 

It will show as a VPN connection in the Defender portal user's timeline: <img width="571" alt="image" src="https://github.com/piaudonn/MDI-RAS/assets/22434561/56739e55-b308-43bb-a4e2-273be59f7a41">

It also supports sending `FrameIPAddress` (the client IP address as seen by the VPN server), `NASIPaddress` (the IP address of the VPN server), `NASIdentifier` (the name of the VPN server) and arbitrary `SessionId`. Use `Get-Help Test-RadiusAccounting` for more information.

## What is it not?

It is not a production tool. There almost no error management, the vendors classes and other RADIUS specific attribute have been reduced to what the MDI sensor would expect. If you use that with something else than MDI, there's no guarantees that it would function.  

This is just an attempt to use classes and other raw level manipulation. It was meant to be fun (and it was). Don't use it if you don't find it fun :)

