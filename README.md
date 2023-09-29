## Microsoft Defender for Identity - Radius Accounting Simulator
### What is it?
This is a PowerShell module that allow you to test the [VPN log integration in Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/vpn-integration). 

The module only has one function: `Test-RadiusAccounting` that you would use this way:

```PowerShell
Test-RadiusAccounting -Server SERVER1 -Secret "Secret" -Username "CONTOSO\Bob" -Machine "WORKSTATION1" -IP "1.2.3.4"
```

The `Server` here is the IP address or the name of a domain controller where the MDI sensor is installed.
The `IP` is the source IP address you want MDI to think your user `Username` is connecting from. 

It will show as a VPN connection in the Defender portal user's timeline.

## What is it not?

It is not a production tool. There almost no error management, the vendors classes and other RADIUS specific attribute have been reduced to what the MDI sensor would expect. If you use that with something else than MDI, there's no guarantees that it would function.  

This is just an attempt to use classes and other raw level manipulation. It was meant to be fun (and it was). Don't use it if you don't find it fun :)

