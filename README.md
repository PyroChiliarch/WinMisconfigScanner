# WinMisconfigScanner
Powershell script to discover misconfigurations on windows devices.

Many of the vulnerabilities hackers will use to take over networks cannot be fixed by simply keeping your software up to date. These misconfigurations can be extremely dangerous, the worst of which may allow an unauthenticated attacker to take complete control over a network using Active Directory. Unfortunately, many of these are still enabled by default.

Currently Checks:
* Device Managment (AD/AAD Joined)
* LLMNR
* mDNS
* SMB Signing

![image](https://github.com/PyroChiliarch/WinMisconfigScanner/assets/11240849/47bfa299-84e3-430f-99b0-a82a78825417)

Please report any false positives/false negatives so I can fix them.
Pull requests welcome aswell.
