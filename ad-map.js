window.MINDMAP_AD_DATA = {
  root: {
    id: 'ad-root',
    data: {
      label: 'Active Directory',
      description: 'Enterprise Security Assessment Flow',
      descriptionMd:
        '## Active Directory\nDomain assessments revolve around **identity**, **Kerberos/NTLM**, **trust paths**, and **misconfigurations**. This map keeps technique names for orientation, but avoids step-by-step offensive commands.\n',
      commands: [],
      type: 'root',
      emoji: '🏰',
      resources: [
        { title: 'MITRE ATT&CK - Enterprise', url: 'https://attack.mitre.org/versions/v13/' },
        { title: 'Microsoft Security - Active Directory Overview', url: 'https://learn.microsoft.com/en-us/windows-server/identity/active-directory-domain-services' }
      ]
    },
    children: [
      {
        id: 'ad-pre',
        data: {
          label: 'Pre-Engagement',
          description: 'ROE, Scope, Safety, Accounts',
          descriptionMd:
            '### Pre-Engagement\nAlign on scope, test windows, data handling, and incident escalation. Ensure you have approved test accounts and clear stop conditions.\n',
          commands: [],
          type: 'category',
          emoji: '🧾',
          resources: [
            { title: 'PTES Pre-Engagement', url: 'https://www.pentest-standard.org/index.php/Pre-engagement' }
          ]
        },
        children: [
          {
            id: 'ad-roe',
            data: {
              label: 'ROE & Constraints',
              description: 'Boundaries & guardrails',
              descriptionMd:
                '### ROE & Constraints\nSpecify what is allowed (auth testing, relay simulations, password policy checks), what is excluded (production disruption, high-volume auth), and evidence handling.\n',
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
              descriptionMd:
                '### Test Accounts\nPrefer named test identities with known roles to validate privilege boundaries and lateral movement paths without “guessing” behavior.\n',
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
          description: 'Domain Discovery',
          descriptionMd: '### Recon\nIdentify hosts, services, domain structure, and trust relationships.',
          commands: [],
          type: 'category',
          emoji: '🔎',
          resources: [
            { title: 'Microsoft - Active Directory Replication and Topology', url: 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-replication' }
          ]
        },
        children: [
          {
            id: 'ad-network-discovery',
            data: {
              label: 'Network Discovery',
              description: 'DCs, critical servers, management planes',
              descriptionMd:
                '### Network Discovery\nBuild an asset view: Domain Controllers, PKI/AD CS, file servers, management jump boxes, and identity-integrated apps.\n',
              commands: [],
              type: 'technique',
              emoji: '🗺️',
              resources: []
            },
            children: []
          },
          {
            id: 'ad-dns-recon',
            data: {
              label: 'DNS Recon',
              description: 'SRV records & site hints',
              descriptionMd:
                '### DNS Recon\nSRV records and naming conventions often reveal DCs, sites, federation, and legacy services.\n',
              commands: [],
              type: 'technique',
              emoji: '🧷',
              resources: []
            },
            children: []
          },
          {
            id: 'smb-enum',
            data: {
              label: 'SMB Enum',
              description: 'Shares & Signing',
              descriptionMd:
                '### SMB Enum\nEnumerate shares and posture signals (signing requirements, guest access, legacy auth). Focus on exposure and data classification.\n',
              commands: [],
              type: 'tool',
              emoji: '🖥️',
              resources: []
            },
            children: []
          },
          {
            id: 'ldap-enum',
            data: {
              label: 'LDAP Enum',
              description: 'Domain Objects',
              descriptionMd:
                '### LDAP Enum\nModel users, groups, computers, OUs, GPO links, delegation, and ACLs to understand effective permissions.\n',
              commands: [],
              type: 'tool',
              emoji: '📋',
              resources: []
            },
            children: []
          },
          {
            id: 'ad-kerberos-recon',
            data: {
              label: 'Kerberos Recon',
              description: 'Realm posture & auth surface',
              descriptionMd:
                '### Kerberos Recon\nMap where Kerberos is used vs NTLM, identify service accounts, SPNs, and weak configuration patterns that affect ticket security.\n',
              commands: [],
              type: 'technique',
              emoji: '🎟️',
              resources: []
            },
            children: []
          },
          {
            id: 'ad-bh-paths',
            data: {
              label: 'Privilege Graph',
              description: 'Trust paths & effective rights',
              descriptionMd:
                '### Privilege Graph\nRepresent permissions as a graph (sessions, local admin rights, ACL edges) to prioritize the shortest realistic escalation path.\n',
              commands: [],
              type: 'technique',
              emoji: '🕸️',
              resources: [
                { title: 'BloodHound Docs (Concepts)', url: 'https://bloodhound.readthedocs.io/en/latest/' }
              ]
            },
            children: []
          },
          {
            id: 'ad-trusts',
            data: {
              label: 'Trusts & Forest Topology',
              description: 'Cross-domain/forest exposure',
              descriptionMd:
                '### Trusts & Forest Topology\nIdentify external trusts, selective auth, SID filtering, and “admin tier” boundaries that can collapse in real environments.\n',
              commands: [],
              type: 'technique',
              emoji: '🌲',
              resources: []
            },
            children: []
          },
          {
            id: 'adcs-enum',
            data: {
              label: 'AD CS Discovery',
              description: 'PKI roles, templates, enrollment',
              descriptionMd:
                '### AD CS Discovery\nDiscover CA servers, enrollment endpoints, certificate templates, and who can enroll/modify. PKI is a frequent domain-control shortcut when misconfigured.\n',
              commands: [],
              type: 'technique',
              emoji: '🪪',
              resources: [
                { title: 'Microsoft - Active Directory Certificate Services', url: 'https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/active-directory-certificate-services-overview' }
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
          descriptionMd:
            '### Initial Access\nObtain a legitimate foothold through approved testing paths (test accounts, exposed services, or validated weaknesses).\n',
          commands: [],
          type: 'category',
          emoji: '🔑',
          resources: []
        },
        children: [
          {
            id: 'ad-auth-surface',
            data: {
              label: 'Auth Surface Review',
              description: 'VPN, RDP, OWA, SSO, legacy endpoints',
              descriptionMd:
                '### Auth Surface Review\nInventory authentication entry points and identify policy mismatches: MFA gaps, legacy auth, weak conditional access, and inconsistent lockout rules.\n',
              commands: [],
              type: 'technique',
              emoji: '🧭',
              resources: []
            },
            children: []
          },
          {
            id: 'spray',
            data: {
              label: 'Password Policy Testing',
              description: 'Lockout-safe validation',
              descriptionMd:
                '### Password Policy Testing\nValidate lockout thresholds and weak-password exposure **within ROE**. Prefer measured validation with explicit stakeholder approval.\n',
              commands: [],
              type: 'tool',
              emoji: '🔓',
              resources: []
            },
            children: []
          },
          {
            id: 'asreproast',
            data: {
              label: 'Kerberos Preauth Weakness',
              description: 'Accounts without preauth',
              descriptionMd:
                '### Kerberos Preauth Weakness\nIdentify accounts with risky Kerberos preauth settings and treat them as high-priority remediation targets.\n',
              commands: [],
              type: 'technique',
              emoji: '🎟️',
              resources: []
            },
            children: []
          },
          {
            id: 'kerberoast',
            data: {
              label: 'Service Account Exposure',
              description: 'SPNs & offline risk',
              descriptionMd:
                '### Service Account Exposure\nService accounts tied to SPNs can increase offline attack surface when passwords are weak or unmanaged.\n',
              commands: [],
              type: 'technique',
              emoji: '🎟️',
              resources: []
            },
            children: []
          },
          {
            id: 'ad-gpp',
            data: {
              label: 'GPP & SYSVOL Secrets',
              description: 'Legacy secret storage',
              descriptionMd:
                '### GPP & SYSVOL Secrets\nCheck for legacy preference artifacts and plaintext-like secrets in policy distribution paths.\n',
              commands: [],
              type: 'technique',
              emoji: '📦',
              resources: []
            },
            children: []
          },
          {
            id: 'ad-laps',
            data: {
              label: 'LAPS / Local Password Mgmt',
              description: 'Password disclosure paths',
              descriptionMd:
                '### LAPS / Local Password Management\nAssess whether local admin passwords are unique, rotated, and properly ACL-protected.\n',
              commands: [],
              type: 'technique',
              emoji: '🔐',
              resources: []
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
          descriptionMd:
            '### Privilege Escalation\nFind misconfigurations, delegation weaknesses, and ACL issues that create admin-equivalent outcomes.\n',
          commands: [],
          type: 'category',
          emoji: '👑',
          resources: []
        },
        children: [
          {
            id: 'local-admin',
            data: {
              label: 'Local Admin Paths',
              description: 'Groups, services, token abuse',
              descriptionMd:
                '### Local Admin Paths\nValidate how local admin is granted (groups, GPO, imaging baselines) and where it can be abused via misconfigured services or writable paths.\n',
              commands: [],
              type: 'technique',
              emoji: '👤',
              resources: []
            },
            children: []
          },
          {
            id: 'acl-abuse',
            data: {
              label: 'ACL & Delegation',
              description: 'WriteDACL, GenericAll, shadow admins',
              descriptionMd:
                '### ACL & Delegation\nLook for “shadow admin” edges where directory permissions effectively allow takeover of users, groups, OUs, or GPOs.\n',
              commands: [],
              type: 'technique',
              emoji: '🧬',
              resources: []
            },
            children: []
          },
          {
            id: 'gpo-abuse',
            data: {
              label: 'GPO Control',
              description: 'Policy-level privilege',
              descriptionMd:
                '### GPO Control\nAssess who can edit or link GPOs that affect privileged systems. Treat GPO modification rights as near-admin.\n',
              commands: [],
              type: 'technique',
              emoji: '📑',
              resources: []
            },
            children: []
          },
          {
            id: 'delegation',
            data: {
              label: 'Delegation Issues',
              description: 'Unconstrained / constrained / RBCD',
              descriptionMd:
                '### Delegation Issues\nEvaluate delegation settings as they can create powerful impersonation paths when combined with weak service isolation.\n',
              commands: [],
              type: 'technique',
              emoji: '🪝',
              resources: []
            },
            children: []
          },
          {
            id: 'adcs-privesc',
            data: {
              label: 'AD CS Misconfigurations',
              description: 'Template & enrollment flaws',
              descriptionMd:
                '### AD CS Misconfigurations\nMisconfigured templates, enrollment agents, or access control can produce credentials equivalent to privileged identities.\n',
              commands: [],
              type: 'technique',
              emoji: '🏷️',
              resources: []
            },
            children: []
          },
          {
            id: 'dcsync',
            data: {
              label: 'Directory Replication Rights',
              description: 'Replication-capable principals',
              descriptionMd:
                '### Directory Replication Rights\nIdentify principals with replication-like rights; this is often an immediate escalation-to-domain-control risk.\n',
              commands: [],
              type: 'technique',
              emoji: '🔁',
              resources: []
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
          descriptionMd:
            '### Lateral Movement\nMove between hosts using legitimate admin protocols and trust relationships, while validating segmentation assumptions.\n',
          commands: [],
          type: 'category',
          emoji: '🔀',
          resources: []
        },
        children: [
          {
            id: 'ad-remote-mgmt',
            data: {
              label: 'Remote Management',
              description: 'WinRM, RDP, SMB admin shares',
              descriptionMd:
                '### Remote Management\nAssess exposure of administrative protocols and whether access is restricted to management networks and privileged workstations.\n',
              commands: [],
              type: 'technique',
              emoji: '🧰',
              resources: []
            },
            children: []
          },
          {
            id: 'psexec',
            data: {
              label: 'Remote Exec (Service-based)',
              description: 'Execution via admin channels',
              descriptionMd:
                '### Remote Exec\nValidate which identities can remotely execute and whether monitoring and hardening controls detect and block it.\n',
              commands: [],
              type: 'tool',
              emoji: '⬆️',
              resources: []
            },
            children: []
          },
          {
            id: 'wmiexec',
            data: {
              label: 'Remote Exec (WMI/DCOM)',
              description: 'Management interface exposure',
              descriptionMd:
                '### WMI/DCOM\nConfirm if WMI/DCOM is broadly reachable and whether endpoint controls constrain misuse.\n',
              commands: [],
              type: 'tool',
              emoji: '🧠',
              resources: []
            },
            children: []
          },
          {
            id: 'cred-hygiene',
            data: {
              label: 'Credential Hygiene',
              description: 'Reuse, caching, session exposure',
              descriptionMd:
                '### Credential Hygiene\nEvaluate how credentials appear on endpoints: cached logons, service creds, scheduled tasks, and session sprawl.\n',
              commands: [],
              type: 'technique',
              emoji: '🧼',
              resources: []
            },
            children: []
          },
          {
            id: 'name-resolution',
            data: {
              label: 'Name Resolution Risks',
              description: 'LLMNR/NBNS/WPAD posture',
              descriptionMd:
                '### Name Resolution Risks\nAssess whether legacy name resolution features increase credential exposure and whether mitigations are enforced.\n',
              commands: [],
              type: 'technique',
              emoji: '📡',
              resources: []
            },
            children: []
          }
        ]
      },

      {
        id: 'ad-persist',
        data: {
          label: 'Persistence',
          description: 'Keep Access',
          descriptionMd:
            '### Persistence\nEvaluate common persistence classes to verify detection coverage and hardening, then ensure clean rollback.\n',
          commands: [],
          type: 'category',
          emoji: '🔁',
          resources: []
        },
        children: [
          {
            id: 'ticket-persist',
            data: {
              label: 'Kerberos Ticket Risk',
              description: 'Long-lived trust artifacts',
              descriptionMd:
                '### Kerberos Ticket Risk\nTreat ticket-forgery and long-lived ticket risks as “domain control” class issues; focus on KRBTGT hygiene, tiering, and monitoring.\n',
              commands: [],
              type: 'technique',
              emoji: '🎟️',
              resources: []
            },
            children: []
          },
          {
            id: 'service-accounts',
            data: {
              label: 'Service Accounts',
              description: 'Credential governance',
              descriptionMd:
                '### Service Accounts\nAssess rotation, gMSA adoption, least privilege, and whether service identities are overused across hosts.\n',
              commands: [],
              type: 'technique',
              emoji: '🔑',
              resources: []
            },
            children: []
          },
          {
            id: 'adcs-persist',
            data: {
              label: 'Certificate Persistence',
              description: 'Abuse of enrollment/issuance',
              descriptionMd:
                '### Certificate Persistence\nIf PKI is present, validate governance of templates and issuance, and whether certificate-based auth is monitored and constrained.\n',
              commands: [],
              type: 'technique',
              emoji: '📛',
              resources: []
            },
            children: []
          },
          {
            id: 'gpo-persist',
            data: {
              label: 'Policy Persistence',
              description: 'GPO + scheduled actions',
              descriptionMd:
                '### Policy Persistence\nConfirm whether policy changes are tightly controlled, reviewed, and alerted, especially for privileged OU scope.\n',
              commands: [],
              type: 'technique',
              emoji: '🧷',
              resources: []
            },
            children: []
          }
        ]
      },

      {
        id: 'ad-impact',
        data: {
          label: 'Impact & Objectives',
          description: 'Proof, not destruction',
          descriptionMd:
            '### Impact & Objectives\nDemonstrate realistic risk: access to sensitive data, control-plane compromise, or ability to alter identity and authorization. Keep evidence minimal and reversible.\n',
          commands: [],
          type: 'category',
          emoji: '🎯',
          resources: []
        },
        children: [
          {
            id: 'ad-data-access',
            data: {
              label: 'Data Access',
              description: 'Files, shares, databases',
              descriptionMd:
                '### Data Access\nValidate data exposure via shares, backups, and service accounts. Emphasize classification and blast radius.\n',
              commands: [],
              type: 'technique',
              emoji: '🗄️',
              resources: []
            },
            children: []
          },
          {
            id: 'ad-control-plane',
            data: {
              label: 'Control Plane',
              description: 'Identity governance integrity',
              descriptionMd:
                '### Control Plane\nAssess whether an attacker could alter identities, groups, policies, or PKI issuance in ways that survive resets.\n',
              commands: [],
              type: 'technique',
              emoji: '🧩',
              resources: []
            },
            children: []
          }
        ]
      },

      {
        id: 'ad-detection',
        data: {
          label: 'Detection & Hardening',
          description: 'Turn findings into controls',
          descriptionMd:
            '### Detection & Hardening\nMap each technique to prevention and telemetry: tiering, MFA, constrained admin paths, PKI governance, and alertable events.\n',
          commands: [],
          type: 'category',
          emoji: '🛠️',
          resources: [
            { title: 'Microsoft - Securing Active Directory', url: 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices' },
            { title: 'Microsoft - Tiered Administrative Model', url: 'https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model' }
          ]
        },
        children: [
          {
            id: 'tiering',
            data: {
              label: 'Admin Tiering',
              description: 'PAWs, separation, JIT',
              descriptionMd:
                '### Admin Tiering\nSeparate admin contexts, restrict logon locations, and prefer just-in-time elevation.\n',
              commands: [],
              type: 'technique',
              emoji: '🧱',
              resources: []
            },
            children: []
          },
          {
            id: 'logging',
            data: {
              label: 'Logging & Alerts',
              description: 'Windows events, DC telemetry',
              descriptionMd:
                '### Logging & Alerts\nValidate coverage for directory changes, policy edits, certificate issuance, and remote management activity.\n',
              commands: [],
              type: 'technique',
              emoji: '📈',
              resources: []
            },
            children: []
          },
          {
            id: 'passwords',
            data: {
              label: 'Password & Secrets Governance',
              description: 'Rotation, gMSA, vaulting',
              descriptionMd:
                '### Password & Secrets Governance\nPrioritize rotation, gMSA adoption, removal of embedded secrets, and least privilege service identities.\n',
              commands: [],
              type: 'technique',
              emoji: '🔐',
              resources: []
            },
            children: []
          },
          {
            id: 'pki-governance',
            data: {
              label: 'PKI Governance',
              description: 'Template control & audit',
              descriptionMd:
                '### PKI Governance\nLock down template modifications, restrict enrollment, audit issuance, and monitor certificate-based auth patterns.\n',
              commands: [],
              type: 'technique',
              emoji: '🏛️',
              resources: []
            },
            children: []
          }
        ]
      },

      {
        id: 'ad-report',
        data: {
          label: 'Reporting & Retest',
          description: 'Actionable remediation',
          descriptionMd:
            '### Reporting & Retest\nPresent privilege paths, affected objects, and concrete remediation. Retest focuses on closure and regression prevention.\n',
          commands: [],
          type: 'category',
          emoji: '📝',
          resources: []
        },
        children: [
          {
            id: 'ad-path-writeup',
            data: {
              label: 'Privilege Path Writeup',
              description: 'Shortest path + controls',
              descriptionMd:
                '### Privilege Path Writeup\nDocument the minimal chain (assumptions, edges, required rights) and pair each step with a preventive control and a detection signal.\n',
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
              descriptionMd:
                '### Cleanup\nRemove test artifacts, revert policy changes, and verify no lingering credentials, certificates, or scheduled actions remain.\n',
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

  extraEdges: [
    {
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
      id: 'e-privesc-impact',
      source: 'ad-privesc',
      target: 'ad-impact',
      data: {
        label: 'Prove Blast Radius',
        type: 'flow',
        descriptionMd: 'Escalation findings should translate into measurable impact: data reachability, policy control, or identity integrity compromise.'
      }
    },
    {
      id: 'e-lateral-detection',
      source: 'ad-lateral',
      target: 'ad-detection',
      data: {
        label: 'Telemetry Validation',
        type: 'context',
        descriptionMd: 'Lateral movement tests validate whether hardening and alerts actually constrain admin protocols and session sprawl.'
      }
    },
    {
      id: 'e-persist-detection',
      source: 'ad-persist',
      target: 'ad-detection',
      data: {
        label: 'Control Coverage',
        type: 'context',
        descriptionMd: 'Persistence classes should be mapped to governance and alerting: GPO change control, PKI auditing, and tier enforcement.'
      }
    },
    {
      id: 'e-detection-report',
      source: 'ad-detection',
      target: 'ad-report',
      data: {
        label: 'Actionability',
        type: 'flow',
        descriptionMd: 'Defensive recommendations and signals belong directly in the report for remediation ownership and retest criteria.'
      }
    }
  ]
};
