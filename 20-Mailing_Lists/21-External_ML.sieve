require [ "fileinto", "mailbox" ];

#######################
##### External ML #####
#######################
### OpenSUSE: https://lists.opensuse.org
### Seclist: https://seclists.org/
### Open Source Security Foundation: https://lists.openssf.org/g/mas
#
# ML
# ├── OpenSUSE
# │   ├── factory
# │   ├── users
# │   └── security announce
# ├── SecList
# │   ├── Nmap Announce
# │   ├── Breach Exchange
# │   ├── Full Disclosure
# │   │   ├── malvuln
# │   │   ├── apple
# │   │   ├── korelogic
# │   │   ├── onapsis
# │   │   ├── asterisk
# │   │   ├── atlassian
# │   │   └── mikrotik
# │   ├── Open Source Security
# │   │   └── WebKit SA
# │   ├── linux-distro
# │   ├── vince
# │   ├── Info Security News
# │   ├── CERT Advisories
# │   └── OpenSSF
# │       ├── Announcements
# │       ├── Security Threats
# │       ├── Security Tooling
# │       ├── Vul Disclosure
# │       └── Code Best Practices
# ├── Debian
# │   ├── Security Announce
# │   └── Security Tracker
# ├── RedHat
# │   ├── Security Announce
# │   └── IBM Virt Security
# ├── Ubuntu
# │   ├── Hardened
# │   ├── Security Announce
# │   └── Security Patch
# ├── Italian
# │   └── GNU Translation
# └── Security Advisory
#     └── Weechat

# rule:[OpenSUSE - factory]
# https://lists.opensuse.org/archives/list/factory@lists.opensuse.org/
if header :contains "List-Id" "<factory.lists.opensuse.org>" { fileinto :create "INBOX/ML/OpenSUSE/factory"; stop; }

# rule:[OpenSUSE - users]
# https://lists.opensuse.org/archives/list/users@lists.opensuse.org/
if header :contains "List-Id" "<users.lists.opensuse.org>" { fileinto :create "INBOX/ML/OpenSUSE/users"; stop; }

# rule:[OpenSUSE - security-announce]
# https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/
if header :contains "List-Id" "<security-announce.lists.opensuse.org>" { fileinto :create "INBOX/ML/OpenSUSE/security announce"; stop; }

# rule:[Seclist - nmap announce]
# https://nmap.org/mailman/listinfo/announce
if header :contains "List-Id" "<announce.nmap.org>" { fileinto :create "INBOX/ML/SecList/Nmap Announce"; stop; }

# rule:[Seclist - breachexchang]
# https://www.riskbasedsecurity.com/mailing-list/
if header :contains "List-Id" "<breachexchange.lists.riskbasedsecurity.com>" { fileinto :create "INBOX/ML/SecList/Breach Exchange"; stop; }

# rule:[Seclist - Full-Disclosure - malvuln]
if allof ( header  :contains "List-Id" "<fulldisclosure.seclists.org>",
           address :is "From" "malvuln13@gmail.com" ) {
    fileinto :create "INBOX/ML/SecList/Full Disclosure/malvuln"; 
    stop;
}
# rule:[Seclist - Full-Disclosure - apple-sa]
if allof ( header  :contains "List-Id" "<fulldisclosure.seclists.org>",
           address :is "To" "security-announce@lists.apple.com" ) {
    fileinto :create "INBOX/ML/SecList/Full Disclosure/apple"; 
    stop;
}
# rule:[Seclist - Full-Disclosure - korelogic-sa]
if allof ( header  :contains "List-Id" "<fulldisclosure.seclists.org>",
           address :contains "Reply-To" "disclosures@korelogic.com" ) {
    fileinto :create "INBOX/ML/SecList/Full Disclosure/korelogic"; 
    stop;
}
# rule:[Seclist - Full-Disclosure - onapsis]
if allof ( header  :contains "List-Id" "<fulldisclosure.seclists.org>",
           address :contains "Reply-To" "research@onapsis.com" ) {
    fileinto :create "INBOX/ML/SecList/Full Disclosure/onapsis"; 
    stop;
}
# rule:[Seclist - Full-Disclosure - asterisk-sa]
if allof ( header  :contains "List-Id" "<fulldisclosure.seclists.org>",
           address :is "From" "security@asterisk.org" ) {
    fileinto :create "INBOX/ML/SecList/Full Disclosure/asterisk"; 
    stop;
}
# rule:[Seclist - Full-Disclosure - mikrotik-sa]
if allof ( header  :contains "List-Id" "<fulldisclosure.seclists.org>",
           header :contains "Subject" "mikrotik" ) {
    fileinto :create "INBOX/ML/SecList/Full Disclosure/mikrotik"; 
    stop;
}
# rule:[Seclist - Full-Disclosure - atlassian]
if allof ( header  :contains "List-Id" "<fulldisclosure.seclists.org>",
           address :is "From" "security@atlassian.com" ) {
    fileinto :create "INBOX/ML/SecList/Full Disclosure/atlassian";
    stop;
}
# rule:[Seclist - Full-Disclosure]
# https://nmap.org/mailman/listinfo/fulldisclosure
if header :contains "List-Id" "<fulldisclosure.seclists.org>" { fileinto :create "INBOX/ML/SecList/Full Disclosure"; stop; }

# rule:[Seclist - oss-security - WebKit]
if allof ( header  :contains "List-Id" "<oss-security.lists.openwall.com>",
           header  :contains "Subject" "WebKit Security Advisory" ) {
    fileinto :create "INBOX/ML/SecList/Open Source Security/WebKit SA";
    stop;
}
# rule:[Seclist - oss-security]
# http://oss-security.openwall.org/wiki/mailing-lists/oss-security
if header :contains "List-Id" "<oss-security.lists.openwall.com>" { fileinto :create "INBOX/ML/SecList/Open Source Security"; stop; }

# rule:[Seclist - linux-distro]
# https://oss-security.openwall.org/wiki/mailing-lists/distros
if header :is "X-List" "vs.openwall.org" { fileinto :create "INBOX/ML/SecList/linux-distro"; stop; }

# rule:[Seclist - VINCE]
# https://kb.cert.org/vince/comm/auth/login/
if address :is "From" "cert+donotreply@cert.org" { fileinto :create "INBOX/ML/SecList/vince"; stop; }

# rule:[Seclist - infosecnews]
# http://lists.infosecnews.org/mailman/listinfo/isn_lists.infosecnews.org
if header :contains "List-Id" "<isn.lists.infosecnews.org>" { fileinto :create "INBOX/ML/SecList/Info Security News"; stop; }

# rule:[Seclist - CERT]
# https://public.govdelivery.com/accounts/USDHSCISA/subscriber/edit?preferences=true#tab1
if allof ( address :is "To" "${susede_addr}",
           anyof ( address :contains "From" "US-CERT@ncas.us-cert.gov",
                   address :contains "From" "CISA@public.govdelivery.com",
                   address :contains "From" "cisacommunity@ncas.us-cert.gov" )) {
    fileinto :create "INBOX/ML/SecList/CERT Advisories";
    stop;
}

# rule:[openSSF - Announcements]
# https://lists.openssf.org/g/openssf-announcements
if header :contains "List-Id" "<openssf-announcements.lists.openssf.org>" { fileinto :create "INBOX/ML/OpenSSF/Announcements"; stop; }

# rule:[openSSF - Security threats]
# https://lists.openssf.org/g/openssf-wg-security-threats
if header :contains "List-Id" "<openssf-wg-security-threats.lists.openssf.org>" { fileinto :create "INBOX/ML/OpenSSF/Security Threats"; stop; }

# rule:[openSSF - Security tools]
# https://lists.openssf.org/g/openssf-wg-security-tooling
if header :contains "List-Id" "<openssf-wg-security-tooling.lists.openssf.org>" { fileinto :create "INBOX/ML/OpenSSF/Security Tooling"; stop; }

# rule:[openSSF - Vulnerability disclosures]
# https://lists.openssf.org/g/openssf-wg-vul-disclosures
if header :contains "List-Id" "<openssf-wg-vul-disclosures.lists.openssf.org>" { fileinto :create "INBOX/ML/OpenSSF/Vul Disclosures"; stop; }

# rule:[openSSF - Secure code best practices]
# https://lists.openssf.org/g/openssf-wg-best-practices
if header :contains "List-Id" "<openssf-wg-best-practices.lists.openssf.org>" { fileinto :create "INBOX/ML/OpenSSF/Code Best Practices"; stop; }

# rule:[Debian - security tracker mute bot]
if allof ( header :contains "List-Id" "<debian-security-tracker.lists.debian.org>",
           address :contains "From" "sectracker@soriano.debian.org") {
    discard;
    stop;
}
# rule:[Debian - security tracker]
# https://lists.debian.org/debian-security-tracker/
if header :contains "List-Id" "<debian-security-tracker.lists.debian.org>" { fileinto :create "INBOX/ML/Debian/Security Tracker"; stop; }

# rule:[Debian - security announce]
# https://lists.debian.org/debian-security-announce/
if header :contains "List-Id" "<debian-security-announce.lists.debian.org>" { fileinto :create "INBOX/ML/Debian/Security Announce"; stop; }

# rule:[RedHat - security announce]
# https://listman.redhat.com/mailman/listinfo/rhsa-announce
if header :contains "List-Id" "<rhsa-announce.redhat.com>" { fileinto :create "INBOX/ML/RedHat/Security Announce"; stop; }

# rule:[RedHat - security announce]
# https://listman.redhat.com/mailman/listinfo/ibm-virt-security
if header :contains "List-Id" "<ibm-virt-security.lists.debian.org>" { fileinto :create "INBOX/ML/Debian/IBM Virt Security"; stop; }

# rule:[Ubuntu - security announce]
# https://lists.ubuntu.com/mailman/listinfo/ubuntu-security-announce
if header :contains "List-Id" "<ubuntu-security-announce.lists.ubuntu.com>" { fileinto :create "INBOX/ML/Ubuntu/Security Announce"; stop; }

# rule:[Ubuntu - security patch]
# https://lists.ubuntu.com/mailman/listinfo/ubuntu-security-patch
if header :contains "List-Id" "<ubuntu-security-patch.lists.ubuntu.com>" { fileinto :create "INBOX/ML/Ubuntu/Security Patch"; stop; }

# rule:[Ubuntu - hardened]
# https://lists.ubuntu.com/mailman/listinfo/ubuntu-hardened
if header :contains "List-Id" "<ubuntu-hardened.lists.ubuntu.com>" { fileinto :create "INBOX/ML/Ubuntu/Hardened"; stop; }

# rule:[Italian - GNU Translation]
# https://lists.gnu.org/mailman/listinfo/www-it-traduzioni
if header :contains "List-Id" "<www-it-traduzioni.gnu.org>" { fileinto :create "INBOX/ML/Italian/GNU Translation"; stop; }

# rule:[SA - weechat]
# https://lists.nongnu.org/mailman/listinfo/weechat-security
if header :contains "List-Id" "<weechat-security.nongnu.org>" { fileinto :create "INBOX/ML/Security Advisory/Weechat"; stop; }