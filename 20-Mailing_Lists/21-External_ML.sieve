require [ "fileinto", "mailbox", "variables", "include" ];
global [ "SUSEDE_ADDR", "SUSECOM_ADDR", "BZ_USERNAME" ];

#######################
##### External ML #####
#######################
### OpenSUSE: https://lists.opensuse.org
### Seclist: https://seclists.org/
### Open Source Security Foundation: https://lists.openssf.org/g/mas
#
# ML
# ├── OPENSUSE
# │   ├── factory
# │   ├── users
# │   └── security-announce
# ├── seclist
# │   ├── nmap-nnounce
# │   ├── breach-exchange
# │   ├── fulldisclosure
# │   │   ├── malvuln
# │   │   ├── apple
# │   │   ├── korelogic
# │   │   ├── onapsis
# │   │   ├── asterisk
# │   │   ├── atlassian
# │   │   └── mikrotik
# │   ├── oss-security
# │   │   └── webkit-sa
# │   ├── linux-distro
# │   ├── vince
# │   ├── isn
# │   ├── cert-advisories
# │   └── openssf
# │       ├── announcements
# │       ├── security-threats
# │       ├── security-tooling
# │       ├── vul-disclosure
# │       └── code-best-practices
# ├── debian
# │   ├── security-announce
# │   └── security-tracker
# ├── redhat
# │   ├── security-announce
# │   └── ibm-virt-security
# ├── ubuntu
# │   ├── hardened
# │   ├── security-announce
# │   └── security-patch
# └── security-advisory
#     └── weechat


# rule:[Seclist - nmap announce]
# https://nmap.org/mailman/listinfo/announce
if header :contains "List-Id" "<announce.nmap.org>" { fileinto :create "INBOX/ML/seclist/nmap-announce"; stop; }

# rule:[Seclist - breachexchang]
# https://www.riskbasedsecurity.com/mailing-list/
if header :contains "List-Id" "<breachexchange.lists.riskbasedsecurity.com>" { fileinto :create "INBOX/ML/seclist/breach-exchange"; stop; }

# rule:[Seclist - Full-Disclosure - malvuln]
if allof ( header  :contains "List-Id" "<fulldisclosure.seclists.org>",
           address :is "From" "malvuln13@gmail.com" ) {
    fileinto :create "INBOX/ML/seclist/fulldisclosure/malvuln";
    stop;
}

# rule:[Seclist - Full-Disclosure - apple-sa]
if allof ( header  :contains "List-Id" "<fulldisclosure.seclists.org>",
           address :is "To" "security-announce@lists.apple.com" ) {
    fileinto :create "INBOX/ML/seclist/fulldisclosure/apple";
    stop;
}

# rule:[Seclist - Full-Disclosure - korelogic-sa]
if allof ( header  :contains "List-Id" "<fulldisclosure.seclists.org>",
           address :contains "Reply-To" "disclosures@korelogic.com" ) {
    fileinto :create "INBOX/ML/seclist/fulldisclosure/korelogic";
    stop;
}

# rule:[Seclist - Full-Disclosure - onapsis]
if allof ( header  :contains "List-Id" "<fulldisclosure.seclists.org>",
           address :contains "Reply-To" "research@onapsis.com" ) {
    fileinto :create "INBOX/ML/seclist/fulldisclosure/onapsis";
    stop;
}

# rule:[Seclist - Full-Disclosure - asterisk-sa]
if allof ( header :contains "List-Id" "<fulldisclosure.seclists.org>",
           address :is "From" "security@asterisk.org" ) {
    fileinto :create "INBOX/ML/seclist/fulldisclosure/asterisk";
    stop;
}

# rule:[Seclist - Full-Disclosure - mikrotik-sa]
if allof ( header :contains "List-Id" "<fulldisclosure.seclists.org>",
           header :contains "Subject" "mikrotik" ) {
    fileinto :create "INBOX/ML/seclist/fulldisclosure/mikrotik";
    stop;
}

# rule:[Seclist - Full-Disclosure - atlassian]
if allof ( header :contains "List-Id" "<fulldisclosure.seclists.org>",
           address :is "From" "security@atlassian.com" ) {
    fileinto :create "INBOX/ML/seclist/fulldisclosure/atlassian";
    stop;
}

# rule:[Seclist - oss-security - WebKit]
if allof ( header :contains "List-Id" "<oss-security.lists.openwall.com>",
           header :contains "Subject" "WebKit Security Advisory" ) {
    fileinto :create "INBOX/ML/seclist/oss-security/webkit-sa";
    stop;
}

# rule:[Seclist - linux-distro]
# https://oss-security.openwall.org/wiki/mailing-lists/distros
if header :is "X-List" "vs.openwall.org" { fileinto :create "INBOX/ML/seclist/linux-distro"; stop; }

# rule:[Seclist - VINCE]
# https://kb.cert.org/vince/comm/auth/login/
if address :is "From" "cert+donotreply@cert.org" { fileinto :create "INBOX/ML/seclist/vince"; stop; }

# rule:[Seclist - CERT]
# https://public.govdelivery.com/accounts/USDHSCISA/subscriber/edit?preferences=true#tab1
if allof ( address :is "To" "${SUSEDE_ADDR}",
           anyof ( address :contains "From" "US-CERT@ncas.us-cert.gov",
                   address :contains "From" "CISA@public.govdelivery.com",
                   address :contains "From" "cisacommunity@ncas.us-cert.gov" )) {
    fileinto :create "INBOX/ML/seclist/cert-advisories";
    stop;
}

# rule:[Debian - security tracker mute bot]
if allof ( header :contains "List-Id" "<debian-security-tracker.lists.debian.org>",
           address :contains "From" "sectracker@soriano.debian.org") {
    discard;
    stop;
}

# rule:[RedHat - security announce]
# https://listman.redhat.com/mailman/listinfo/rhsa-announce
if header :contains "List-Id" "<rhsa-announce.redhat.com>" { fileinto :create "INBOX/ML/redhat/security-announce"; stop; }

# rule:[weechat - SA]
# https://lists.nongnu.org/mailman/listinfo/weechat-security
if header :contains "List-Id" "<weechat-security.nongnu.org>" { fileinto :create "INBOX/ML/security-advisory/weechat"; stop; }

# rule:[openSUSE - catch all]
if header :matches "List-Id" "*<*.lists.opensuse.org>" {
    set :lower "ML_NAME" "${2}";
    fileinto :create "INBOX/ML/opensuse/${ML_NAME}";
    stop;
}

# rule:[openSSF - catch all]
if header :matches "List-Id" ["*<openssf-wg-*.lists.openssf.org>", "*<openssf-*.lists.openssf.org>"] {
    set :lower "ML_NAME" "${2}";
    fileinto :create "INBOX/ML/openssf/${ML_NAME}";
    stop;
}

# rule:[Debian - catch all]
if header :matches "List-Id" ["*<debian-*.lists.debian.org>", "*<*.lists.debian.org>"] {
    set :lower "ML_NAME" "${2}";
    fileinto :create "INBOX/ML/debian/${ML_NAME}";
    stop;
}

# rule:[Ubuntu - catch all]
if header :matches "List-Id" ["*<ubuntu-*.lists.ubuntu.com>", "*<*.lists.ubuntu.com>"] {
    set :lower "ML_NAME" "${2}";
    fileinto :create "INBOX/ML/ubuntu/${ML_NAME}";
    stop;
}

# rule:[seclists,infosecnews,openwall - catch all]
if header :matches "List-Id" ["*<*.lists.infosecnews.org>", "*<*.seclists.org>", "*<*.lists.openwall.com>"] {
    set :lower "ML_NAME" "${2}";
    fileinto :create "INBOX/ML/seclist/${ML_NAME}";
    stop;
}

# rule:[sourcehut - catch user ML]
if header :matches "List-Id" "*<~*/*@lists.sr.ht>" {
    set :lower "ML_USER_NAME" "${2}";
    set :lower "ML_NAME" "${3}";
    fileinto :create "INBOX/ML/sourcehut/${ML_USER_NAME}/${ML_NAME}" ;
    stop;
}
