require [ "fileinto", "mailbox", "body", "variables", "include", "envelope", "subaddress" ];
global [ "SUSEDE_ADDR", "SUSECOM_ADDR", "BZ_USERNAME" ];

#######################
##### Internal ML #####
#######################
### SUSEDE: https://mailman.suse.de/mailman/listinfo
### SUSECOM: http://lists.suse.com/mailman/listinfo
#
# ML
# └── SUSE
#     ├── security-team
#     │   ├── xorg
#     │   └── samba
#     ├── security
#     │   ├── xen
#     │   │   └── security-advisory
#     │   ├── mariadb
#     │   ├── django
#     │   ├── ceph
#     │   ├── kubernetes
#     │   ├── qemu
#     │   ├── cloud-foundry
#     │   └── mitre
#     │       ├── suse-cna
#     │       └── cve-cna
#     ├── maintsecteam
#     │   ├── maintenance-wr
#     │   ├── workreport
#     │   └── smash-smelt
#     ├── security-reports
#     │   ├── embargo-alerts
#     │   └── chromium
#     ├── devel
#     ├── high-impact-vul
#     ├── high-impact-vul-info
#     ├── kernel
#     ├── linux
#     ├── maint-coord
#     ├── maintsec-reports
#     │   └── channels-changes
#     ├── research
#     ├── results
#     ├── secure-boot
#     ├── secure-devel
#     ├── security-intern
#     ├── security-review
#     ├── sle-security-updates
#     │   ├── container
#     │   └── image
#     └── users

# rule:[maintsecteam - Maintenance_Weekly-Report]
if allof ( header :contains "List-Id" "<maintsecteam.suse.de>",
           address :is "From" "maint-coord@suse.de",
           # The subject contains ( Maintenance && Weekly Report )
           header :contains "Subject" "Maintenance",
           header :contains "Subject" "Weekly Report" ) {
    fileinto :create "INBOX/ML/SUSE/maintsecteam/maintenance-wr";
    stop;
}

# rule:[maintsecteam - workreports]
if allof ( header :contains "List-Id" "<maintsecteam.suse.de>",
           # The subject contains ( workreport || (work && report) )
           anyof ( header :contains "Subject" "workreport",
                   allof ( header :contains "Subject" "work",
                           header :contains "Subject" "report" ))) {
    fileinto :create "INBOX/ML/SUSE/maintsecteam/workreport";
    stop;
}

# rule:[maintsecteam - SMESH-SMELT_Releases]
if allof ( header :contains "List-Id" "<maintsecteam.suse.de>",
           # The subject contains ( release && (smash || smelt) )
           allof ( header :contains "Subject" "release",
                   anyof ( header :contains "Subject" "smash",
                           header :contains "Subject" "smelt" ))) {
    fileinto :create "INBOX/ML/SUSE/maintsecteam/smash-smelt";
    stop;
}

# rule:[maintsec-reports - channel file changed]
# Note: it seems that only SLE12 changes are sent over this ML.
if allof ( header :contains "List-Id" "<maintsec-reports.suse.de>",
           header :contains "Subject" "Channel changes for" ) {
    fileinto :create "INBOX/ML/SUSE/maintsec-reports/channels-changes";
    stop;
}

# rule:[security - redhat noise]
# Remove all the noise made by the RH ServiceNow instance
if allof ( header :contains "List-Id" "<security.suse.de>",
           header :is "X-ServiceNow-Generated" "true",
           anyof ( address :is "From" "secalert@redhat.com",
                   address :is "From" "infosec@redhat.com" )) {
    fileinto :create "INBOX/Trash";
    stop;
}

# rule:[security - XSA]
if allof ( header :contains "List-Id" "<security.suse.de>",
           address :is "From" "security@xen.org" ) {
    fileinto :create "INBOX/ML/SUSE/security/xen/security-advisory";
    stop;
}

# rule:[security - Xen]
if allof ( header :contains "List-Id" "<security.suse.de>",
           header :is "X-BeenThere" "xen-security-issues-discuss@lists.xenproject.org" ) {
    fileinto :create "INBOX/ML/SUSE/security/xen";
    stop;
}

# rule:[security - Ceph]
if allof ( header :contains "List-Id" "<security.suse.de>",
           anyof ( address :is "CC" "security@ceph.io",
                   address :is "To" "security@ceph.io" )) {
    fileinto :create "INBOX/ML/SUSE/security/ceph";
    stop;
}

# rule:[security - MariaDB]
if allof ( header :contains "List-Id" "<security.suse.de>",
           address :is "From" "announce@mariadb.org") {
    fileinto :create "INBOX/ML/SUSE/security/mariadb";
    stop;
}

# rule:[security - Django]
if allof ( header :contains "List-Id" "<security.suse.de>",
           header :contains "Subject" "Django security releases") {
    fileinto :create "INBOX/ML/SUSE/security/django";
    stop;
}

# rule:[security - Kubernetes]
if allof ( header :contains "List-Id" "<security.suse.de>",
           address :contains "To" "@kubernetes.io") {
    fileinto :create "INBOX/ML/SUSE/security/kubernetes";
    stop;
}

# rule:[security - Cloud Foundry]
if allof ( header :contains "List-Id" "<security.suse.de>",
           envelope :domain :is "From" "cloudfoundry.org") {
    fileinto :create "INBOX/ML/SUSE/security/cloud-foundry";
    stop;
}

# rule:[security - Mitre SUSE CNA report]
if allof ( header :contains "List-Id" "<security.suse.de>",
           header :is "From" "cna-coordinator@mitre.org",
           header :contains "Subject" "suse CNA Report") {
    fileinto :create "INBOX/ML/SUSE/security/mitre/suse-cna";
    stop;
}

# rule:[security - Mitre CVE-CNA]
if allof ( header :contains "List-Id" "<security.suse.de>",
           anyof ( envelope :domain :is "From" "mitre.org",
                   header :contains "X-Envelope-To" "@mitre.org" )) {
    fileinto :create "INBOX/ML/SUSE/security/mitre/cve-cna";
    stop;
}

# rule:[security - qemu security]
# https://lists.nongnu.org/mailman/listinfo/qemu-security
if header :contains "List-Id" "<qemu-security.nongnu.org>" { fileinto :create "INBOX/ML/SUSE/security/qemu"; stop; }

# rule:[security-reports - Embargo Alerts]
if allof ( header :contains "List-Id" "<security-reports.suse.de>",
           header :contains "Subject" "EMBARGOED ISSUE MENTIONED IN" ) {
    fileinto :create "INBOX/ML/SUSE/security-reports/embargo-alerts";
    stop;
}

# rule:[security-reports - Embargo date missing]
if allof ( header :contains "List-Id" "<security-reports.suse.de>",
           header :contains "Subject" "OBS:EmbargoDate not set for" ) {
    fileinto :create "INBOX/ML/SUSE/security-reports/embargo-alerts";
    stop;
}

# rule:[security-reports - Chromium Releases]
if allof ( header :contains "List-Id" "<security-reports.suse.de>",
           header :contains "Subject" "Chromium Stable" ) {
    fileinto :create "INBOX/ML/SUSE/security-reports/chromium";
    stop;
}

# rule:[security-team - no US-CERT]
# Discard newsletters coming US-CERT because these are duplicated for me as I'm already subscribed to that list
# ML -> SecList -> CERT Advisories
if allof ( header :contains "List-Id" "<security-team.suse.de>",
           address :is "From" "US-CERT@ncas.us-cert.gov" ) {
    discard;
    stop;
}

# rule:[security-team - xorg-security ML]
if allof ( header :contains "List-Id"  "<security-team.suse.de>",
           header :contains "X-BeenThere" "xorg-security@lists.x.org" ) {
    fileinto :create "INBOX/ML/SUSE/security-team/xorg";
    stop;
}

# rule:[security-team - Samba ML]
if allof ( header :contains "List-Id" "<security-team.suse.de>",
           header :contains "From" "samba-bugs@samba.org" ) {
    fileinto :create "INBOX/ML/SUSE/security-team/samba";
    stop;
}

# rule:[security-team - security-team and me in CC ]
# When someone follows up on a thread where I'm also in CC, I want it in the same ML folder
if allof (     address :contains "CC" "security-team@suse.de",
               address :contains "CC" "${SUSEDE_ADDR}",
           not address :contains "To" "${SUSEDE_ADDR}" ) {
    fileinto :create "INBOX/ML/SUSE/security-team";
    stop;
}

# rule:[sle-security-updates - containers]
if allof ( header :contains "List-Id" "<sle-security-updates.lists.suse.com>",
           body :contains "SUSE Container Update Advisory" ) {
    fileinto :create "INBOX/ML/SUSE/sle-security-updates/container";
    stop;
}

# rule:[sle-security-updates - images]
if allof ( header :contains "List-Id" "<sle-security-updates.lists.suse.com>",
           body :contains "SUSE Image Update Advisory" ) {
    fileinto :create "INBOX/ML/SUSE/sle-security-updates/image";
    stop;
}

# rule:[catch all *.lists.suse.com]
if header :matches "List-Id" "*<*.lists.suse.com>" {
    set :lower "ML_NAME" "${2}";
    fileinto :create "INBOX/ML/SUSE/suse-${ML_NAME}";
    stop;
}

# rule:[catch all *.suse.de]
# default rule for remaining internal MLs
if header :matches "List-Id" "*<*.suse.de>" {
    set :lower "ML_NAME" "${2}";
    fileinto :create "INBOX/ML/SUSE/${ML_NAME}";
    stop;
}
