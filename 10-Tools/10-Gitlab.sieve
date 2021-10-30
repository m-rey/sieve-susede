require [ "fileinto", "mailbox", "variables", "include" ];
global [ "SUSEDE_ADDR", "SUSECOM_ADDR", "BZ_USERNAME" ];

#######################
##### G I T L A B #####
#######################
# TOOLS
# └── gitlab
#     └── projects

# rule:[project notifications]
# project related GitLab messages.
if allof ( address :is "From" "gitlab@suse.de",
           exists "X-GitLab-Project-Path" ) {
    fileinto :create "INBOX/TOOLS/gitlab/projects";
    stop;
}

# rule:[catch all]
# all other notifications from GitLab end up here.
if allof ( address :is "From" "gitlab@suse.de" ) {
    fileinto :create "INBOX/TOOLS/gitlab";
    stop;
}
