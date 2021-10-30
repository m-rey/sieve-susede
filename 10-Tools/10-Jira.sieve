require [ "fileinto", "mailbox", "variables", "include" ];
global [ "SUSEDE_ADDR", "SUSECOM_ADDR", "BZ_USERNAME" ];

#######################
#####   J I R A   #####
#######################
# TOOLS
# └── jira

# rule:[catch all]
# Notifications from Jira end up here.
if allof ( address :is "From" "jira@suse.com" ) {
    fileinto :create "INBOX/TOOLS/jira";
    stop;
}
