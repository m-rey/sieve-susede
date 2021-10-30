require [ "fileinto", "mailbox", "variables", "include" ];
global [ "SUSEDE_ADDR", "SUSECOM_ADDR", "BZ_USERNAME" ];

########################
#####  CONFLUENCE  #####
########################
# TOOLS
# └── confluence

# rule:[catch all]
# Notifications from Confluence end up here.
if allof ( address :is "From" "confluence@suse.com" ) {
    fileinto :create "INBOX/TOOLS/confluence";
    stop;
}
