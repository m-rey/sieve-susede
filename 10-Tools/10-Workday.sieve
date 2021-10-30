require [ "fileinto", "mailbox", "variables", "include" ];
global [ "SUSEDE_ADDR", "SUSECOM_ADDR", "BZ_USERNAME" ];

#######################
###  W O R K D A Y  ###
#######################
# TOOLS
# └── workday
#     └── projects

# rule:[workday notifications]
# project related GitHub messages.
if allof ( address :is "From" "suse@myworkday.com" ) { fileinto :create "INBOX/TOOLS/workday"; stop; }
