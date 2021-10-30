require [ "fileinto", "mailbox", "variables", "include" ];
global [ "SUSEDE_ADDR", "SUSECOM_ADDR", "BZ_USERNAME" ];

#######################
##### G I T H U B #####
#######################
# TOOLS
# └── github
#     └── projects

# rule:[project notifications]
# project related GitHub messages.
if allof ( address :is "From" "notifications@github.com", exists "List-Id" ) { fileinto :create "INBOX/TOOLS/github/projects"; stop; }

# rule:[catch all]
# all other notifications from GitLab end up here.
if allof ( address :is "From" "notifications@github.com" ) { fileinto :create "INBOX/TOOLS/github"; stop; }
