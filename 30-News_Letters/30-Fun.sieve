require [ "fileinto", "mailbox", "envelope", "subaddress", "variables", "include" ];
global [ "SUSEDE_ADDR", "SUSECOM_ADDR", "BZ_USERNAME" ];

#######################
##### NEWS LETTER #####
#######################
# NL
# └── techloaf

# rule:[techloaf]
# https://subscribe.techloaf.io
if address :is "From" "hello@techloaf.io" { fileinto :create "INBOX/NL/techloaf"; stop; }
