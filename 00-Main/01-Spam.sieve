require ["fileinto", "mailbox", "variables", "include"];
global [ "SUSEDE_ADDR", "SUSECOM_ADDR", "BZ_USERNAME" ];

#######################
#####   S P A M   #####
#######################
# Spam

# rule:[Spam]
if allof ( header :contains "X-Spam-Flag" "YES",
           #_____________________________#
           ###    W H I T E L I S T    ###
           #▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔#
           # Important emails I don't want that fall into the SPAM folder
           not anyof ( header  :is "X-List" "vs.openwall.org",
                       address :is "From" "cert+donotreply@cert.org" )) {
           #▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔▔#
    fileinto :create "INBOX/Spam";
    stop;
}
