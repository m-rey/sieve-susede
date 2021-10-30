require [ "fileinto", "mailbox", "variables", "include" ];
global [ "SUSEDE_ADDR", "SUSECOM_ADDR", "BZ_USERNAME" ];

#######################
##### NEWS LETTER #####
#######################
# NL
# └── lwn

# rule:[lwn]
# https://lwn.net
if allof ( address :is "From" "lwn@lwn.net",
           address :is "To" "${SUSEDE_ADDR}" ) {
    fileinto :create "INBOX/NL/lwn";
    stop;
}
