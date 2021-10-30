require [ "fileinto", "mailbox", "variables", "include" ];
global [ "SUSEDE_ADDR", "SUSECOM_ADDR", "BZ_USERNAME" ];

#######################
##### generic ML  #####
#######################
# experimental

# rule:[*.lists.*.* - catch all]
if header :matches "List-Id" "*<*.lists.*.*>" {
    set :lower "ML_NAME" "${2}";
    set :lower "ML_SITE_NAME" "${3}";
    fileinto :create "INBOX/ML/${ML_SITE}/${ML_SITE_NAME}" ;
    stop;
}

# rule:[X-Mailinglist]
if header :matches "X-Mailinglist" "*" {
    set :lower "ML_NAME" "${1}";
    fileinto :create "INBOX/ML/${ML_NAME}";
    stop;
}
