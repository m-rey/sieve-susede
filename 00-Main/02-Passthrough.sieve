require ["fileinto", "body", "mailbox", "variables", "include"];
global [ "SUSEDE_ADDR", "SUSECOM_ADDR", "BZ_USERNAME" ];

#######################
#    N O   S T O P    #
#######################
#######################
# NOTIFY
# └── food
# └── release
#
# CALENDAR

# misc rules that don't stop the filtering after a match

# rule:[notify - free food]
if allof ( address :domain "From" ["suse.com", "suse.de"],
           address :is "To" "maxtorhof@suse.de",
           anyof ( body :contains ["nachtisch", "food", "left over", "leftover", "cake", "sweets", "hungry", "serve yourself"],
                   header :contains "SUBJECT" ["nachtisch", "food", "left over", "leftover", "cake", "sweets", "hungry", "serve yourself"] )) {
    fileinto :create "INBOX/NOTIFY/food";
}

# rule:[notify - github releases]
if header :matches "Message-ID" "<*/*/releases/*@github.com>" { fileinto :create "INBOX/NOTIFY/release"; }

# rule:[calendar]
if body :content "text/calendar" :contains "" { fileinto "INBOX/CALENDAR"; stop; }
