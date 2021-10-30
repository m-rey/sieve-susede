require [ "fileinto", "mailbox", "envelope", "subaddress", "variables", "include" ];
global [ "SUSEDE_ADDR", "SUSECOM_ADDR", "BZ_USERNAME" ];

#######################
##### NEWS LETTER #####
#######################
# NL
# ├── noyb-gdprtoday

# rule:[noyb-gdprtoday]
# https://noyb.eu/en/gdpr-dnes
if address :is "From" "GDPRhub@noyb.eu" { fileinto :create "INBOX/NL/noyb-gdprhub"; stop; }
