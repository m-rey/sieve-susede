require ["fileinto", "body", "mailbox", "variables", "include"];
global [ "SUSEDE_ADDR", "SUSECOM_ADDR", "BZ_USERNAME" ];

#######################
#   R E D I R E C T   #
#######################
#######################
# redirect emails

# rule:[redirect appointments calendar]
if allof ( exists "x-ms-exchange-calendar-series-instance-id",
           not header :contains "X-MS-Exchange-ForwardingLoop" "${SUSECOM_ADDR}" ) {
    redirect "${SUSEDE_ADDR}";
    discard;
    stop;
}

