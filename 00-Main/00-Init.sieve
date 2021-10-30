# Sieve: https://tools.ietf.org/html/rfc5228
require [ "variables", "include" ];

global [ "SUSEDE_ADDR", "SUSECOM_ADDR", "BZ_USERNAME" ];
set "SUSEDE_ADDR" "mrey@suse.de";
set "SUSECOM_ADDR" "mrey@suse.com";
set "BZ_USERNAME" "mrey";

include :personal "01-Spam.sieve";
include :personal "02-Passthrough.sieve";
include :personal "03-Redirect.sieve";

# Internal tools notification
include :personal "10-Bugzilla.sieve";
include :personal "10-Confluence.sieve";
include :personal "10-Github.sieve";
include :personal "10-Gitlab.sieve";
include :personal "10-IBS.sieve";
include :personal "10-Jira.sieve";
include :personal "10-OBS.sieve";
include :personal "10-Workday.sieve";

# Mailing Lists
include :personal "20-Internal_ML.sieve";
include :personal "21-External_ML.sieve";

# News Letters
include :personal "30-Linux.sieve";
include :personal "30-Fun.sieve";
include :personal "30-GDPR.sieve";

# End Rules
include :personal "90-Generic_ML.sieve";
