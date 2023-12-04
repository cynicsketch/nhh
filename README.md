# nhh
A NixOS module applying various changes to improve security.

The decisions made were primarily based on madaidan's insecurities, but not solely.

# GOALS:
Provide sane defaults that should generally avoid breakage, while still improving security in a meaningful way.
Security is a spectrum; common overrides are documented in the module with comments, should a user wish to tweak their 'balance' between performance/usability/security. 

# NON-GOALS:
Performance is generally disregarded (by default). Your system shouldn't slow to a crawl, but in benchmarking you should certainly expect at least some overhead. Particularly hard hitting options can be disabled by user discretion.
The defaults also aren't as restrictive as is optimal for usability reasons, these can also be disabled by user discretion.
Defence against government adversaries is out of scope and out of threat model. 

# TODO:
Implement Lanzaboote, a secure boot implementation for NixOS, when it is mature. 
