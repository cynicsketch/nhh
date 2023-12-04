# nhh
A NixOS module applying various changes to improve security.

"nhh" stands for "NixOS, harder, hardened." Because it's harder than hardened.

The decisions made were primarily based on madaidan's insecurities, but not solely.

# Goals:
Provide sane defaults that should generally avoid breakage, while still improving security in a meaningful way.
Security is a spectrum; common overrides are documented in the module with comments, should a user wish to tweak their 'balance' between performance/usability/security. 

# Non-goals:
Performance is generally disregarded (by default). Your system shouldn't slow to a crawl, but in benchmarking you should certainly expect at least some overhead. Particularly hard hitting options can be disabled by user discretion.
The defaults also aren't as restrictive as is optimal for usability reasons, these can also be disabled by user discretion.
Defence against government adversaries is out of scope and out of threat model. 

# Usage:
Import "nnh.nix" into your NixOS configuration. To set overrides, edit the module and read the comments. You should read over the comments in the module anyways before you implement it.

# TODO:
Implement Lanzaboote, a secure boot implementation for NixOS, when it is mature. 
Add "proper" configuration, as in settings like "nhh.options.foobar = true;" in configuration.nix, rather than manually editing the module.
