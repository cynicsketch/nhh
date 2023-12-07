# nhh
A NixOS module applying various changes to improve security.

"nhh" stands for "NixOS, harder, hardened." Because it's harder than hardened.

The decisions made were primarily based on madaidan's insecurities, but not solely.

# Goals:
Provide sane defaults that should generally should be applicable to many different setups, while still improving security in a meaningful way.
Security is a spectrum; common overrides are documented in the module with comments, should a user wish to tweak their 'balance' between performance/usability/security. 

# Non-goals:
Defence against government adversaries is out of scope and out of threat model. Some changes are relaxed for usability reasons, therefore the defaults aren't necessarily "optimal" for every possible use case; nothing is. Anonymity is not a goal.


# Usage:
Import "nnh.nix" into your NixOS configuration. To set overrides, edit the module and read the comments. You should read over the comments in the module anyways before you implement it.
Notable things broken (by default): Hibernation is disabled by several changes, performance is impacted negatively by varying amounts depending on the system. These can be overrided.

# TODO:
Implement Lanzaboote, a secure boot implementation for NixOS, when it is mature. 
Add "proper" configuration, as in settings like "nhh.options.foobar = true;" in configuration.nix, rather than manually editing the module.
Implement "statelessness" to revert changes to root after reboot. Not *cryptographically* secure like a "verified boot" implementation, but better than nothing.
