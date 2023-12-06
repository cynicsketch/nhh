# nhh
A NixOS module applying various changes to improve security.

"nhh" stands for "NixOS, harder, hardened." Because it's harder than hardened.

The decisions made were primarily based on madaidan's insecurities, but not solely.

# Goals:
Provide sane defaults that should generally avoid breakage, while still improving security in a meaningful way.
Note: Some defaults break hibernate, harm performance significantly, or may cause hardware compatibility issues. It is recommended to read through the comments before applying, to be aware of options you may want to override.
Security is a spectrum; common overrides are documented in the module with comments, should a user wish to tweak their 'balance' between performance/usability/security. 

# Non-goals:
Defence against government adversaries is out of scope and out of threat model. Some changes are relaxed for usability reasons, therefore the defaults aren't necessarily "optimal" for every possible use case; nothing is.


# Usage:
Import "nnh.nix" into your NixOS configuration. To set overrides, edit the module and read the comments. You should read over the comments in the module anyways before you implement it.

# TODO:
Implement Lanzaboote, a secure boot implementation for NixOS, when it is mature. 
Add "proper" configuration, as in settings like "nhh.options.foobar = true;" in configuration.nix, rather than manually editing the module.
