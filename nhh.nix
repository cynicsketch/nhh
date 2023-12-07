# Primarily sourced was madaidan's Linux Hardening Guide. See for details: 
# URL: https://madaidans-insecurities.github.io/guides/linux-hardening.html
# Archive: https://web.archive.org/web/20220320000126/https://madaidans-insecurities.github.io/guides/linux-hardening.html 

# Additionally sourced is privsec's Desktop Linux Hardening:
# URL: https://privsec.dev/posts/linux/desktop-linux-hardening/
# Archive: Latest version not yet indexed by archive.org.

# Some configuration used was from Kicksecure's security-misc repository:
# URL: https://github.com/Kicksecure/security-misc

# Some configuration used was also from GrapheneOS server infrastructure:
# URL: https://github.com/GrapheneOS/infrastructure

# Sections from madaidan's guide that are IRRELEVANT/NON-APPLICABLE:
# 1. (Advice)
# 2.1 (Advice)
# 2.3.3 (Advice)
# 2.5.1 (Advice)
# 2.5.3 (Advice)
# 2.6 (Advice)
# 2.10 (Package is broken)
# 7 (Advice)
# 10.5.4 (The problem of NTP being unencrypted is fixed by using NTS instead.)
# 15 (Implemented by default)
# 16 (Not needed with MAC spoofing)
# 19 (Advice)
# 20 (Not relevant)
# 21.7 (Advice, not in threat model)
# 22 (Advice)

# Sections from madaidan's guide requiring manual user intervention:
# 2.4 (Significant breakage)
# 2.7 (systemd service hardening must be done manually)
# 2.9 (Paid software)
# 2.11 (Unique for all hardware, inconvenient)
# 4 (Sandboxing must be done manually)
# 6 (Compiling everything is inconvenient)
# 8.6 (No option, not for all systems)
# 8.7 (Inconvenient, depends on specific user behavior)
# 10.1 (Up to user to determine hostname and username)
# 10.2 (Up to user to determine timezone, local, and keymap)
# 10.5.3 (Not packaged)
# 10.6 (Not packaged, inconvenient and not within threat model)
# 11 (No option, NixOS doesn't obey FHS)
# 21.1 (Out of scope)
# 21.2 (See above)
# 21.3 (User's job to set passwords)
# 21.3.1 (See above)
# 21.3.2 (See above)
# 21.3.3 (See above)
# 21.4 (Non-declarative setup, experimental)

({ config, lib, pkgs, ... }:
(with lib; {
  boot = {
   kernel = {
      sysctl = {
        "dev.tty.ldisc_autoload" = "0";
        "fs.protected_fifos" = "2";
        "fs.protected_hardlinks" = "1";
        "fs.protected_regular" = "2";
        "fs.protected_symlinks" = "1";
        "fs.suid_dumpable" = "0";
        "kernel.dmesg_restrict" = "1";
        "kernel.kexec_load_disabled" = "1";
        "kernel.kptr_restrict" = "2";
        "kernel.perf_event_paranoid" = "3";
        "kernel.printk" = "3 3 3 3";
        "kernel.sysrq" = "0"; # Disables magic sysrq key. Set to 4 to use the
        # Secure Attention Key if that is useful to you, but most people won't.
        "kernel.unprivileged_bpf_disabled" = "1";
        "kernel.unprivileged_userns_clone" = "1"; # NOTABLE REGRESSION!!!
        # Unprivileged userns has a large attack surface and has been the cause
        # of many privilege escalation vulnerabilities Set to 0 if you don't
        # need it. The reason this isn't done by default is because it breaks
        # rootless podman, Flatpak, and other tools using the feature.
        "kernel.yama.ptrace_scope" = "1"; # NOTABLE REGRESSION!!!
        # Yama restricts ptrace, which allows processes to read and modify the
        # memory of other processes. Which has obvious security implications.
        # Set to 1 to restrict ptrace, so only child processes may be ptraced.
        # Setting to 2 restricts ptrace to require admin privileges.
        # Setting to 3 disables ptrace altogether. 
        # If possible, set to 2, or optimally 3, to further restrict. 
        "net.core.bpf_jit_harden" = "2";
        "net.ipv4.conf.all.accept_redirects" = "0";
        "net.ipv4.conf.all.accept_source_route" = "0";
        "net.ipv4.conf.all.rp_filter" = "1";
        "net.ipv4.conf.all.secure_redirects" = "0";
        "net.ipv4.conf.all.send_redirects" = "0";
        "net.ipv4.conf.default.accept_redirects" = "0";
        "net.ipv4.conf.default.accept_source_route" = "0";
        "net.ipv4.conf.default.rp_filter" = "1";
        "net.ipv4.conf.default.secure_redirects" = "0";
        "net.ipv4.conf.default.send_redirects" = "0";
        "net.ipv4.icmp_echo_ignore_all" = "1";
        "net.ipv4.tcp_dsack" = "0";
        "net.ipv4.tcp_fack" = "0";
        "net.ipv4.tcp_rfc1337" = "1";
        "net.ipv4.tcp_sack" = "0";
        "net.ipv4.tcp_syncookies" = "1";
        "net.ipv4.tcp_timestamps" = "0";
        "net.ipv6.conf.all.accept_ra" = "0";
        "net.ipv6.conf.all.accept_redirects" = "0";
        "net.ipv6.conf.all.accept_source_route" = "0";
        "net.ipv6.conf.default.accept_redirects" = "0";
        "net.ipv6.conf.default.accept_source_route" = "0";
        "net.ipv6.default.accept_ra" = "0";
        "syskernel.core_pattern" = "|/bin/false";
        "vm.mmap_rnd_bits" = "32";
        "vm.mmap_rnd_compat_bits" = "16";
        "vm.swappiness" = "1";
        "vm.unprivileged_userfaultfd" = "0";
      };
    };
    kernelPackages = (pkgs).linuxPackages_hardened; # linux_hardened patchset
    # breaks hibernation. Hibernation is only important on battery operated
    # systems.
    kernelParams = [
      ("slab_nomerge")
      ("init_on_alloc=1")
      ("init_on_free=1")
      ("page_alloc.shuffle=1")
      ("pti=on") # Mitigates Meltdown, some KASLR bypasses. Hurts performance.
      ("randomize_kstack_offset=on")
      ("extra_latent_entropy") # Gather more entropy on boot. Only works with
      # linux_hardened patchset.
      ("vsyscall=none")
      ("debugfs=off")
      ("oops=panic")
      ("module.sig_enforce=1") # Requires all kernel modules to be signed. This
      # prevents out-of-tree kernel modules from working unless signed, incl.
      # DKMS, so some drivers, such as Nvidia and VirtualBox drivers, may need
      # to be signed.
      ("lockdown=confidentiality") # May break some drivers, same reason as the
      # above. Also breaks hibernation. Hibernation is only useful on battery
      # operated systems.
      ("quiet")
      ("loglevel=0")
      ("random.trust_cpu=off")
      ("random.trust_bootloader=off")
      ("intel_iommu=on")
      ("amd_iommu=force_isolation")
      ("iommu=force")
      ("iommu.passthrough=0") # GPU passthrough to VMs will not work with this.
      ("iommu.strict=1")
      ("efi=disable_early_pci_dma") # May prevent some systems from booting.
      ("mitigations=auto,nosmt") # Apply relevant CPU exploit mitigations, and
      # disable symmetric multithreading. Remove "nosmt" to get back SMT, which
      # may improve performance, but may make your system more vulnerable to
      # specific exploits. Removing all mitigations completely can improve
      # performance, but isn't recommended.
    ];
  };
  environment = {
    # memoryAllocator = { provider = "graphene-hardened"; }; # NOTABLE REGRESSION!!!
    # Alternative memory allocators can be more secure. graphene-hardened would
    # be most ideal for security. Note: On nixos-unstable (Nov 2023) 
    # graphene-hardened will BREAK your system, and nix rollbacks WILL NOT work.
    systemPackages = # doas-sudo wrapper, only needed if using sudo.
      (with pkgs; [ (((pkgs).writeScriptBin "sudo" ''exec doas "$@"'')) ]);
    etc = {
      securetty = { # Empty /etc/securetty to prevent root login on tty.
        text = ''
        # /etc/securetty: list of terminals on which root is allowed to login.
        # See securetty(5) and login(1).
        '';
      };
      machine-id = { # Set machine-id to the Kicksecure machine-id, for privacy
      # reasons. /var/lib/dbus/machine-id doesn't exist on dbus enabled NixOS
      # systems, so we don't have to worry about that.
        text = ''
b08dfa6083e7567a1921a715000001fb
        '';
      };
      "bluetooth/main.conf" = mkForce { # Borrow Kicksecure bluetooth configuration.
        text = ''
[General]
# How long to stay in pairable mode before going back to non-discoverable
# The value is in seconds. Default is 0.
# 0 = disable timer, i.e. stay pairable forever
PairableTimeout = 30

# How long to stay in discoverable mode before going back to non-discoverable
# The value is in seconds. Default is 180, i.e. 3 minutes.
# 0 = disable timer, i.e. stay discoverable forever
DiscoverableTimeout = 30

# Maximum number of controllers allowed to be exposed to the system.
# Default=0 (unlimited)
MaxControllers=1

# How long to keep temporary devices around
# The value is in seconds. Default is 30.
# 0 = disable timer, i.e. never keep temporary devices
TemporaryTimeout = 0 

[Policy]
# AutoEnable defines option to enable all controllers when they are found.
# This includes adapters present on start as well as adapters that are plugged
# in later on. Defaults to 'true'.
AutoEnable=false

# network/on: A device will only accept advertising packets from peer
# devices that contain private addresses. It may not be compatible with some
# legacy devices since it requires the use of RPA(s) all the time.
Privacy=network/on        
        '';
      };
      "modprobe.d/nixos.conf" = { # Borrow Kicksecure module blacklist.
      # "install "foobar" /bin/not-existent" prevents the module from being
      # loaded at all. "blacklist "foobar"" prevents the module from being
      # loaded automatically at boot, but it can still be loaded afterwards.
        text = ''
## Copyright (C) 2012 - 2023 ENCRYPTED SUPPORT LP <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## See the following links for a community discussion and overview regarding the selections
## https://forums.whonix.org/t/blacklist-more-kernel-modules-to-reduce-attack-surface/7989
## https://madaidans-insecurities.github.io/guides/linux-hardening.html#kasr-kernel-modules

## Disable automatic conntrack helper assignment
## https://phabricator.whonix.org/T486
options nf_conntrack nf_conntrack_helper=0

## Disable bluetooth to reduce attack surface due to extended history of security vulnerabilities
## https://en.wikipedia.org/wiki/Bluetooth#History_of_security_concerns
#
## Now replaced by a privacy and security preserving default bluetooth configuration for better usability
#
# install bluetooth /bin/disabled-bluetooth-by-security-misc
# install btusb /bin/disabled-bluetooth-by-security-misc

## Disable thunderbolt and firewire modules to prevent some DMA attacks
install thunderbolt /bin/disabled-thunderbolt-by-security-misc
install firewire-core /bin/disabled-firewire-by-security-misc
install firewire_core /bin/disabled-firewire-by-security-misc
install firewire-ohci /bin/disabled-firewire-by-security-misc
install firewire_ohci /bin/disabled-firewire-by-security-misc
install firewire_sbp2 /bin/disabled-firewire-by-security-misc
install firewire-sbp2 /bin/disabled-firewire-by-security-misc
install ohci1394 /bin/disabled-firewire-by-security-misc
install sbp2 /bin/disabled-firewire-by-security-misc
install dv1394 /bin/disabled-firewire-by-security-misc
install raw1394 /bin/disabled-firewire-by-security-misc
install video1394 /bin/disabled-firewire-by-security-misc

## Disable CPU MSRs as they can be abused to write to arbitrary memory.
## https://security.stackexchange.com/questions/119712/methods-root-can-use-to-elevate-itself-to-kernel-mode
install msr /bin/disabled-msr-by-security-misc

## Disables unneeded network protocols that will likely not be used as these may have unknown vulnerabilties.
## Credit to Tails (https://tails.boum.org/blueprint/blacklist_modules/) for some of these.
## > Debian ships a long list of modules for wide support of devices, filesystems, protocols. Some of these modules have a pretty bad security track record, and some of those are simply not used by most of our users.
## > Other distributions like Ubuntu[1] and Fedora[2] already ship a blacklist for various network protocols which aren't much in use by users and have a poor security track record.
install dccp /bin/disabled-network-by-security-misc
install sctp /bin/disabled-network-by-security-misc
install rds /bin/disabled-network-by-security-misc
install tipc /bin/disabled-network-by-security-misc
install n-hdlc /bin/disabled-network-by-security-misc
install ax25 /bin/disabled-network-by-security-misc
install netrom /bin/disabled-network-by-security-misc
install x25 /bin/disabled-network-by-security-misc
install rose /bin/disabled-network-by-security-misc
install decnet /bin/disabled-network-by-security-misc
install econet /bin/disabled-network-by-security-misc
install af_802154 /bin/disabled-network-by-security-misc
install ipx /bin/disabled-network-by-security-misc
install appletalk /bin/disabled-network-by-security-misc
install psnap /bin/disabled-network-by-security-misc
install p8023 /bin/disabled-network-by-security-misc
install p8022 /bin/disabled-network-by-security-misc
install can /bin/disabled-network-by-security-misc
install atm /bin/disabled-network-by-security-misc

## Disable uncommon file systems to reduce attack surface
## HFS and HFS+ are legacy Apple filesystems that may be required depending on the EFI parition format
install cramfs /bin/disabled-filesys-by-security-misc
install freevxfs /bin/disabled-filesys-by-security-misc
install jffs2 /bin/disabled-filesys-by-security-misc
install hfs /bin/disabled-filesys-by-security-misc
install hfsplus /bin/disabled-filesys-by-security-misc
install udf /bin/disabled-filesys-by-security-misc

## Disable uncommon network file systems to reduce attack surface
install cifs /bin/disabled-netfilesys-by-security-misc
install nfs /bin/disabled-netfilesys-by-security-misc
install nfsv3 /bin/disabled-netfilesys-by-security-misc
install nfsv4 /bin/disabled-netfilesys-by-security-misc
install ksmbd /bin/disabled-netfilesys-by-security-misc
install gfs2 /bin/disabled-netfilesys-by-security-misc

## Disables the vivid kernel module as it's only required for testing and has been the cause of multiple vulnerabilities
## https://forums.whonix.org/t/kernel-recompilation-for-better-hardening/7598/233
## https://www.openwall.com/lists/oss-security/2019/11/02/1
## https://github.com/a13xp0p0v/kconfig-hardened-check/commit/981bd163fa19fccbc5ce5d4182e639d67e484475
install vivid /bin/disabled-vivid-by-security-misc

## Disable Intel Management Engine (ME) interface with the OS
## https://www.kernel.org/doc/html/latest/driver-api/mei/mei.html
install mei /bin/disabled-intelme-by-security-misc
install mei-me /bin/disabled-intelme-by-security-misc

## Blacklist automatic loading of the Atheros 5K RF MACs madwifi driver
## https://git.launchpad.net/ubuntu/+source/kmod/tree/debian/modprobe.d/blacklist-ath_pci.conf?h=ubuntu/disco
blacklist ath_pci

## Blacklist automatic loading of miscellaneous modules
## https://git.launchpad.net/ubuntu/+source/kmod/tree/debian/modprobe.d/blacklist.conf?h=ubuntu/disco
blacklist evbug
blacklist usbmouse
blacklist usbkbd
blacklist eepro100
blacklist de4x5
blacklist eth1394
blacklist snd_intel8x0m
blacklist snd_aw2
blacklist prism54
blacklist bcm43xx
blacklist garmin_gps
blacklist asus_acpi
blacklist snd_pcsp
blacklist pcspkr
blacklist amd76x_edac

## Blacklist automatic loading of framebuffer drivers
## https://git.launchpad.net/ubuntu/+source/kmod/tree/debian/modprobe.d/blacklist-framebuffer.conf?h=ubuntu/disco
blacklist aty128fb
blacklist atyfb
blacklist radeonfb
blacklist cirrusfb
blacklist cyber2000fb
blacklist cyblafb
blacklist gx1fb
blacklist hgafb
blacklist i810fb
blacklist intelfb
blacklist kyrofb
blacklist lxfb
blacklist matroxfb_bases
blacklist neofb
blacklist nvidiafb
blacklist pm2fb
blacklist rivafb
blacklist s1d13xxxfb
blacklist savagefb
blacklist sisfb
blacklist sstfb
blacklist tdfxfb
blacklist tridentfb
blacklist vesafb
blacklist vfb
blacklist viafb
blacklist vt8623fb
blacklist udlfb

## Disable CD-ROM devices
## https://nvd.nist.gov/vuln/detail/CVE-2018-11506
## https://forums.whonix.org/t/blacklist-more-kernel-modules-to-reduce-attack-surface/7989/31
#install cdrom /bin/disabled-cdrom-by-security-misc
#install sr_mod /bin/disabled-cdrom-by-security-misc
blacklist cdrom
blacklist sr_mod
        '';
      };
    };
   };
  fileSystems = {
    "/boot" = { options = [ ("nosuid") ("noexec") ("nodev") ]; };
    "/dev/shm" = {
      device = "/dev/shm";
      options = [ ("bind") ("nosuid") ("noexec") ("nodev") ];
    };
    "/home" = { # NOTABLE REGRESSION!!!
    # Add noexec for more security, if your workflow allows for it.
      device = "/home";
      options = [ ("bind") ("nosuid") ("nodev") ];
    };
    "/tmp" = {
      device = "/tmp";
      options = [ ("bind") ("nosuid") ("noexec") ("nodev") ];
    };
    "/var" = { # NOTABLE REGRESSION!!!
    # Add noexec for more security, if your workflow allows for it.
      device = "/var";
      options = [ ("bind") ("nosuid") ("nodev") ];
    };
  };
  networking = { # Enables firewall. You may need to tweak your firewall rules
  # depending on your usecase. On a desktop, this shouldn't cause problems.
    firewall = {
      allowedTCPPorts = [ ];
      allowedUDPPorts = [ ];
      enable = true;
    };
    networkmanager = {
      ethernet = { macAddress = "random"; };
      wifi = {
        macAddress = "random";
        scanRandMacAddress = true;
      };
    };
  };
  nix = { settings = { allowed-users = [ ("@wheel") ]; }; };
  security = { # Enabling MAC doesn't magically make your system secure. You
  # need to set up policies yourself for it to be effective.
    apparmor = {
      enable = true;
      killUnconfinedConfinables = true;
    };
    doas = { # Comment all of this if you don't want to use doas.
      enable = true;
      extraRules = [
        ({
          keepEnv = true;
          persist = true;
          users = [ ("user") ];
        })
      ];
    };
    pam = {
      loginLimits = [
        ({
          domain = "*";
          item = "core";
          type = "hard";
          value = "0";
        })
      ];
      services = {
        su = { requireWheel = true; };
        su-l = { requireWheel = true; };
        system-login = { failDelay = { delay = "4000000"; }; };
      };
    };
    polkit = { # These polkit rules are only needed for GNOME Shell
    # integration. You may want to change the line "subject.isInGroup..."
    # if you don't want to use your sudo/sudo equivalent user as your
    # "unprivileged account." That would be recommended, but is out of scope.
      extraConfig = ''
        polkit.addRule(function(action, subject) {
            if ((action.id == "org.usbguard.Policy1.listRules" ||
                 action.id == "org.usbguard.Policy1.appendRule" ||
                 action.id == "org.usbguard.Policy1.removeRule" ||
                 action.id == "org.usbguard.Devices1.applyDevicePolicy" ||
                 action.id == "org.usbguard.Devices1.listDevices" ||
                 action.id == "org.usbguard1.getParameter" ||
                 action.id == "org.usbguard1.setParameter") &&
                subject.active == true && subject.local == true &&
                subject.isInGroup("wheel")) {
                    return polkit.Result.YES;
            }
        });
      '';
    };
    sudo = { enable = false; }; # Disables sudo when using doas.
  };
  services = {
    # openssh = { settings = {PermitRootLogin = "no"} }; # Disallow root login
    # over SSH.
    haveged = { enable = true; }; # Haveged adds entropy; it's not useless,
    # unlike what the Arch wiki says. The haveged *inspired* implementation in
    # mainline Linux is different, haveged still provides additional entropy. 
    resolved = { dnssec = "true"; }; # DNS connections will fail if not using
    # a DNS server supporting DNSSEC.
    timesyncd = { enable = false; }; # timesyncd is replaced with chrony for
    # syncing time.
    chrony = {
      enable = true;
      extraFlags = [ "-F 1" ]; # Enable seccomp filter for chronyd.
      # The below config is borrowed from GrapheneOS server infrastructure.
      # It enables NTS to secure NTP requests, among some other useful
      # settings.
      extraConfig = ''
        server time.cloudflare.com iburst nts
        server ntppool1.time.nl iburst nts
        server nts.netnod.se iburst nts
        server ptbtime1.ptb.de iburst nts

        minsources 2
        authselectmode require

        # EF
        dscp 46

        driftfile /var/lib/chrony/drift
        ntsdumpdir /var/lib/chrony

        leapsectz right/UTC
        makestep 1.0 3

        rtconutc
        rtcsync

        cmdport 0
      '';
    };
    usbguard = { # By default, GNOME Shell integration is enabled for USBGuard.
    # USB devices are blocked on lockscreen but allowed when logged in, which
    # is similar to ChromeOS in implementation. Not needed if not using GNOME.
      presentDevicePolicy = "allow"; # NOTABLE REGRESSION!!!
      # This automatically allows any USB device plugged in before the USBGuard
      # daemon starts.
      dbus = { enable = true; }; # Needed only for GNOME Shell integration.
      enable = true; # There are alternative methods other than USBGuard to
      # defeat BadUSB attacks, see madaidan's website.
    };
  };
  systemd = { coredump = { enable = false; }; };
  users = { users = { root = { hashedPassword = "!"; }; }; }; # Lock root user.
  zramSwap = { enable = true; }; # zram reduces the need to swap to disk
  # reducing the risk of writing sensitive data to non-volatile storage.
  # zram can also *replace* swap if you don't need hibernation, and therefore
  # bypass related issues entirely. zram also as added benefits in improving
  # storage lifespan and swap performance by effectively swapping to RAM.
}))
