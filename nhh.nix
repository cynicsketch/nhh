# This module is based primarily on madaidan's Linux Hardening Guide. See it
# for detailed explanations:
# Original URL: https://madaidans-insecurities.github.io/guides/linux-hardening.html
# Archive: https://web.archive.org/web/20220320000126/https://madaidans-insecurities.github.io/guides/linux-hardening.html

# Sections from madaidan's guide that are IRRELEVANT/NON-APPLICABLE:
# 1. (Advice)
# 2.1 (Advice)
# 2.3.3 (Advice)
# 2.5.1 (Advice)
# 2.5.3 (Advice)
# 2.6 (Advice)
# 2.10 (Package is broken)
# 7 (Advice)
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
# 8.1 (No option)
# 8.6 (No option, not for all systems)
# 8.7 (Inconvenient, depends on specific user behavior)
# 10.1 (Inconvenient, not within threat model)
# 10.2 (Inconvenient, not within threat model)
# 10.3 (No option)
# 10.5.3 (Not packaged)
# 10.5.4 (Not packaged)
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
    blacklistedKernelModules = [
      ("dccp")
      ("sctp")
      ("rds")
      ("tipc")
      ("n-hdlc")
      ("ax25")
      ("netrom")
      ("x25")
      ("rose")
      ("decnet")
      ("econet")
      ("af_802154")
      ("ipx")
      ("appletalk")
      ("psnap")
      ("p8023")
      ("p8022")
      ("can")
      ("atm")
      ("cramfs")
      ("freevxfs")
      ("jffs2")
      ("hfs")
      ("hfsplus")
      ("squashfs")
      ("udf")
      ("cifs")
      ("nfs")
      ("nfsv3")
      ("nfsv4")
      ("ksmbd")
      ("gfs2")
      ("vivid")
      # NOTABLE REGRESSION!!!
      # Disable BT and web cam for privacy/attack surface reduction. 
      # ("bluetooth") # Disable bluetooth
      # ("btusb") # Same as above
      # ("uvcvideo") # Disable webcam
      ("thunderbolt") # Disable Thunderbolt due to risk of DMA attacks
      ("firewire-core") # Disable FireWire due to risk of DMA attacks
    ];
    kernel = {
      sysctl = {
        "dev.tty.ldisc_autoload" = "0";
        "fs.protected_fifos" = "2";
        "fs.protected_hardlinks" = "1";
        "fs.protected_regular" = "2";
        "fs.protected_symlinks" = "1";
        "fs.suid_dumpable" = "0";
        "kernel.dmesg_restrict" = "1"; # dmesg requires admin privileges now.
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
    kernelPackages = (pkgs).linuxPackages_hardened;
    kernelParams = [
      ("slab_nomerge")
      ("init_on_alloc=1")
      ("init_on_free=1")
      ("page_alloc.shuffle=1")
      ("pti=on") # Mitigates Meltdown, some KASLR bypasses. Hurts performance.
      ("randomize_kstack_offset=on")
      ("vsyscall=none")
      ("debugfs=off")
      ("oops=panic")
      ("module.sig_enforce=1") # Requires all kernel modules to be signed. This
      # prevents out-of-tree kernel modules from working unless signed, incl.
      # DKMS, so some drivers, such as Nvidia and VirtualBox drivers, may need
      # to be signed.
      ("lockdown=confidentiality") # Mitigates many ways to extract info from
      # the kernel, but notably breaks hibernation. Hibernation only matters on
      # battery operated devices.
      ("quiet")
      ("loglevel=0")
      ("random.trust_cpu=off")
      ("intel_iommu=on")
      ("amd_iommu=on")
      ("efi=disable_early_pci_dma")
      ("mitigations=auto,nosmt") # Apply relevant CPU exploit mitigations, and
      # disable symmetric multithreading. Remove "nosmt" to get back SMT, which
      # may improve performance, but may make your system more vulnerable to
      # specific exploits. Removing all mitigations completely can improve
      # performance, but isn't recommended.
    ];
  };
  environment = {
    # memoryAllocator = { provider = "graphene-hardened"; }; # NOTABLE REGRESSION!!
    # Alternative memory allocators can be more secure. graphene-hardened would
    # be most ideal for security. Note: On nixos-unstable (Nov 2023) 
    # graphene-hardened will BREAK your system, and nix rollbacks WILL NOT work.
    systemPackages = # doas-sudo wrapper, only needed if using sudo.
      (with pkgs; [ (((pkgs).writeScriptBin "sudo" ''exec doas "$@"'')) ]);
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
    # integration.
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
                subject.isInGroup("wheel")) { # If you don't use your sudo or
                # equivalent user as your "unprivileged," account, which is
                # recommended but out of scope here, change this.
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
  users = { users = { root = { hashedPassword = "!"; }; }; }; # Prevents login
  # to to the root account.
}))
