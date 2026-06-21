# Usage:
# - Build the package: nix build .#killswitch
# - Add to tmp shell: nix shell .#killswitch
# - Add to profile: nix profile add .#killswitch
# - Install the package in a NixOS config:
#     environment.systemPackages = [ inputs.killswitch.packages.${pkgs.system}.killswitch ];
# - Enable the NixOS daemon service from this flake:
#     imports = [ inputs.killswitch.nixosModules.killswitch ];
#     services.killswitch = {
#       enable = true;
#       settings = {
#        interface_regexps = [ "^(en|wl|ww)" ];
#        enable_v4 = true;
#        allowed_v4_hostports = [ "udp/198.51.100.10:51820" ];
#       };
#     };
{
  description = "Linux network killswitch";
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils = {
      url = "github:numtide/flake-utils";
    };
    pre-commit-hooks = {
      url = "github:cachix/pre-commit-hooks.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };
  outputs = {
    self,
    nixpkgs,
    flake-utils,
    pre-commit-hooks,
    ...
  }: let
    module = {
      config,
      lib,
      pkgs,
      ...
    }: let
      cfg = config.services.killswitch;
      jsonFormat = pkgs.formats.json {};
      settingsFile = jsonFormat.generate "killswitch.json" cfg.settings;
      configPath =
        if cfg.settings == null
        then cfg.configPath
        else settingsFile;
    in {
      options.services.killswitch = {
        enable = lib.mkEnableOption "Linux eBPF network killswitch daemon";

        package = lib.mkPackageOption self.packages.${pkgs.stdenv.hostPlatform.system} "killswitch" {};

        settings = lib.mkOption {
          type = lib.types.nullOr jsonFormat.type;
          default = null;
          example = lib.literalExpression ''
            {
              interface_regexps = [ "^(en|wl|ww)" ];
              ignored_interface_regexps = [ "^(veth|br-)" ];
              admin_api.auth.groupnames = [ "killswitch" ];
              enable_v4 = true;
              allowed_v4_hostports = [ "udp/198.51.100.10:51820" ];
            }
          '';
          description = ''
            Killswitch daemon configuration rendered as JSON. When this is set,
            it takes precedence over `configPath`.
          '';
        };

        configPath = lib.mkOption {
          type = lib.types.path;
          default = "/etc/killswitch/killswitch.json";
          description = ''
            Path to the killswitch daemon JSON configuration file. This is used
            when `settings` is null.
          '';
        };
      };

      config = lib.mkIf cfg.enable {
        users.groups.killswitch = {};

        environment.systemPackages = [ cfg.package ];

        systemd.services.killswitch = {
          description = "Linux eBPF network killswitch";
          wantedBy = [ "multi-user.target" ];
          after = [ "network-pre.target" ];
          wants = [ "network-pre.target" ];
          path = [ pkgs.iw ];
          serviceConfig = {
            Type = "simple";
            ExecStart = lib.escapeShellArgs [ "${lib.getExe cfg.package}" (toString configPath) ];
            Restart = "on-failure";
            RestartSec = "2s";
          };
        };
      };
    };
  in
    flake-utils.lib.eachDefaultSystem (system: let
      pkgs = import nixpkgs {
        inherit system;
      };

      llvm = pkgs.llvmPackages_latest;
      bpfClang = pkgs.writeShellScriptBin "bpf-clang" ''
        exec ${llvm.clang-unwrapped}/bin/clang "$@"
      '';

      checks = {
        pre-commit-check = pre-commit-hooks.lib.${system}.run {
          src = ./.;
          hooks = {
            gotest.enable = true;
            commitizen.enable = true;
            typos.enable = true;
            typos-commit = {
              enable = true;
              description = "Find typos in commit message";
              entry = let script = pkgs.writeShellScript "typos-commit" ''
                typos "$1"
              ''; in builtins.toString script;
              stages = [ "commit-msg" ];
            };
            govet.enable = true;
            gofmt.enable = true;
            golangci-lint.enable = true;
            gotidy = {
              enable = true;
              description = "Makes sure go.mod matches the source code";
              entry = let script = pkgs.writeShellScript "gotidyhook" ''
                go mod tidy -v
              ''; in builtins.toString script;
              stages = [ "pre-commit" ];
            };
          };
        };
      };

      killswitch = pkgs.buildGoModule {
        pname = "killswitch";
        version = "0.1.5";
        src = ./.;
        vendorHash = "sha256-R6IPwurr2qMQNvMLCBNMugFCokNm1E9Jyl8W5LesPJE=";
        proxyVendor = true;

        nativeBuildInputs = [
          bpfClang
          llvm.llvm
        ];

        env.CGO_ENABLED = "0";

        preBuild = ''
          export CPATH="${pkgs.linuxHeaders}/include:${pkgs.libbpf}/include:$CPATH"
          go generate ./cmd/killswitch
        '';

        subPackages = [
          "cmd/killswitch"
          "cmd/killswitch-cli"
          "cmd/killswitch-user"
        ];

        meta = {
          description = "Linux eBPF network killswitch";
          homepage = "https://github.com/asciimoth/killswitch";
          license = with pkgs.lib.licenses; [ mit gpl3Only ];
          mainProgram = "killswitch";
          platforms = pkgs.lib.platforms.linux;
        };
      };
    in {
      packages = {
        default = killswitch;
        killswitch = killswitch;
      };

      devShells.default = pkgs.mkShell {
        shellHook = checks.pre-commit-check.shellHook + ''
          export CGO_ENABLED=0

          # For <linux/bpf.h> and <bpf/bpf_helpers.h>
          export CPATH="${pkgs.linuxHeaders}/include:${pkgs.libbpf}/include:$CPATH"

          echo "Using bpf-clang: $(bpf-clang --version | head -n1)"
          echo "Using llvm-strip: $(llvm-strip --version | head -n1)"
        '';

        buildInputs = with pkgs; [
          go
          golangci-lint
          gopls
          gotools

          typos
          commitizen

          just
          goreleaser

          bpfClang
          llvm.llvm

          linuxHeaders # linux/bpf.h
          libbpf # bpf/bpf_helpers.h

          # debug/trace
          bpftools
          pwru
        ];
      };
    })
    // {
      nixosModules.default = module;
      nixosModules.killswitch = module;
    };
}
