{
  description = "go-jenkins-mcp: MCP server for the Jenkins API";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
        pname = "go-jenkins-mcp";
        version = "0.2.0" + (if self ? shortRev then "+${self.shortRev}" else "");
        fs = pkgs.lib.fileset;
        src = fs.toSource {
          root = ./.;
          fileset = fs.unions [
            (fs.fileFilter (file: file.hasExt "go") ./.)
            (fs.fileFilter (file: file.name == "go.mod") ./.)
            (fs.fileFilter (file: file.name == "go.sum") ./.)
          ];
        };
      in
      rec {
        packages = rec {
          go-jenkins-mcp = pkgs.buildGo127Module {
            inherit pname version src;

            subPackages = [ "." ];

            vendorHash = "sha256-OxX/ylFt+zJg83lTeTZ3usgv7tU50DTrdHxYsoKnKCg=";

            ldflags = [
              "-s"
              "-w"
              "-X main.version=${version}"
            ];

            meta.mainProgram = pname;
          };

          default = go-jenkins-mcp;
        };

        apps.default = flake-utils.lib.mkApp { drv = packages.default; };

        checks.default = packages.default;

        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            go_1_27
            gopls
            gotools
            (go-tools.override { buildGoModule = buildGo127Module; })
            delve
          ];
        };

        formatter = pkgs.nixfmt;
      }
    );
}
