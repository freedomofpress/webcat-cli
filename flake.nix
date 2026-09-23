{
  description = "WEBCAT CLI for creating, validating, and packaging enrollments and manifests";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        inherit (pkgs) lib;

        packageJson = builtins.fromJSON (builtins.readFile ./package.json);

        sigsum = pkgs.sigsum;

        # Match CI and the engines floor rather than nixpkgs' default Node.
        nodejs = pkgs.nodejs_22;

        webcat-cli = pkgs.buildNpmPackage {
          pname = "webcat-cli";
          inherit nodejs;
          version = packageJson.version;

          src = lib.cleanSource ./.;

          # Deriving deps from package-lock.json directly avoids carrying an
          # npmDepsHash that must be recomputed on every dependency bump.
          npmDeps = pkgs.importNpmLock { npmRoot = ./.; };
          inherit (pkgs.importNpmLock) npmConfigHook;

          nativeBuildInputs = [ pkgs.makeWrapper ];

          doCheck = true;
          checkPhase = ''
            runHook preCheck
            npm test
            # node_modules is copied into $out; drop vitest's cache first.
            rm -rf node_modules/.vite
            runHook postCheck
          '';

          # Put the sigsum tools on the CLI's own PATH, so an installed `webcat`
          # is self-sufficient without a separate `go install` step.
          postInstall = ''
            wrapProgram $out/bin/webcat \
              --prefix PATH : ${lib.makeBinPath [ sigsum ]}
          '';

          meta = {
            description = "Utilities for WEBCAT enrollment and manifest generation and validation";
            homepage = "https://github.com/freedomofpress/webcat-cli";
            license = lib.licenses.mit;
            mainProgram = "webcat";
          };
        };
      in
      {
        packages = {
          default = webcat-cli;
          inherit webcat-cli;

          # Everything a site operator needs, for `nix profile install .#toolchain`.
          toolchain = pkgs.symlinkJoin {
            name = "webcat-toolchain-${packageJson.version}";
            paths = [ webcat-cli sigsum ];
            meta.description = "webcat-cli together with the sigsum-go utilities";
          };
        };

        # `nix flake check` runs the test suite.
        checks = { inherit webcat-cli; };

        devShells.default = pkgs.mkShell {
          packages = [
            nodejs

            # sigsum-key and sigsum-submit, which the CLI spawns.
            sigsum

            # Sigstore signing is in-process; these are only for debugging.
            pkgs.cosign
            pkgs.rekor-cli

            # git-restore-mtime, which the docs.webcat.tech GitHub Actions guide
            # recommends for clamping mtimes so a rebuild does not change the manifest.
            pkgs.git-tools

            # jq drives demo.sh; the docs use curl to check served CSP headers.
            pkgs.jq
            pkgs.curl
            pkgs.git
            pkgs.just
          ];

          shellHook = ''
            echo "webcat-cli dev shell: node $(node --version); run \`just\` for targets"
          '';
        };
      });
}
