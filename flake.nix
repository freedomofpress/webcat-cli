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

        # Single point of truth for the version, so bumping package.json is enough.
        packageJson = builtins.fromJSON (builtins.readFile ./package.json);

        webcat-cli = pkgs.buildNpmPackage {
          pname = "webcat-cli";
          version = packageJson.version;

          src = lib.cleanSource ./.;

          # Deriving deps from package-lock.json directly avoids carrying an
          # npmDepsHash that must be recomputed on every dependency bump.
          npmDeps = pkgs.importNpmLock { npmRoot = ./.; };
          inherit (pkgs.importNpmLock) npmConfigHook;

          # Match the dev shell, and the floor of package.json's engines.
          nodejs = pkgs.nodejs_22;

          nativeBuildInputs = [ pkgs.makeWrapper ];

          # vitest over unit and offline smoke tests; safe in the sandbox.
          # buildNpmPackage has no check hook of its own, so name the phase.
          doCheck = true;
          checkPhase = ''
            runHook preCheck
            npm test
            runHook postCheck
          '';

          # Put the sigsum tools on the CLI's own PATH, so an installed `webcat`
          # is self-sufficient without a separate `go install` step.
          postInstall = ''
            wrapProgram $out/bin/webcat \
              --prefix PATH : ${lib.makeBinPath [ pkgs.sigsum ]}
          '';

          meta = {
            inherit (packageJson) description;
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
          inherit (pkgs) sigsum;

          # Everything a site operator needs, for `nix profile install .#toolchain`.
          toolchain = pkgs.symlinkJoin {
            name = "webcat-toolchain-${packageJson.version}";
            paths = [ webcat-cli pkgs.sigsum ];
            meta.description = "webcat-cli together with the sigsum-go utilities";
          };
        };

        # Builds the package, so `nix flake check` runs its tests.
        checks.default = webcat-cli;

        devShells.default = pkgs.mkShell {
          packages = [
            pkgs.nodejs_22
            pkgs.just

            # The CLI spawns sigsum-key (`init --keys`) and sigsum-submit (`manifest sign`).
            pkgs.sigsum

            # Sigstore signing is in-process; these are for inspecting its output.
            pkgs.cosign
            pkgs.rekor-cli

            # git-restore-mtime, which the GitHub Actions guide recommends for
            # clamping mtimes so that a rebuild does not change the manifest.
            pkgs.git-tools

            # Used by demo.sh and the documented end-to-end walkthrough.
            pkgs.jq
            pkgs.curl
            pkgs.git
          ];

          shellHook = ''
            echo "webcat-cli dev shell: run \`just\` to list tasks"
          '';
        };
      });
}
