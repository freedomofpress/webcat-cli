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

        # `webcat manifest sign` shells out to sigsum-submit, and the documented
        # key-generation steps use sigsum-key. Both come from sigsum-go.
        sigsum = pkgs.sigsum;

        webcat-cli = pkgs.buildNpmPackage {
          pname = "webcat-cli";
          version = packageJson.version;

          src = lib.cleanSource ./.;

          # Deriving deps from package-lock.json directly avoids carrying an
          # npmDepsHash that must be recomputed on every dependency bump.
          npmDeps = pkgs.importNpmLock { npmRoot = ./.; };
          inherit (pkgs.importNpmLock) npmConfigHook;

          nativeBuildInputs = [ pkgs.makeWrapper ];

          # `npm run test` is vitest over pure unit tests; safe in the sandbox.
          doCheck = true;

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
          inherit webcat-cli sigsum;

          # Everything a site operator needs, for `nix profile install .#toolchain`.
          toolchain = pkgs.symlinkJoin {
            name = "webcat-toolchain-${packageJson.version}";
            paths = [ webcat-cli sigsum ];
            meta.description = "webcat-cli together with the sigsum-go utilities";
          };
        };

        apps = {
          sigsum-key = {
            type = "app";
            program = "${sigsum}/bin/sigsum-key";
            meta.description = "Generate and convert Sigsum signing keys";
          };
          sigsum-submit = {
            type = "app";
            program = "${sigsum}/bin/sigsum-submit";
            meta.description = "Submit a payload to a Sigsum transparency log";
          };
        };

        devShells.default = pkgs.mkShell {
          packages = [
            pkgs.nodejs_22

            # The only binaries the CLI itself shells out to: `manifest sign`
            # spawns sigsum-submit, and signer keys come from sigsum-key.
            sigsum

            # Sigstore needs no CLI — `manifest sign --type sigstore` talks to
            # Fulcio, Rekor, and the TSA in-process through @sigstore/sign, and
            # --fulcio-url / --rekor-url are service endpoints, not programs.
            # These two are here to inspect what that produced when debugging.
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
            echo "webcat-cli dev shell r- node $(node --version), $(sigsum-key --version 2>&1 | head -1)"
            echo "  npm ci && npm run build     build dist/cli.cjs"
            echo "  npm run start -- --help     run the CLI from source"
          '';
        };
      });
}
