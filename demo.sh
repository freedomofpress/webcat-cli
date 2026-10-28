#!/usr/bin/env bash

# Create keys
mkdir -p keys
sigsum-key generate -o keys/key1
HEX1=$(sigsum-key to-hex -k keys/key1.pub)
echo $HEX1
sigsum-key generate -o keys/key2
HEX2=$(sigsum-key to-hex -k keys/key2.pub)
echo $HEX2

TMPDIR=$(mktemp -d)

# Create an empty index.html file
echo index > "$TMPDIR/index.html"
echo error > "$TMPDIR/error.html"


cat > trust_policy <<EOF
log 4644af2abd40f4895a003bca350f9d5912ab301a49c77f13e5b6d905c20a5fe6 https://test.sigsum.org/barreleye

witness poc.sigsum.org/nisse 1c25f8a44c635457e2e391d1efbca7d4c2951a0aef06225a881e46b98962ac6c
witness rgdd.se/poc-witness  28c92a5a3a054d317c86fc2eeb6a7ab2054d6217100d0be67ded5b74323c5806

group  demo-quorum-rule any poc.sigsum.org/nisse rgdd.se/poc-witness
quorum demo-quorum-rule
EOF

cat > webcat.config.json <<EOF
{
  "app": "https://github.com/element-hq/element-web",
  "version": "1.12.3",
  "default_csp": "default-src 'none'; style-src 'self' 'unsafe-inline'; script-src 'self' 'wasm-unsafe-eval'; img-src * blob: data:; connect-src * blob:; font-src 'self' data: ; media-src * blob: data:; child-src blob: data:; worker-src 'self'; frame-src blob: data:; form-action 'self'; manifest-src 'self'; frame-ancestors 'self'",
  "default_index": "index.html",
  "default_fallback": "/error.html",
  "wasm": [
    "8A7Ecx-qI7PnFNAOiNTRDi31wKQn06K0rm41Jv3RTvc"
  ],
  "extra_csp": {}
}
EOF

# Create enrollment.json
webcat enrollment create --policy-file trust_policy --threshold 1 --max-age 15552000 --cas-url https://cas.demoelement.com --signer "$HEX1" --signer "$HEX2" --output enrollment.json
jq . < enrollment.json

# View the WEBCAT config file
jq . < webcat.config.json

# Generate unsigned manifest
webcat manifest generate --policy-file trust_policy --config webcat.config.json --directory "$TMPDIR" --output manifest_unsigned.json

#jq . < manifest_unsigned.json

# ---------------------------------------------------------------------

# Sign manifest"
webcat manifest sign --policy-file trust_policy -i manifest_unsigned.json -k keys/key1 -o manifest.json

jq . < manifest.json

# ---------------------------------------------------------------------

# Create bundle"
webcat bundle create --enrollment enrollment.json --manifest manifest.json --output bundle.json

jq . < bundle.json

webcat manifest verify bundle.json
# ---------------------------------------------------------------------



