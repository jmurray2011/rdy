# First release: owner checklist

Run these steps yourself; preparing the repository does not run them. The candidate tag exercises the real release workflow and creates a signed GitHub prerelease.

1. Delete `dist/` after reviewing anything you want to retain. It contains old local builds.
2. Initialize the repository: `git init -b main`.
3. Set `git config core.fileMode false`.
4. Stage explicit paths and set the validation script executable before the first commit:

   ```sh
   git add .github .gitattributes .gitignore .golangci.yml CHANGELOG.md CONTRIBUTING.md LICENSE NOTICE README.md SECURITY.md go.mod go.sum cmd core docs examples gate internal scripts
   git update-index --chmod=+x scripts/validate.sh
   git commit -m "Initial rdy release"
   ```

5. Create the empty public repository `github.com/jmurray2011/rdy` (do not add a GitHub-generated README or license).
6. Enable GitHub private vulnerability reporting. Create an active `v*` tag ruleset restricting creation/updates/deletion to the owner; retain owner bypass for removing the release candidate. Ensure Actions can request the release job's contents, OIDC and attestation permissions.
7. Push main:

   ```sh
   git remote add origin https://github.com/jmurray2011/rdy.git
   git push -u origin main
   ```

8. Confirm main CI is green, including the native RPM/DEB fixtures.
9. Exercise a candidate tag (its exact CHANGELOG section already exists):

   ```sh
   git tag v0.1.0-rc1
   git push origin v0.1.0-rc1
   ```

10. From a clean machine, download the candidate binary, checksum manifest, checksum signature bundle, binary signature bundle and licensing files. Verify the checksum signature before trusting the manifest; verify the selected binary's signature and GitHub provenance:

    ```sh
    tag=v0.1.0-rc1
    gh release download "$tag" --repo jmurray2011/rdy
    identity="https://github.com/jmurray2011/rdy/.github/workflows/release.yml@refs/tags/$tag"
    cosign verify-blob --bundle SHA256SUMS.sigstore.json --certificate-identity "$identity" --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS
    sha256sum --ignore-missing -c SHA256SUMS
    cosign verify-blob --bundle rdy-linux-amd64.sigstore.json --certificate-identity "$identity" --certificate-oidc-issuer https://token.actions.githubusercontent.com rdy-linux-amd64
    gh attestation verify rdy-linux-amd64 --repo jmurray2011/rdy
    chmod +x rdy-linux-amd64
    ./rdy-linux-amd64 --version
    ```

    Check all five binaries, SBOMs and licensing assets are present; the selected binary must appear as OK in the checksums. Use the platform's SHA-256 tool on macOS/Windows. Test the other platform binaries on their respective systems.
11. Delete the candidate release and remote/local candidate tag using the owner ruleset bypass:

    ```sh
    gh release delete v0.1.0-rc1 --repo jmurray2011/rdy --yes
    git push origin --delete v0.1.0-rc1
    git tag -d v0.1.0-rc1
    ```

12. Confirm the tested commit is still on main, then publish the stable tag:

    ```sh
    git tag v0.1.0
    git push origin v0.1.0
    ```

    Verify the stable assets again using the `v0.1.0` workflow identity. Subsequent releases require their own exact CHANGELOG section before tagging.
