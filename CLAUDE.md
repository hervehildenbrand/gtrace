# gtrace Project Instructions

## Release Workflow - MANDATORY

After every PR merge to `main`, prompt the user to cut a new release.

### Steps

1. After merge completes, ask: **"PR merged. Tag a new release? Current: vX.Y.Z"**
2. Wait for user confirmation (version number or yes/no)
3. If approved:
   ```
   git checkout main && git pull
   git tag vX.Y.Z
   git push origin vX.Y.Z
   ```
4. Monitor the GitHub Actions release workflow: `gh run watch <id>`
5. Once release succeeds, upgrade locally: `echo "y" | gtrace upgrade`
6. Verify the new binary: `gtrace --version`

### Version Bumping

- **feat:** bump minor (e.g., v0.6.0 → v0.7.0)
- **fix:** bump patch (e.g., v0.7.0 → v0.7.1)
- **breaking change:** bump major (e.g., v0.7.0 → v1.0.0)
- Check latest tag with: `git tag --sort=-version:refname | head -1`

### Why

Releases are built by goreleaser via GitHub Actions on tag push. Merging a PR does NOT produce a release. Users running `gtrace upgrade` will get stale binaries if we forget to tag.
