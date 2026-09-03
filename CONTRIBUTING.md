# Contributing

This repository is the .NET encryption engine for Kryptic (`Kryptic.Encryption` on
NuGet).

## What we accept

- Bug fixes and test coverage
- Documentation corrections
- Compatibility fixes
- Interop vector updates when wire formats change (must land in all three
  encryption repositories in the same release)

## What we do not accept

- Custom cryptographic primitives
- Wire format changes in only one encryption runtime
- Public GitHub issues for vulnerabilities (email security@kryptic.dev)

## Development

```bash
dotnet test
```

Read [SECURITY.md](SECURITY.md) before changing crypto code. Sibling runtimes:
[Kryptic.Encryption.NPM](https://github.com/dev-kryptic/Kryptic.Encryption.NPM)
and [Kryptic.Encryption.Go](https://github.com/dev-kryptic/Kryptic.Encryption.Go).

## Releasing

A merge to `main` is the release. The publish workflow commits the version bump as
the Kryptic Release Bot, publishes to NuGet, tags `vX.Y.Z`, and opens a GitHub
Release using the matching section in [CHANGELOG.md](CHANGELOG.md).

Before merging release-worthy changes, move notes from **Unreleased** into a
`## X.Y.Z` section so the release has a description. Format changes must ship in
all three encryption repositories in the same release.

## Licensing of contributions

This repository is Apache-2.0. By opening a pull request you confirm the
contribution is your own work (or you have the right to submit it) and you
license it under Apache-2.0. There is no CLA.
