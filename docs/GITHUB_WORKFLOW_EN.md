# GitHub development and updates

The repository contains the Relay Platform source, development history, documentation, tests, and the bundled optional protocol engine source and license. Version 0.117.0 is a development release; see [current status](STATUS.md), the [non-payment delivery checklist](NONPAYMENT_DELIVERY.md), and the [complete English target list](NONPAYMENT_TARGETS_EN.md) for unfinished work.

Repository: [EntropyEnthalpy-SYS/relay-platform](https://github.com/EntropyEnthalpy-SYS/relay-platform).

For a new development checkout:

```sh
git clone https://github.com/EntropyEnthalpy-SYS/relay-platform.git
cd relay-platform
```

## Branches and changes

`main` is the shared integration branch. Use a separate branch and a pull request for each change so that the diff and test results can be reviewed together.

In a normal clone of the repository, begin with:

```sh
git switch main
git pull --ff-only origin main
git switch -c feature/short-description
```

Make the change, then run the existing verification entry point:

```sh
sh scripts/verify.sh
```

The local prerequisites are Rust 1.99.1 with rustfmt and Clippy, Node.js 24, Python 3.14, a C compiler, libclang, and OpenSSL or LibreSSL. Rust dependencies are fixed by `Cargo.lock`; the web interface requires no npm build.

Stage only the intended source and documentation changes, inspect `git diff --cached`, commit, and push the branch. Open a pull request targeting `main` on GitHub. Merge after review and a successful **Verify / Linux regression** check. For a simple local update, switch to `main` and run `git pull --ff-only origin main` again.

## Automated verification

[The workflow](../.github/workflows/verify.yml) runs on pushes to `main`, pull requests, and manual dispatch from GitHub's Actions page. It uses Ubuntu 24.04, Rust 1.99.1, Node.js 24, and Python 3.14. GitHub actions are pinned to exact commits, and the job has read-only repository permissions.

It invokes `scripts/verify.sh`, covering:

- Rust formatting, Clippy, and the default Rust unit and integration tests.
- JavaScript syntax and the English/Chinese interface regression suites.
- Python syntax, a release binary build, and deployment unit tests.

This workflow is an automated regression check. Ignored tests requiring optional protocol engines, real browsers and proxy clients, privileged networking, WAN traffic, DNS provider access, endurance runs, and hardware-capacity acceptance require their separate test environments. A successful CI run does not establish that all product targets or production acceptance criteria are complete. Read the workflow log for the exact passed, failed, and ignored test counts.

## Releases and server updates

1. Finish the intended changes and merge them after review and CI.
2. Run the additional Linux and protocol acceptance tests relevant to the release. Record the environment, source commit, limitations, and results.
3. Update the version and release notes, then tag the tested commit using `vMAJOR.MINOR.PATCH`. Publish a GitHub release with the source archive, verification package, checksums, and any separately validated deployment bundles.
4. Follow [Linux deployment and rollback](LINUX_DEPLOYMENT.md) to build or install on the intended architecture, back up state, upgrade in the documented order, and run smoke tests.

Pushing a commit or merging a pull request updates the source repository. VPS deployment is a separate operation and is not triggered by this workflow. The workflow needs no VPS credentials, DNS tokens, or release-signing keys.

## Source and runtime data

Commit source, examples, and reproducible test definitions. Keep live databases, state directories, passwords, SSH keys, API tokens, `.env` files, and signing keys outside Git. Test scripts create temporary credentials locally; live server details are not needed to contribute or run CI. Review staged files before every push.

Public visibility does not select a license for the project's own code. Its redistribution license has not yet been specified; the existing third-party notices and bundled engine license continue to apply to their respective components. See [third-party components](THIRD_PARTY.md).
