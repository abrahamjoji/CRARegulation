# Contributing

Thanks for your interest in improving this project. Bug reports, documentation fixes and new features are all welcome.

## Before you start

- **Bugs and small fixes:** open a pull request directly, or an issue first if you are unsure.
- **New features or larger changes:** open a feature request issue first so the design can be agreed before you write code.
- **Security problems:** do not open an issue. Follow [SECURITY.md](SECURITY.md).

## How to contribute

Only maintainers can push to this repository, so all changes come in through pull requests from a fork.

1. Fork the repository and clone your fork.
2. Create a branch from `main`: `git switch -c feature/short-description`.
3. Set up the environment (Linux, Python 3.11+):

   ```bash
   python3 -m venv .venv
   .venv/bin/pip install --require-hashes -r requirements/dev.lock
   .venv/bin/pip install -e .
   ```

4. Make your change and add or update tests under `tests/`.
5. Run the deterministic test suite:

   ```bash
   .venv/bin/python -m unittest discover tests
   ```

6. Push the branch to your fork and open a pull request against `main`.

## Pull request expectations

- One logical change per pull request, with a clear description of what and why.
- Tests pass in CI. The `main` branch is protected: every pull request needs passing checks and a maintainer review before it is merged.
- No secrets, credentials, private keys or customer data in code, tests or fixtures. Use obviously fake values.
- New dependencies or tool versions are pinned (hashes in `requirements/*.lock`, SHA-pinned GitHub Actions), matching the existing style.
- Update the relevant document in `docs/` when behaviour changes.

## Where to add features

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/REPOSITORY_LAYOUT.md](docs/REPOSITORY_LAYOUT.md) for how the code is organised. Product code lives in `src/`; `poc/` holds demonstrations and is not part of the shipped product.

## License

By contributing, you agree that your contributions are licensed under the project's [MIT License](LICENSE).

## Code of conduct

This project follows the [Code of Conduct](CODE_OF_CONDUCT.md).
