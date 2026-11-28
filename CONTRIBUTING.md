# Contributing

ssotrace is a personal project, shared as-is and maintained as time allows.

- **Found a bug?** Open an issue using the bug report template. Never attach a real HAR file: describe the problem, or reproduce it with a file processed by `ssotrace redact`.
- **Know an error code ssotrace should explain?** Open an issue with the "Suggest an error code" template: the provider, the code or exact message, what it means, and how to fix it. The explanations ssotrace shows live in one file, [`internal/kb/codes.json`](internal/kb/codes.json).
- **Found a security problem?** Report it privately, as described in [SECURITY.md](SECURITY.md).
- **Want to change it?** You're welcome to fork it under the [MIT license](LICENSE). `make check` runs everything CI runs.
