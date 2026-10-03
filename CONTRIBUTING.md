# Contribution Guidelines

<!--
SPDX-FileType: DOCUMENTATION
SPDX-FileCopyrightText: 2026 Edward Kmett <ekmett@gmail.com>
SPDX-License-Identifier: BSD-2-Clause OR Apache-2.0
-->

Contributions are welcome. Please follow the [code of conduct](CODE_OF_CONDUCT.md).
Submitted code should be compatible with the repository's
`BSD-2-Clause OR Apache-2.0` license; see [LICENSE.md](LICENSE.md).
Exceptions require Edward Kmett's explicit consent.

## Source and documentation

Use the smallest change that addresses the problem, and run the tests described
in [README.md](README.md#build-and-test). Public API contracts belong in Doxygen
comments beside their declarations. Document ownership, preconditions, return
values, and failure behavior when relevant. Build the documentation after changing
its configuration or comments; documentation warnings are errors.

## SPDX and provenance

Files should carry SPDX identifiers near the top or bottom, following this style:

```text
SPDX-FileType: Source
SPDX-FileCopyrightText: 2026 Edward Kmett <ekmett@gmail.com>
SPDX-License-Identifier: BSD-2-Clause OR Apache-2.0
```

Use the file's comment syntax and the appropriate file type. Contributors may add
their own copyright line. Preserve upstream notices when reusing material; track
the source and version or commit for bundled assets, along with their license.
For assets that cannot contain a notice, use a nearby `LICENSE.spdx` file.

OpenSSL is an external dependency, not bundled source. The Contributor Covenant
text retains its own attribution and CC-BY-4.0 notice.

Contact Edward Kmett at <ekmett@gmail.com> with policy questions.
