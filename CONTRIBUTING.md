# Thank you for contributing to FreeIPA!

Contribution details and contact information are available at https://www.freeipa.org/page/Contribute.

## Reporting Bugs

Report bugs at https://codeberg.org/freeipa/freeipa/issues.

FreeIPA consists of multiple components. Check which component the bug relates to and report it in the appropriate repository.

Before you submit a bug report, search the issue tracker to see whether the issue has already been reported.
If it has, add a comment to the existing issue instead of opening a new one.

Include as much detail as you can: FreeIPA version, OS version, steps to reproduce, and the expected behavior.
For feature requests, describe the request in as much detail as possible.

### Security Vulnerabilities

Report all security-related bugs and flaws privately before you make the information public. This gives us a chance to release a fix before the issue is widely exploited.

Send all relevant information to the [Red Hat Product Security Team](https://access.redhat.com/security/team/contact).

## Contributing Code

Instructions for contributing code are available at https://www.freeipa.org/page/Contribute/Code.

We use GitHub to manage pull requests and to mirror the code.
Open a pull request on the GitHub repository.
Pull requests are merged and then pushed to the Codeberg repository.

Read the [Developer Certificate of Origin](https://developercertificate.org/) and sign your commits
with `Signed-off-by: name <email@example.com>`.
Only a human adds `Signed-off-by`. You are responsible for reviewing, understanding, and testing the change.
If an AI tool assisted with the commit, add `Assisted-by: ai-tool <ai-tool@example.com>`.

A typical commit message is structured like this:

```
component: Subject
# component: Subject is a single-line summary

Explanation
# Explanation must describe the fix or feature and the method
# chosen to implement it. It can span multiple lines.

Fixes: https://codeberg.org/freeipa/freeipa/issues/XXXX
or
Related: https://codeberg.org/freeipa/freeipa/issues/XXXX
# Fixes: means that the commit fixes the referenced issue.
# Related: means that the commit is related to the issue.
# in some way, but does not resolve it.
Assisted-by: ai-tool <ai-tool@example.com>
# If an AI tool assisted with this commit,
# add the Assisted-by line.
Signed-off-by: name <email@example.com>
```

Read the [Code of Conduct](./CODE_OF_CONDUCT.md) and follow it in all your interactions. In short, be respectful and inclusive.

If you are not sure about your changes, the reviewers can help you.
