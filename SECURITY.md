# Security policy

## Reporting a vulnerability
Report it privately through **Security > Report a vulnerability** on this repository. Do not open a public issue.

Include what you found, how to reproduce it, and which script and version are affected. Do not include tenant IDs, UPNs, tokens or log output from a real tenant.

You can expect an acknowledgement within 7 days. This is a personal project maintained in spare time, so fixes are best effort.

## Supported versions
Only the latest tagged release gets fixes.

## Design notes for reviewers
- Scripts use delegated sign-in through Microsoft Graph Command Line Tools. There are no app registrations, client secrets or certificates in this repo.
- Each script requests only the Graph scopes it needs. They are listed in each script's help block and in the README.
- Real tenant values live in `config.local.psd1`, which is gitignored. Output and logs (which contain UPNs) go to `output/`, also gitignored.
- Removing directory roles is deliberately not automated, so no script needs `RoleManagement.ReadWrite.Directory`.
