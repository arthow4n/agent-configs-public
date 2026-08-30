# Public repository guidance

This repository is publicly shared. Agents working in a clone of this repository
must treat every file as publishable, including configs, skills, plugins,
manifests, scripts, generated files, examples, documentation, and test data.

## Required review before committing or pushing

Review the complete change, including untracked files and generated output.
Do not commit or push until you have checked that it contains no:

- Personal details such as real names, usernames, email addresses, local
  hostnames, user IDs, organization details, private URLs, or identifying
  comments and logs.
- Secrets such as API keys, access tokens, passwords, cookies, credentials,
  private keys, or service-specific IDs.
- Machine-specific or user-specific configuration that is not intentionally
  part of the public example.
- Unredacted output copied from a personal machine, account, workspace, or
  private project.

## Path and portability requirements

- Never hard-code a user-specific absolute path such as `/home/<user>/...`,
  `/Users/<user>/...`, or `C:\Users\<user>\...`.
- Use `~` for a home-directory path when the consuming tool supports shell
  expansion. Otherwise use a portable environment variable or a documented,
  repository-relative path.
- Prefer relative paths for files within this repository, and do not assume
  the repository is cloned into a particular directory.
- Replace personal or machine-specific values in examples with obvious
  placeholders.

If a value might identify a person, machine, account, or private environment,
remove it, generalize it, or replace it with a placeholder before publishing.
When in doubt, stop and ask for review rather than exposing it.

## Publishing workflow

After completing the required privacy, security, and portability review, prefer
to commit and push the reviewed changes automatically unless the user says
otherwise. Do not commit or push changes that have not passed that review.
