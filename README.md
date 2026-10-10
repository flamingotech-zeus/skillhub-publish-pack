# Skill Packaging and Publishing

[English](README.md) | [简体中文](README.zh-CN.md)

> Turn a local skill or an internal methodology into a packaged, de-identified artifact that can be published and installed by others.

## What this is

This is not a zip command. Packaging for distribution has constraints that a plain archive ignores — accepted field names, forbidden binary content, a review step, and the requirement that nothing sensitive leaves with the package.

The skill encodes all of that, including the de-identification pass, which is the step people skip when they are in a hurry.

## Why we open-sourced it

We package internal methods for the team regularly, and every time we rediscovered the same field constraints and re-checked the same list by hand.

Writing it down made the process shorter and, more usefully, made the de-identification step non-optional. The procedures are generic; the examples in it are placeholders.

## What it does

- **Field specification.** Which metadata fields are required, which are optional, and the accepted values for each — checked against the current platform rules rather than remembered.
- **Hard archive constraints.** Certain content types cause rejection. The rule is applied at build time, so a rejected upload is not discovered after the fact.
- **A de-identification pass.** An automated scan runs over the package for credentials, internal names and absolute paths before anything is submitted.
- **Two helper scripts.** One audits the package, one builds it.
- **Error reference.** Common rejection reasons and what each one actually means.
- **Review process documented.** What is checked, and in what order.

## Requirements

Python 3

## Installation

```bash
git clone https://github.com/<your-username>/skillhub-publish-pack.git
```

Then place the folder into your agent skills directory:

| OS | Path |
|---|---|
| Windows | `C:\Users\<you>\.workbuddy\skills\skillhub-publish-pack\` |
| macOS / Linux | `~/.workbuddy/skills/skillhub-publish-pack/` |

There is no build step. Restart the session and it takes effect.

## How to use

Ask to package or publish:

- "Turn this into a skill and publish it"
- "Package this for the team"
- "What are the requirements for publishing"

The skill runs the audit pass first, then builds, then walks through submission.

## Files

```
├── SKILL.md
└── scripts/
    ├── audit_all.py
    └── skill_pack.py
```

## Notes and limits

1. **De-identification is not optional.** This is the step that turns a convenient shortcut into an incident. The skill makes it a gate rather than a suggestion.
2. **Field rules change.** The platform's requirements are not frozen. The skill checks current rules instead of relying on a cached list.
3. **Binary content is rejected.** Images, archives and executables belong outside the package.
4. **The examples are placeholders.** They illustrate the shape of a correct package and are not production content.

## License

MIT
