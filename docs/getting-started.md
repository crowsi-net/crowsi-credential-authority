# Using crowsi-credential-authority

Manage the relationship between devices, permission grants and opaque credential references.

## Before you start

This authority manages relationships and permission metadata. Secret values belong to the custody implementation.

## First steps

Run from the repository root:

```sh
cargo test --locked
```

## How to assess the result

- Track registered device and grant metadata.
- Validate transfer and use relationships.

A passing source-level check establishes only what that check observes. Keep missing configuration, unavailable services and unverified deployment paths visible.

## Continue reading

[Repository overview](../README.md)
