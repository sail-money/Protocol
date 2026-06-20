# Experimental permission templates

The contracts in this directory are **experimental** permission templates.

- They are **unaudited**.
- They are **not part of the trusted core** (the kernel and governance). A bug in any
  template here cannot affect the kernel or accounts that do not register it.
- They are **not shipped or deployed at launch**. The launch set is the shared
  templates that remain under `contracts/templates/`.
- They are retained intact for future verification, review, and potential
  re-introduction once hardened.

Do not register these templates on a production account. Their test coverage lives
under `test/experimental/`, and a separate deployment script
(`script/experimental/DeployExperimentalTemplates.s.sol`) exists only for controlled,
non-production deployments.
