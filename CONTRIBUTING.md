# Contributing

Thanks for considering a contribution.

## License of contributions

By contributing, you agree that your contribution is licensed under the same
license as the project: Functional Source License, Version 1.1, Apache 2.0
Future License (`FSL-1.1-ALv2`), unless a separate written agreement says
otherwise.

You also represent that you have the right to submit the contribution and that
it does not include code, data, secrets, or third-party material that you are
not allowed to contribute.

## Developer Certificate of Origin

This project uses the Developer Certificate of Origin approach. Sign off commits
with:

```bash
git commit -s
```

The sign-off means you certify the DCO statement at:

https://developercertificate.org/

## Pull request expectations

- Keep changes focused and reviewable.
- Do not include secrets, API keys, real customer data, or proprietary prompts.
- Add or update tests when changing enforcement logic.
- Update docs when changing user-facing behavior.
- Prefer safe defaults for DLP, identity, device trust, and logging.

## Local test commands

```bash
python -m pytest
./scripts/test_policy_bundle.sh
./scripts/test_web_evaluate.sh
./scripts/test_model_control.sh
```
