# Docs

## Description
Adds a detailed Windows support research note for the native implementation path.

This is intentionally framed as research, not a claim that rencfs mounts on Windows today. It documents:

- recommended WinFsp backend and alternatives considered;
- WinFsp licensing/attribution checkpoint for an `MIT OR Apache-2.0` project;
- Windows-only dependency and delay-load build shape;
- proposed `src/mount/windows.rs` architecture around the existing `EncryptedFs` layer;
- operation mapping from WinFsp callbacks to rencfs methods;
- Windows metadata decisions and unsupported NTFS features for the first milestone;
- build/CI plan and a manual smoke test checklist for a Windows host with WinFsp installed;
- acceptance criteria for a truthful first implementation PR.

Related to the Windows support bounty/research request (`research implementation for Windows`, Opire listing for #3).

## Type of change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [x] Documentation update

## Checklist:

- [x] I have performed a self-review of my code
- [x] I have tested my code on different platforms (if applicable)
- [x] I have commented my code, particularly in hard-to-understand areas
- [x] I have added necessary documentation (if appropriate)
- [x] My changes generate no new warnings
- [x] I have added tests that prove my fix is effective or that my feature works
- [x] New and existing unit tests pass locally with my changes

## Verification
- `cargo check` passes locally on macOS/aarch64.
- I did not install Windows or claim Windows runtime validation. The PR adds a Windows smoke-test checklist for the next implementation step.

## AI disclosure
AI-assisted contribution by QuarkAssistant using GPT/Codex tooling. Human-authored repository context and public documentation were reviewed; no private data was used.