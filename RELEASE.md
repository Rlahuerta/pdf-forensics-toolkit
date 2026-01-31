# Release Process for Version 1.0.0

## Overview

This document describes the release preparation for version 1.0.0 of the PDF Forensics Toolkit.

## What Has Been Done

### 1. Version Number
- ✅ Version set to `1.0.0` in `pdf_forensics/__init__.py`
- ✅ Version configured in `pyproject.toml` to read from `__init__.py`

### 2. Git Tag
- ✅ Created annotated git tag `v1.0.0`
- ✅ Tag message: "Release version 1.0.0 - Initial stable release of PDF Forensics Toolkit"

### 3. Release Notes
- ✅ Created `CHANGELOG.md` with comprehensive release notes
- ✅ Documented all features, technical stack, and known limitations

## Creating the GitHub Draft Release

After this PR is merged, follow these steps to create the draft release on GitHub:

### Step 1: Push the Tag

The tag `v1.0.0` will be pushed when this PR is merged. Alternatively, you can push it manually:

```bash
git push origin v1.0.0
```

### Step 2: Create GitHub Release Draft

1. Go to: https://github.com/Rlahuerta/pdf-forensics-toolkit/releases/new
2. Select tag: `v1.0.0`
3. Release title: `v1.0.0 - Initial Stable Release`
4. Copy the release notes from `CHANGELOG.md` (section for v1.0.0)
5. Check the "Set as a pre-release" box if needed (optional for initial release)
6. Check "Save draft" to save without publishing
7. Click "Save draft" button

### Step 3: Review the Draft

Before publishing:
- Review all release notes for accuracy
- Test the release artifacts if applicable
- Verify all links work correctly
- Check that the tag points to the correct commit

### Step 4: Publish

When ready to publish:
1. Go to the draft release
2. Click "Edit"
3. Uncheck "Set as a pre-release" if it was checked
4. Click "Publish release"

## Release Contents

This release includes:
- Complete PDF forensic analysis toolkit
- Three command-line tools (pdf-forensics, verify-pdf-sig, compare-pdfs)
- Comprehensive test suite (63 tests)
- Full documentation in README.md
- CI/CD integration via GitHub Actions

## Next Steps

After publishing the release:
1. Announce the release (if applicable)
2. Update any external documentation
3. Monitor for issues and feedback
4. Plan for version 1.1.0 features

## Build and Distribution

Users can install from source:

```bash
# Clone repository
git clone https://github.com/Rlahuerta/pdf-forensics-toolkit.git
cd pdf-forensics-toolkit

# Checkout the release tag
git checkout v1.0.0

# Install
pip install .
```

Or use conda:

```bash
conda env create -f environment.yml -p ./pdf_forensics_env
conda activate ./pdf_forensics_env
```

## Version Numbering

This project follows [Semantic Versioning](https://semver.org/):
- **MAJOR** version (1.x.x): Incompatible API changes
- **MINOR** version (x.1.x): New functionality, backwards compatible
- **PATCH** version (x.x.1): Backwards compatible bug fixes

## Contact

For questions about this release, please open an issue on GitHub.
