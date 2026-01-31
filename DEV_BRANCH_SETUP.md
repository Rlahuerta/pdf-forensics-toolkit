# Dev Branch Setup Instructions

## Overview

This document explains how to set up the `dev` branch from `main` (or `master`) for the PDF Forensics Toolkit repository.

## Automatic Setup (Recommended)

Once this PR is merged to `main`, the `dev` branch can be created automatically:

### Option 1: Via GitHub Web Interface

1. Go to https://github.com/Rlahuerta/pdf-forensics-toolkit
2. Click on the branch dropdown (currently showing "main")
3. Type "dev" in the text field
4. Click "Create branch: dev from main"

### Option 2: Via Command Line

```bash
# Clone the repository (if not already cloned)
git clone https://github.com/Rlahuerta/pdf-forensics-toolkit.git
cd pdf-forensics-toolkit

# Fetch the latest changes
git fetch origin

# Create dev branch from main
git checkout -b dev origin/main

# Push the dev branch to remote
git push -u origin dev
```

## Manual Setup (Current State)

Since we cannot push branches directly from this environment, the dev branch has been created locally but needs to be pushed to the remote repository with proper permissions.

### Steps for Repository Owner

1. Pull this PR branch:
   ```bash
   git fetch origin copilot/add-ci-pipeline-conda-venv
   git checkout copilot/add-ci-pipeline-conda-venv
   ```

2. Create and push the dev branch:
   ```bash
   # Create dev branch from main
   git checkout -b dev main
   
   # Push to remote
   git push -u origin dev
   ```

3. Merge the PR to main (which includes the CI workflow)

## What's Included

The CI pipeline has been set up with:

- **GitHub Actions workflow** (`.github/workflows/ci.yml`)
- **Triggers**: Push/PR to `main` and `dev` branches
- **Conda environment**: Uses `environment.yml` for dependency management
- **Testing**: Full pytest suite with coverage reporting
- **System dependencies**: Automatic installation of `libmagic1` and `exiftool`

## Verifying the Setup

After creating the dev branch and merging this PR:

1. Push a commit to the `dev` branch
2. Go to the "Actions" tab in GitHub
3. Verify that the CI workflow runs successfully
4. Check that all tests pass

## CI Pipeline Features

- ✅ Conda environment creation from `environment.yml`
- ✅ Python 3.11 installation
- ✅ System dependency installation
- ✅ Full test suite execution
- ✅ Code coverage reporting
- ✅ Optional Codecov integration

## Next Steps

1. Merge this PR to `main`
2. Create the `dev` branch from `main` (see instructions above)
3. Configure branch protection rules (optional):
   - Require PR reviews before merging
   - Require status checks to pass (CI workflow)
   - Enable automatic deletion of merged branches

## Troubleshooting

If the CI workflow fails:

1. Check the Actions tab for detailed logs
2. Verify `environment.yml` is valid
3. Ensure all test fixtures are present in `tests/fixtures/`
4. Check that system dependencies are correctly installed

For local testing, follow the instructions in `.github/workflows/README.md`.
