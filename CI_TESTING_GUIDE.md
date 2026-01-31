# CI Pipeline Testing Guide

This guide explains how to verify the CI pipeline is working correctly.

## Quick Validation

Run the validation script to check the CI configuration:

```bash
python scripts/validate_ci.py
```

This will verify:
- CI workflow file syntax and structure
- Environment configuration
- Test structure
- Documentation presence

## Local Testing (Full Simulation)

To simulate what the CI pipeline does locally:

### 1. Install System Dependencies

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y libmagic1 exiftool

# macOS
brew install libmagic exiftool
```

### 2. Create Conda Environment

```bash
# Create environment (first time)
conda env create -f environment.yml -n pdf-forensics-toolkit

# Activate environment
conda activate pdf-forensics-toolkit
```

### 3. Verify Installation

```bash
# Check Python version
python --version

# List installed packages
conda list

# Verify key packages
python -c "import pymupdf; print('PyMuPDF version:', pymupdf.version[0])"
python -c "import pikepdf; print('pikepdf version:', pikepdf.__version__)"
python -c "import pytest; print('pytest version:', pytest.__version__)"
```

### 4. Run Tests

```bash
# Run all tests with coverage
python -m pytest tests/ -v --cov=pdf_forensics --cov=pdf_source_identifier --cov=verify_signature --cov=compare_pdfs --cov-report=term-missing

# Run specific test file
python -m pytest tests/test_pdf_source_identifier.py -v

# Run specific test class
python -m pytest tests/test_pdf_source_identifier.py::TestDetectTamperingIndicators -v
```

## GitHub Actions Testing

Once the dev branch is created and this PR is merged:

### 1. Push a Test Commit

```bash
# Switch to dev branch
git checkout dev

# Make a small change (e.g., update README)
echo "# Test CI" >> TEST_CI.md
git add TEST_CI.md
git commit -m "Test CI pipeline"
git push origin dev
```

### 2. Check Workflow Status

Go to: `https://github.com/Rlahuerta/pdf-forensics-toolkit/actions`

You should see:
- A new workflow run triggered by your commit
- The workflow running through all steps
- Green checkmarks when tests pass

### 3. View Workflow Logs

Click on the workflow run to see:
- Checkout code (should succeed)
- Setup Conda (shows package installation)
- Verify conda environment (lists installed packages)
- Install system dependencies (installs libmagic1, exiftool)
- Run tests (shows pytest output)
- Upload coverage (optional, depends on Codecov token)

## Troubleshooting

### Workflow Fails on "Setup Conda"

**Problem**: Conda environment creation fails

**Solutions**:
- Check `environment.yml` is valid YAML
- Verify all package versions are available
- Check conda channels are accessible

### Workflow Fails on "Install system dependencies"

**Problem**: apt-get fails to install packages

**Solutions**:
- Check package names are correct
- Verify Ubuntu runner has access to repositories
- Try updating apt cache first

### Workflow Fails on "Run tests"

**Problem**: Tests fail or import errors

**Solutions**:
- Check conda environment activated correctly
- Verify `shell: bash -el {0}` is set for conda commands
- Check test fixtures exist in `tests/fixtures/`
- Review pytest output for specific errors

### Local Tests Pass but CI Fails

**Possible causes**:
- Different Python or package versions
- Missing system dependencies
- Test fixtures not committed to git
- Environment variables not set

**Debug steps**:
1. Check conda environment in CI logs
2. Compare package versions with local
3. Verify all test files are committed
4. Check for hardcoded paths in tests

## Expected Test Results

When all tests pass, you should see:

```
======================= test session starts ========================
collected 63 items

tests/test_compare_pdfs.py::test_extract_metadata PASSED     [  1%]
tests/test_compare_pdfs.py::test_compare_pdfs PASSED         [  3%]
...
tests/test_verify_signature.py::test_extract_signatures PASSED [100%]

===================== 63 passed in X.XXs ========================
```

## CI Pipeline Status Badge

After verifying the CI works, add this badge to README.md:

```markdown
[![CI](https://github.com/Rlahuerta/pdf-forensics-toolkit/workflows/CI/badge.svg)](https://github.com/Rlahuerta/pdf-forensics-toolkit/actions)
```

## Coverage Reports

If Codecov is configured:

1. Add `CODECOV_TOKEN` to repository secrets
2. View coverage at: `https://codecov.io/gh/Rlahuerta/pdf-forensics-toolkit`
3. Add coverage badge to README.md:

```markdown
[![codecov](https://codecov.io/gh/Rlahuerta/pdf-forensics-toolkit/branch/main/graph/badge.svg)](https://codecov.io/gh/Rlahuerta/pdf-forensics-toolkit)
```

## Maintenance

### Updating Dependencies

When updating `environment.yml`:

1. Test locally first
2. Push to dev branch
3. Verify CI passes
4. Merge to main

### Adding New Tests

1. Add test files in `tests/` directory
2. Follow naming convention: `test_*.py`
3. CI will automatically discover and run them

### Modifying CI Workflow

1. Edit `.github/workflows/ci.yml`
2. Validate with: `python scripts/validate_ci.py`
3. Test locally if possible
4. Push to dev branch and verify
