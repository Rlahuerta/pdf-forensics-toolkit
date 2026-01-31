# Verification Pipeline Documentation

## Overview

This document describes the automated verification pipeline that ensures all code modifications to the PDF Forensics Toolkit are correct and maintain quality standards.

## Pipeline Location

- **File**: `.github/workflows/verify-modifications.yml`
- **Type**: GitHub Actions workflow
- **Status Badge**: Displayed at the top of README.md

## Trigger Conditions

The pipeline runs automatically on:

1. **Push events** to:
   - `main` branch
   - `develop` branch
   - Any `copilot/**` branch

2. **Pull request events** targeting:
   - `main` branch
   - `develop` branch

3. **Manual trigger** via `workflow_dispatch`

## Verification Steps

The pipeline performs the following verification steps in order:

### 1. Checkout Code
Uses `actions/checkout@v4` to clone the repository.

### 2. Set up Python 3.11
Installs Python 3.11 (matching `environment.yml` specification) with pip caching enabled.

### 3. Install System Dependencies
Installs required system packages:
- `libmagic1` - File type detection
- `exiftool` - Metadata extraction

### 4. Install Python Dependencies
Installs all packages specified in `environment.yml`:
- PyMuPDF, pikepdf, pdfplumber, pypdf - PDF parsing
- pyHanko, cryptography, endesive - Digital signatures
- pytest, pytest-cov - Testing framework
- And 10+ more packages

### 5. Verify Python Syntax
Compiles all Python source files to check for syntax errors:
- `pdf_source_identifier.py`
- `verify_signature.py`
- `compare_pdfs.py`
- All files in `pdf_forensics/` package

### 6. Run Test Suite
Executes the complete pytest test suite with verbose output:
- 63+ tests across 3 test files
- Short traceback format for clarity
- Fails if any test fails

### 7. Run Tests with Coverage
Generates code coverage reports:
- Terminal output with missing lines
- XML format for CI systems
- Helps identify untested code

### 8. Display Coverage Summary
Shows coverage percentage and summary (always runs, even if previous step fails).

### 9. Check for Critical Files
Verifies all essential files and directories exist:
- Main scripts: `pdf_source_identifier.py`, `verify_signature.py`, `compare_pdfs.py`
- Package directory: `pdf_forensics/`
- Test directory: `tests/`

### 10. Validation Summary
Displays a success message if all checks pass.

## Expected Outcomes

### ✅ Success
When all checks pass:
- Badge shows green "passing"
- Summary displays success message
- PR is ready for review

### ❌ Failure
When any check fails:
- Badge shows red "failing"
- Detailed error logs are available
- PR should not be merged until fixed

### 🟡 In Progress
While pipeline is running:
- Badge shows yellow "running"
- Wait for completion before reviewing

## Running Locally

To run the same checks locally before pushing:

```bash
# 1. Activate environment
conda activate ./pdf_forensics_env

# 2. Validate syntax
python -m py_compile pdf_source_identifier.py verify_signature.py compare_pdfs.py
python -m py_compile pdf_forensics/*.py

# 3. Run tests
python -m pytest tests/ -v

# 4. Check coverage
python -m pytest tests/ --cov=. --cov-report=term-missing
```

## Maintenance

### Adding New Checks

To add a new verification step:

1. Edit `.github/workflows/verify-modifications.yml`
2. Add a new step under the `steps:` section
3. Test locally first if possible
4. Update this documentation

### Updating Dependencies

When updating `environment.yml`:

1. Also update the "Install Python dependencies" step in the workflow
2. Keep versions in sync
3. Test the workflow after changes

### Modifying Triggers

To change when the pipeline runs:

1. Edit the `on:` section in the workflow file
2. Use GitHub Actions syntax for events
3. Common events: `push`, `pull_request`, `schedule`, `workflow_dispatch`

## Troubleshooting

### Pipeline Fails on Dependency Installation

- Check that all dependencies in `environment.yml` are available on PyPI
- Verify version constraints are correct
- Some packages may require system dependencies

### Pipeline Fails on Tests

- Run tests locally to reproduce the issue
- Check if test fixtures are included in the repository
- Verify the `tests/fixtures/` directory is committed

### Pipeline Times Out

- Default timeout is 6 hours (GitHub Actions default)
- If needed, add `timeout-minutes:` to the job
- Consider splitting into multiple jobs if very slow

## Benefits

This verification pipeline provides:

1. **Automated Quality Checks**: Every change is automatically tested
2. **Early Detection**: Catch issues before merge
3. **Consistency**: Same checks run for everyone
4. **Documentation**: Clear pass/fail status
5. **Confidence**: Know that tests pass on a clean system

## Version History

- **2026-01-31**: Initial implementation
  - Python syntax validation
  - Pytest test suite execution
  - Code coverage reporting
  - Critical file verification
  - Clear success/failure messages
