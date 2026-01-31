# CI/CD Workflows

## CI Pipeline

The `ci.yml` workflow provides continuous integration for the PDF Forensics Toolkit.

### Triggers

- **Push events** to `main` and `dev` branches
- **Pull requests** targeting `main` and `dev` branches

### What it does

1. **Checkout code** - Retrieves the repository code
2. **Setup Conda** - Creates a conda environment from `environment.yml`
3. **Verify environment** - Lists installed packages for debugging
4. **Install system dependencies** - Installs `libmagic1` and `exiftool` required by the toolkit
5. **Run tests** - Executes the full test suite with coverage reporting
6. **Upload coverage** - Sends coverage data to Codecov (optional)

### Environment

- **OS**: Ubuntu Latest
- **Python**: 3.11 (via conda)
- **Dependencies**: Managed by `environment.yml` in the root directory

### Local Testing

To test the workflow locally before pushing:

```bash
# Validate YAML syntax
python -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))"

# Create conda environment
conda env create -f environment.yml -p ./pdf_forensics_env

# Activate environment
conda activate ./pdf_forensics_env

# Install system dependencies (Ubuntu/Debian)
sudo apt-get install -y libmagic1 exiftool

# Run tests
python -m pytest tests/ -v --cov=. --cov-report=term-missing
```

### Notes

- The workflow uses `bash -el {0}` shell for conda-related commands to ensure proper environment activation
- System dependencies (`libmagic1`, `exiftool`) are installed separately as they're not available via conda/pip
- Coverage upload to Codecov is optional and won't fail the build if the token is not configured
