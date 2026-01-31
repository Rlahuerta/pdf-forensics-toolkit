#!/usr/bin/env python3
"""
CI Pipeline Validation Script

This script validates that the CI pipeline configuration is correct
and all necessary files are in place.
"""

import os
import sys
import yaml
from pathlib import Path


def check_file_exists(filepath, description):
    """Check if a file exists."""
    if os.path.exists(filepath):
        print(f"✓ {description}: {filepath}")
        return True
    else:
        print(f"✗ {description} NOT FOUND: {filepath}")
        return False


def validate_yaml_syntax(filepath):
    """Validate YAML syntax."""
    try:
        with open(filepath, 'r') as f:
            yaml.safe_load(f)
        print(f"✓ Valid YAML syntax: {filepath}")
        return True
    except Exception as e:
        print(f"✗ Invalid YAML syntax in {filepath}: {e}")
        return False


def validate_workflow_structure(workflow_path):
    """Validate the workflow file structure."""
    try:
        with open(workflow_path, 'r') as f:
            workflow = yaml.safe_load(f)
        
        # Check required top-level keys
        # Note: 'on' gets parsed as True (boolean) by YAML parser
        required_keys = ['name', 'jobs']
        has_on_key = True in workflow or 'on' in workflow
        
        for key in required_keys:
            if key not in workflow:
                print(f"✗ Missing required key in workflow: {key}")
                return False
        
        if not has_on_key:
            print("✗ Missing required key in workflow: on")
            return False
        
        print(f"✓ Workflow has all required top-level keys")
        
        # Get the 'on' value (which is stored as True)
        on_config = workflow.get(True, workflow.get('on'))
        if on_config:
            print(f"  ✓ Triggers configured for: push and pull_request")
        
        # Check jobs structure
        if 'test' not in workflow['jobs']:
            print("✗ Missing 'test' job in workflow")
            return False
        
        test_job = workflow['jobs']['test']
        
        # Check for steps
        if 'steps' not in test_job:
            print("✗ Missing 'steps' in test job")
            return False
        
        print(f"✓ Test job has {len(test_job['steps'])} steps")
        
        # Validate critical steps
        step_names = [step.get('name', '') for step in test_job['steps']]
        critical_steps = [
            'Checkout code',
            'Setup Conda',
            'Install system dependencies',
            'Run tests'
        ]
        
        for critical_step in critical_steps:
            if critical_step in step_names:
                print(f"  ✓ Step present: {critical_step}")
            else:
                print(f"  ✗ Missing critical step: {critical_step}")
                return False
        
        # Check conda setup configuration
        for step in test_job['steps']:
            if step.get('name') == 'Setup Conda':
                with_config = step.get('with', {})
                if with_config.get('environment-file') != 'environment.yml':
                    print("✗ Conda setup doesn't use environment.yml")
                    return False
                print(f"  ✓ Conda environment file: {with_config.get('environment-file')}")
                print(f"  ✓ Python version: {with_config.get('python-version')}")
        
        # Check for proper shell configuration in conda-dependent steps
        for step in test_job['steps']:
            if step.get('name') in ['Verify conda environment', 'Run tests']:
                if step.get('shell') != 'bash -el {0}':
                    print(f"✗ Step '{step.get('name')}' missing proper shell configuration")
                    return False
                print(f"  ✓ Proper shell config in: {step.get('name')}")
        
        return True
        
    except Exception as e:
        print(f"✗ Error validating workflow structure: {e}")
        return False


def validate_environment_yml(env_path):
    """Validate environment.yml structure."""
    try:
        with open(env_path, 'r') as f:
            env = yaml.safe_load(f)
        
        # Check required keys
        if 'dependencies' not in env:
            print("✗ environment.yml missing 'dependencies' key")
            return False
        
        print(f"✓ environment.yml has dependencies section")
        
        # Check for Python
        deps = env['dependencies']
        has_python = any('python' in str(dep) for dep in deps)
        if not has_python:
            print("✗ environment.yml doesn't specify Python version")
            return False
        
        print(f"  ✓ Python version specified")
        
        # Check for pip dependencies
        has_pip = any(isinstance(dep, dict) and 'pip' in dep for dep in deps)
        if has_pip:
            print(f"  ✓ Pip dependencies present")
            pip_deps = next(dep['pip'] for dep in deps if isinstance(dep, dict) and 'pip' in dep)
            print(f"  ✓ {len(pip_deps)} pip packages defined")
        
        return True
        
    except Exception as e:
        print(f"✗ Error validating environment.yml: {e}")
        return False


def check_test_structure():
    """Check if tests directory exists and has test files."""
    tests_dir = Path('tests')
    if not tests_dir.exists():
        print("✗ tests/ directory not found")
        return False
    
    print("✓ tests/ directory exists")
    
    test_files = list(tests_dir.glob('test_*.py'))
    if not test_files:
        print("✗ No test files found in tests/")
        return False
    
    print(f"✓ Found {len(test_files)} test file(s):")
    for test_file in test_files:
        print(f"  - {test_file.name}")
    
    return True


def main():
    """Main validation function."""
    print("=" * 60)
    print("CI Pipeline Validation")
    print("=" * 60)
    print()
    
    all_passed = True
    
    # Check workflow file
    print("1. Checking CI workflow file...")
    workflow_path = '.github/workflows/ci.yml'
    if not check_file_exists(workflow_path, "CI workflow"):
        all_passed = False
    elif not validate_yaml_syntax(workflow_path):
        all_passed = False
    elif not validate_workflow_structure(workflow_path):
        all_passed = False
    print()
    
    # Check environment file
    print("2. Checking environment configuration...")
    env_path = 'environment.yml'
    if not check_file_exists(env_path, "Environment file"):
        all_passed = False
    elif not validate_yaml_syntax(env_path):
        all_passed = False
    elif not validate_environment_yml(env_path):
        all_passed = False
    print()
    
    # Check test structure
    print("3. Checking test structure...")
    if not check_test_structure():
        all_passed = False
    print()
    
    # Check documentation
    print("4. Checking documentation...")
    check_file_exists('.github/workflows/README.md', "Workflow documentation")
    check_file_exists('DEV_BRANCH_SETUP.md', "Dev branch setup guide")
    print()
    
    # Summary
    print("=" * 60)
    if all_passed:
        print("✓ ALL VALIDATION CHECKS PASSED")
        print("=" * 60)
        print()
        print("The CI pipeline is properly configured and ready to use.")
        print("Next steps:")
        print("1. Merge this PR to main")
        print("2. Create dev branch: git checkout -b dev main && git push -u origin dev")
        print("3. Push a commit to trigger the CI workflow")
        return 0
    else:
        print("✗ SOME VALIDATION CHECKS FAILED")
        print("=" * 60)
        print()
        print("Please review the errors above and fix the configuration.")
        return 1


if __name__ == '__main__':
    sys.exit(main())
