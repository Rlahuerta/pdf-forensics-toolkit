#!/usr/bin/env python3
"""
Master script to generate all PDF test fixtures in sequence.

This orchestrates the complete test fixture generation pipeline,
calling each generation function and tracking progress/errors.

Usage:
    python scripts/generate_all_test_fixtures.py

Output:
    - Test PDFs in tests/fixtures/ directory
    - Progress report to stdout
"""

from generate_test_fixtures import (
    generate_signed_valid_pdf,
    generate_signed_invalid_pdf,
    generate_signed_expired_pdf,
    generate_javascript_pdf,
    generate_launch_action_pdf,
    generate_embedded_file_pdf,
    generate_uri_action_pdf,
    generate_hidden_layer_pdf,
    generate_invisible_text_pdf,
    generate_hidden_annotations_pdf,
    generate_creator_pdfs,
    generate_orphan_objects_pdf,
    generate_shadow_attack_pdf,
)
from pathlib import Path


def main():
    """Generate all test fixtures with progress tracking."""
    
    print("=" * 70)
    print("PDF FORENSICS TOOLKIT - TEST FIXTURE GENERATOR")
    print("=" * 70)
    
    fixtures_dir = Path('tests/fixtures')
    fixtures_dir.mkdir(parents=True, exist_ok=True)
    
    generated_count = 0
    failed_count = 0
    
    print(f"\n📁 Output directory: {fixtures_dir}")
    print()
    
    print("=" * 70)
    print("📝 PHASE 1: Digital Signatures")
    print("=" * 70)
    
    try:
        print("\n1. Valid signed PDF...")
        generate_signed_valid_pdf(str(fixtures_dir / 'signed_valid_test.pdf'))
        generated_count += 1
    except Exception as e:
        print(f"   ❌ FAILED: {e}")
        failed_count += 1
    
    try:
        print("\n2. Invalid signed PDF (tampered)...")
        signed_input = str(fixtures_dir / 'signed_valid_test.pdf')
        generate_signed_invalid_pdf(
            signed_input,
            str(fixtures_dir / 'signed_invalid_test.pdf')
        )
        generated_count += 1
    except Exception as e:
        print(f"   ❌ FAILED: {e}")
        failed_count += 1
    
    try:
        print("\n3. Expired certificate PDF...")
        generate_signed_expired_pdf(str(fixtures_dir / 'signed_expired_test.pdf'))
        generated_count += 1
    except Exception as e:
        print(f"   ❌ FAILED: {e}")
        failed_count += 1
    
    print("\n" + "=" * 70)
    print("⚠️  PHASE 2: Security Threats")
    print("=" * 70)
    
    try:
        print("\n4. Embedded JavaScript...")
        generate_javascript_pdf(str(fixtures_dir / 'javascript_test.pdf'))
        generated_count += 1
    except Exception as e:
        print(f"   ❌ FAILED: {e}")
        failed_count += 1
    
    try:
        print("\n5. Launch action (external program)...")
        generate_launch_action_pdf(str(fixtures_dir / 'launch_action_test.pdf'))
        generated_count += 1
    except Exception as e:
        print(f"   ❌ FAILED: {e}")
        failed_count += 1
    
    try:
        print("\n6. Embedded executable file...")
        generate_embedded_file_pdf(str(fixtures_dir / 'embedded_file_test.pdf'))
        generated_count += 1
    except Exception as e:
        print(f"   ❌ FAILED: {e}")
        failed_count += 1
    
    try:
        print("\n7. URI action (phishing redirect)...")
        generate_uri_action_pdf(str(fixtures_dir / 'uri_action_test.pdf'))
        generated_count += 1
    except Exception as e:
        print(f"   ❌ FAILED: {e}")
        failed_count += 1
    
    print("\n" + "=" * 70)
    print("👁️  PHASE 3: Hidden Content")
    print("=" * 70)
    
    try:
        print("\n8. Hidden OCG layers...")
        generate_hidden_layer_pdf(str(fixtures_dir / 'hidden_layer_test.pdf'))
        generated_count += 1
    except Exception as e:
        print(f"   ❌ FAILED: {e}")
        failed_count += 1
    
    try:
        print("\n9. Invisible text (rendering mode 3)...")
        generate_invisible_text_pdf(str(fixtures_dir / 'invisible_text_test.pdf'))
        generated_count += 1
    except Exception as e:
        print(f"   ❌ FAILED: {e}")
        failed_count += 1
    
    try:
        print("\n10. Hidden annotations...")
        generate_hidden_annotations_pdf(str(fixtures_dir / 'hidden_annotations_test.pdf'))
        generated_count += 1
    except Exception as e:
        print(f"   ❌ FAILED: {e}")
        failed_count += 1
    
    print("\n" + "=" * 70)
    print("🏢 PHASE 4: Diverse Creators")
    print("=" * 70)
    
    try:
        print("\n11. Creator pattern PDFs (6 variants)...")
        count = generate_creator_pdfs(str(fixtures_dir))
        generated_count += count
    except Exception as e:
        print(f"   ❌ FAILED: {e}")
        failed_count += 1
    
    print("\n" + "=" * 70)
    print("🔨 PHASE 5: Tampering Simulations")
    print("=" * 70)
    
    try:
        print("\n12. Orphan objects (deleted content)...")
        generate_orphan_objects_pdf(str(fixtures_dir / 'orphan_objects_test.pdf'))
        generated_count += 1
    except Exception as e:
        print(f"   ❌ FAILED: {e}")
        failed_count += 1
    
    try:
        print("\n13. Shadow attack (multiple content streams)...")
        generate_shadow_attack_pdf(str(fixtures_dir / 'shadow_attack_test.pdf'))
        generated_count += 1
    except Exception as e:
        print(f"   ❌ FAILED: {e}")
        failed_count += 1
    
    print("\n" + "=" * 70)
    print("✅ COMPLETE")
    print("=" * 70)
    print(f"\n📊 Summary:")
    print(f"   ✅ Generated: {generated_count} fixtures")
    if failed_count > 0:
        print(f"   ❌ Failed:    {failed_count} fixtures")
    print(f"\n📁 Location: {fixtures_dir.resolve()}")
    print()


if __name__ == '__main__':
    main()
