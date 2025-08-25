#!/usr/bin/env python3
"""CLI tool to verify SAFECode-Web API against test corpus."""

import argparse
import json
import sys
import time
from typing import Dict, List, Optional
import requests
from pathlib import Path


class APIVerifier:
    """Verify API functionality against test corpus."""
    
    def __init__(self, base_url: str, api_token: Optional[str] = None):
        """
        Initialize API verifier.
        
        Args:
            base_url: Base URL of the API
            api_token: Optional API token for authentication
        """
        self.base_url = base_url.rstrip('/')
        self.api_token = api_token
        self.session = requests.Session()
        
        if api_token:
            self.session.headers.update({
                'Authorization': f'Bearer {api_token}'
            })
    
    def test_health(self) -> bool:
        """Test health endpoint."""
        try:
            response = self.session.get(f"{self.base_url}/health", timeout=10)
            if response.status_code == 200:
                data = response.json()
                print(f"✓ Health check passed: {data.get('status', 'unknown')}")
                return True
            else:
                print(f"✗ Health check failed: {response.status_code}")
                return False
        except Exception as e:
            print(f"✗ Health check error: {e}")
            return False
    
    def test_scan(self, filename: str, code: str, expected_cwe: str, 
                  expected_status: str, description: str) -> Dict:
        """
        Test scan endpoint with a test case.
        
        Args:
            filename: Test file name
            code: Source code to scan
            expected_cwe: Expected CWE
            expected_status: Expected finding status
            description: Test description
            
        Returns:
            Dict: Test result
        """
        try:
            payload = {
                "filename": filename,
                "code": code,
                "ruleset": "p/security-audit"
            }
            
            response = self.session.post(
                f"{self.base_url}/scan",
                json=payload,
                timeout=30
            )
            
            if response.status_code != 200:
                return {
                    "success": False,
                    "error": f"HTTP {response.status_code}: {response.text}"
                }
            
            data = response.json()
            findings = data.get('findings', [])
            
            # Look for expected CWE
            matching_findings = [
                f for f in findings 
                if f.get('cwe_id') == expected_cwe
            ]
            
            if not matching_findings:
                return {
                    "success": False,
                    "error": f"No findings for CWE {expected_cwe}"
                }
            
            # Check status
            actual_status = matching_findings[0].get('status', 'UNKNOWN')
            status_match = actual_status == expected_status
            
            return {
                "success": True,
                "status_match": status_match,
                "expected_status": expected_status,
                "actual_status": actual_status,
                "findings_count": len(findings),
                "matching_findings": len(matching_findings)
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def run_corpus_tests(self, corpus_path: str) -> Dict:
        """
        Run tests against the corpus.
        
        Args:
            corpus_path: Path to corpus manifest file
            
        Returns:
            Dict: Test results summary
        """
        print(f"Running corpus tests from: {corpus_path}")
        
        if not Path(corpus_path).exists():
            return {
                "success": False,
                "error": f"Corpus file not found: {corpus_path}"
            }
        
        test_results = []
        passed = 0
        failed = 0
        
        with open(corpus_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                
                try:
                    test_case = json.loads(line)
                except json.JSONDecodeError as e:
                    print(f"✗ Invalid JSON on line {line_num}: {e}")
                    failed += 1
                    continue
                
                filename = test_case.get('filename', f'test_{line_num}')
                code = test_case.get('code', '')
                expected_cwe = test_case.get('expected_cwe', '')
                expected_status = test_case.get('expected_status', 'ACTIVE')
                description = test_case.get('description', 'No description')
                
                print(f"\nTesting: {filename} - {description}")
                print(f"Expected: CWE {expected_cwe}, Status {expected_status}")
                
                result = self.test_scan(
                    filename, code, expected_cwe, expected_status, description
                )
                
                if result['success']:
                    if result['status_match']:
                        print(f"✓ PASS: Status {result['actual_status']} matches expected {result['expected_status']}")
                        passed += 1
                    else:
                        print(f"✗ FAIL: Status {result['actual_status']} does not match expected {result['expected_status']}")
                        failed += 1
                else:
                    print(f"✗ ERROR: {result['error']}")
                    failed += 1
                
                test_results.append({
                    'filename': filename,
                    'description': description,
                    'result': result
                })
                
                # Small delay between requests
                time.sleep(0.5)
        
        return {
            "success": True,
            "total": len(test_results),
            "passed": passed,
            "failed": failed,
            "results": test_results
        }
    
    def test_metrics(self) -> bool:
        """Test metrics endpoint."""
        try:
            response = self.session.get(f"{self.base_url}/metrics", timeout=10)
            if response.status_code == 200:
                data = response.json()
                print(f"✓ Metrics endpoint working: {data.get('scan_requests_total', 0)} total scans")
                return True
            else:
                print(f"✗ Metrics endpoint failed: {response.status_code}")
                return False
        except Exception as e:
            print(f"✗ Metrics endpoint error: {e}")
            return False
    
    def test_alerts(self) -> bool:
        """Test alerts endpoint."""
        try:
            response = self.session.get(f"{self.base_url}/alerts", timeout=10)
            if response.status_code == 200:
                data = response.json()
                print(f"✓ Alerts endpoint working: {data.get('total', 0)} alerts")
                return True
            else:
                print(f"✗ Alerts endpoint failed: {response.status_code}")
                return False
        except Exception as e:
            print(f"✗ Alerts endpoint error: {e}")
            return False


def main():
    """Main CLI function."""
    parser = argparse.ArgumentParser(
        description="Verify SAFECode-Web API against test corpus"
    )
    parser.add_argument(
        "--base-url",
        default="http://localhost:8001",
        help="Base URL of the API (default: http://localhost:8001)"
    )
    parser.add_argument(
        "--corpus",
        default="tests/corpus/manifest.jsonl",
        help="Path to corpus manifest file (default: tests/corpus/manifest.jsonl)"
    )
    parser.add_argument(
        "--token",
        help="API token for authentication"
    )
    parser.add_argument(
        "--health-only",
        action="store_true",
        help="Only run health check"
    )
    
    args = parser.parse_args()
    
    print("SAFECode-Web API Verification Tool")
    print("=" * 40)
    
    verifier = APIVerifier(args.base_url, args.token)
    
    # Test health endpoint
    if not verifier.test_health():
        print("Health check failed. Is the API running?")
        sys.exit(1)
    
    if args.health_only:
        print("Health check passed!")
        sys.exit(0)
    
    # Test other endpoints
    verifier.test_metrics()
    verifier.test_alerts()
    
    # Run corpus tests
    print("\n" + "=" * 40)
    corpus_result = verifier.run_corpus_tests(args.corpus)
    
    if not corpus_result['success']:
        print(f"Corpus test failed: {corpus_result['error']}")
        sys.exit(1)
    
    # Print summary
    print("\n" + "=" * 40)
    print("TEST SUMMARY")
    print("=" * 40)
    print(f"Total tests: {corpus_result['total']}")
    print(f"Passed: {corpus_result['passed']}")
    print(f"Failed: {corpus_result['failed']}")
    
    if corpus_result['failed'] > 0:
        print("\nFAILED TESTS:")
        for result in corpus_result['results']:
            if not result['result']['success'] or not result['result'].get('status_match', True):
                print(f"  - {result['filename']}: {result['description']}")
                if 'error' in result['result']:
                    print(f"    Error: {result['result']['error']}")
    
    # Exit with appropriate code
    if corpus_result['failed'] > 0:
        print(f"\n❌ {corpus_result['failed']} tests failed")
        sys.exit(1)
    else:
        print(f"\n✅ All {corpus_result['total']} tests passed!")
        sys.exit(0)


if __name__ == "__main__":
    main()
