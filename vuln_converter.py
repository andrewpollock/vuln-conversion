#!/usr/bin/python

from vuln_conversion import convert_cve_to_osv, convert_osv_to_cve
from vuln_conversion_test import TestCveOsvConverter
import json

if __name__ == '__main__':
    # Example Usage:
    # Note: The sample_cve_v5_record and sample_osv_record are defined in the TestCveOsvConverter class.
    # You would load your actual JSON data here.
    
    # Create an instance of the test class to access its data
    test_data_provider = TestCveOsvConverter()
    test_data_provider.setUp() # Initialize the sample data

    print("--- CVE to OSV Conversion Example ---")
    try:
        sample_cve_json = test_data_provider.sample_cve_v5_record
        print(f"Input CVE JSON (partial): {json.dumps(sample_cve_json['cveMetadata'], indent=2)}")
        osv_output = convert_cve_to_osv(sample_cve_json)
        print("\nOutput OSV JSON:")
        print(json.dumps(osv_output, indent=2))
    except Exception as e:
        print(f"Error during CVE to OSV conversion: {e}")

    print("\n\n--- OSV to CVE Conversion Example ---")
    try:
        sample_osv_json = test_data_provider.sample_osv_record
        print(f"Input OSV JSON (partial): {{'id': '{sample_osv_json['id']}', 'summary': '{sample_osv_json['summary']}'}}")
        cve_output = convert_osv_to_cve(sample_osv_json)
        print("\nOutput CVE JSON:")
        print(json.dumps(cve_output, indent=2))
    except Exception as e:
        print(f"Error during OSV to CVE conversion: {e}")

