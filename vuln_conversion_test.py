#!/usr/bin/python

import unittest
from vuln_conversion import convert_cve_to_osv, convert_osv_to_cve, get_nested_value

class TestCveOsvConverter(unittest.TestCase):

    def setUp(self):
        self.sample_cve_v5_record = {
            "dataType": "CVE_RECORD",
            "dataVersion": "5.0",
            "cveMetadata": {
                "cveId": "CVE-2023-12345",
                "assignerOrgId": "82542616-A862-4554-B7CD-13553A76EA70",
                "assignerShortName": "ExampleCNA",
                "state": "PUBLISHED",
                "datePublished": "2023-01-15T08:00:00.000Z",
                "dateUpdated": "2023-01-20T10:30:00.000Z",
                "dateReserved": "2023-01-01T00:00:00.000Z"
            },
            "containers": {
                "cna": {
                    "providerMetadata": {
                        "orgId": "82542616-A862-4554-B7CD-13553A76EA70",
                        "shortName": "ExampleCNA",
                        "dateUpdated": "2023-01-20T10:30:00.000Z"
                    },
                    "title": "Sample Vulnerability Title",
                    "descriptions": [
                        {
                            "lang": "en",
                            "value": "A sample vulnerability description. This is the first sentence. This is the second sentence."
                        },
                        {
                            "lang": "es",
                            "value": "Descripción de vulnerabilidad de muestra."
                        }
                    ],
                    "affected": [
                        {
                            "vendor": "TestVendor",
                            "product": "ProductA",
                            "packageName": "go/example.com/producta",
                            "platforms": ["Linux", "Windows"],
                            "versions": [
                                {
                                    "status": "affected",
                                    "versionType": "semver",
                                    "version": "1.0.0",
                                    "lessThan": "1.5.0"
                                },
                                {
                                    "status": "affected",
                                    "version": "2.0.0"
                                }
                            ],
                            "defaultStatus": "affected"
                        },
                        {
                            "vendor": "TestVendor",
                            "product": "ProductB",
                            "versions": [
                                 {
                                     "status": "affected",
                                     "version": "0", # Indicates all versions starting from 0
                                     "lessThanOrEqual": "2.2.1"
                                 }
                            ]
                        },
                        {
                            "vendor": "TestVendor",
                            "product": "ProductC-Wildcard",
                             "versions": [
                                 {
                                     "status": "affected",
                                     "version": "3.3.*"
                                 }
                             ]
                        }
                    ],
                    "problemTypes": [
                        {
                            "description": [
                                {
                                    "type": "CWE",
                                    "lang": "en",
                                    "description": "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
                                    "cweId": "CWE-79"
                                }
                            ]
                        }
                    ],
                    "references": [
                        {
                            "url": "https://example.com/advisory/123",
                            "name": "Example Advisory",
                            "tags": ["vendor-advisory"]
                        },
                        {
                            "url": "https://example.com/fix/patch1",
                            "tags": ["patch"]
                        }
                    ],
                    "metrics": [
                        {
                            "format": "CVSS",
                            "scenarios": [{"lang": "en", "value": "General"}],
                            "cvssV3_1": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                # ... other fields
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL"
                            }
                        }
                    ],
                    "credits": [
                        {
                            "lang": "en",
                            "type": "finder",
                            "user": "finder_user_id",
                            "value": "Credit to the finder."
                        }
                    ],
                    "source": {
                        "advisory": "EXCNA-001",
                        "discovery": "INTERNAL"
                    }
                }
            }
        }

        self.sample_osv_record = {
            "schema_version": "1.4.0",
            "id": "CVE-2023-12345",
            "modified": "2023-01-20T10:30:00.000Z",
            "published": "2023-01-15T08:00:00.000Z",
            "aliases": ["GHSA-xxxx-yyyy-zzzz"],
            "summary": "A sample vulnerability description.", # Shortened for OSV
            "details": "A sample vulnerability description. This is the first sentence. This is the second sentence.",
            "affected": [
                {
                    "package": {
                        "ecosystem": "go/example.com/producta", # Mapped from packageName
                        "name": "ProductA"
                    },
                    "ranges": [
                        {
                            "type": "SEMVER",
                            "events": [
                                {"introduced": "1.0.0"},
                                {"limit": "1.5.0"}
                            ]
                        }
                    ],
                    "versions": ["2.0.0"] # Specific affected version
                },
                { # Product B
                    "package": {
                        "ecosystem": "Unknown", # No packageName provided
                        "name": "ProductB"
                    },
                     "ranges": [
                        {
                            "type": "ECOSYSTEM", # Defaulting, could be SEMVER if known
                            "events": [
                                {"introduced": "0"},
                                {"last_affected": "2.2.1"}
                            ]
                        }
                    ]
                },
                 { # Product C Wildcard
                    "package": {
                        "ecosystem": "Unknown",
                        "name": "ProductC-Wildcard"
                    },
                     "ranges": [
                        {
                            "type": "SEMVER",
                            "events": [
                                {"introduced": "3.3.0"}, # Assuming 3.3.* means from 3.3.0
                                {"limit": "3.4.0"}    # And up to (exclusive) next minor
                            ]
                        }
                    ]
                }
            ],
            "references": [
                {"type": "ADVISORY", "url": "https://example.com/advisory/123"},
                {"type": "FIX", "url": "https://example.com/fix/patch1"}
            ],
            "severity": [
                {
                    "type": "CVSS_V3",
                    "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                }
            ],
            "credits": [
                {
                    "name": "Credit to the finder.",
                    "type": "FINDER"
                }
            ],
            "database_specific": {
                "cwe_details": ["CWE-79"],
                "provider_metadata": {
                     "orgId": "82542616-A862-4554-B7CD-13553A76EA70",
                     "shortName": "ExampleCNA",
                     "dateUpdated": "2023-01-20T10:30:00.000Z"
                }
            }
        }
        
        self.sample_cve_rejected = {
            "dataType": "CVE_RECORD",
            "dataVersion": "5.0",
            "cveMetadata": {
                "cveId": "CVE-2023-99999",
                "assignerOrgId": "test-org-id",
                "assignerShortName": "TESTCNA",
                "state": "REJECTED",
                "datePublished": "2023-02-01T00:00:00Z",
                "dateUpdated": "2023-02-02T00:00:00Z"
            },
            "containers": {
                "cna": {
                    "providerMetadata": {
                        "orgId": "test-org-id",
                        "shortName": "TESTCNA",
                        "dateUpdated": "2023-02-02T00:00:00Z"
                    },
                    "rejectedReasons": [
                        {"lang": "en", "value": "This CVE ID is rejected because it is a duplicate of CVE-xxxx-yyyy."}
                    ],
                    "descriptions": [ # Some CNAs put rejection reason in description
                         {"lang": "en", "value": "REJECTED ** This CVE ID is rejected because it is a duplicate of CVE-xxxx-yyyy."}
                    ]
                }
            }
        }

        self.sample_osv_withdrawn = {
            "schema_version": "1.5.0",
            "id": "CVE-2023-99999",
            "modified": "2023-02-02T00:00:00Z",
            "published": "2023-02-01T00:00:00Z",
            "withdrawn": "2023-02-02T00:00:00Z",
            "details": "REJECTED ** This CVE ID is rejected because it is a duplicate of CVE-xxxx-yyyy."
            # summary might also be present
        }


    def test_cve_to_osv_conversion_id(self):
        osv_result = convert_cve_to_osv(self.sample_cve_v5_record)
        self.assertEqual(osv_result["id"], self.sample_cve_v5_record["cveMetadata"]["cveId"])

    def test_cve_to_osv_conversion_dates(self):
        osv_result = convert_cve_to_osv(self.sample_cve_v5_record)
        self.assertEqual(osv_result["published"], self.sample_cve_v5_record["cveMetadata"]["datePublished"])
        self.assertEqual(osv_result["modified"], self.sample_cve_v5_record["cveMetadata"]["dateUpdated"])

    def test_cve_to_osv_description_and_summary(self):
        osv_result = convert_cve_to_osv(self.sample_cve_v5_record)
        expected_details = "A sample vulnerability description. This is the first sentence. This is the second sentence."
        expected_summary = "A sample vulnerability description." # First sentence
        self.assertEqual(osv_result["details"], expected_details)
        self.assertEqual(osv_result["summary"], expected_summary)

    def test_cve_to_osv_affected_packages_and_versions(self):       
        osv_result = convert_cve_to_osv(self.sample_cve_v5_record)
        self.assertTrue(len(osv_result["affected"]) >= 2) # At least ProductA and ProductB

        # ProductA checks
        product_a_osv = next((p for p in osv_result["affected"] if p["package"]["name"] == "ProductA"), None)
        self.assertIsNotNone(product_a_osv)
        self.assertEqual(product_a_osv["package"]["ecosystem"], "go/example.com/producta")
        
        # Range: 1.0.0 to <1.5.0
        range1_found = any(
            r["events"][0].get("introduced") == "1.0.0" and
            r["events"][1].get("fixed") == "1.5.0"
            for r in product_a_osv.get("ranges", [])
        )
        self.assertTrue(range1_found, "Range 1.0.0 to <1.5.0 not found for ProductA")
        
        # Specific version: 2.0.0
        self.assertIn("2.0.0", product_a_osv.get("versions", []))

        # ProductB checks (versions 0 to <=2.2.1)
        product_b_osv = next((p for p in osv_result["affected"] if p["package"]["name"] == "ProductB"), None)
        self.assertIsNotNone(product_b_osv)
        self.assertEqual(product_b_osv["package"]["ecosystem"], "Unknown") # Default as no packageName
        range_b_found = any(
            r["events"][0].get("introduced") == "0" and
            r["events"][1].get("last_affected") == "2.2.1"
            for r in product_b_osv.get("ranges", [])
        )
        self.assertTrue(range_b_found, "Range 0 to <=2.2.1 not found for ProductB")

        # ProductC Wildcard check
        product_c_osv = next((p for p in osv_result["affected"] if p["package"]["name"] == "ProductC-Wildcard"), None)
        self.assertIsNotNone(product_c_osv, "ProductC-Wildcard not found in OSV output")
        # Expected: introduced: 3.3.0, limit: 3.4.0 (heuristic)
        range_c_found = any(
            r.get("type") == "SEMVER" and # Should be SEMVER as version was 3.3.*
            len(r.get("events", [])) == 2 and
            r["events"][0].get("introduced") == "3.3.0" and # Assuming wildcard means from .0
            r["events"][1].get("limit") == "3.4.0" # Assuming wildcard limit to next minor
            for r in product_c_osv.get("ranges", [])
        )
        self.assertTrue(range_c_found, f"Wildcard range for ProductC-Wildcard not mapped as expected. Got: {product_c_osv.get('ranges', [])}")


    def test_cve_to_osv_references(self):
        osv_result = convert_cve_to_osv(self.sample_cve_v5_record)
        self.assertEqual(len(osv_result["references"]), 2)
        self.assertIn({"type": "ADVISORY", "url": "https://example.com/advisory/123"}, osv_result["references"])
        self.assertIn({"type": "FIX", "url": "https://example.com/fix/patch1"}, osv_result["references"])

    def test_cve_to_osv_severity_cvss(self):
        osv_result = convert_cve_to_osv(self.sample_cve_v5_record)
        self.assertEqual(len(osv_result["severity"]), 1)
        self.assertEqual(osv_result["severity"][0]["type"], "CVSS_V3")
        self.assertEqual(osv_result["severity"][0]["score"], "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    def test_cve_to_osv_credits(self):
        osv_result = convert_cve_to_osv(self.sample_cve_v5_record)
        self.assertEqual(len(osv_result["credits"]), 1)
        self.assertEqual(osv_result["credits"][0]["name"], "Credit to the finder.")
        self.assertEqual(osv_result["credits"][0]["type"], "FINDER") # Mapped from 'finder'

    def test_cve_to_osv_problemtypes_cwe(self):
        osv_result = convert_cve_to_osv(self.sample_cve_v5_record)
        self.assertIn("database_specific", osv_result)
        self.assertIn("cwe_details", osv_result["database_specific"])
        self.assertIn("CWE-79", osv_result["database_specific"]["cwe_details"])
        
    def test_cve_to_osv_rejected_cve(self):
        osv_result = convert_cve_to_osv(self.sample_cve_rejected)
        self.assertEqual(osv_result["id"], "CVE-2023-99999")
        self.assertIsNotNone(osv_result.get("withdrawn"))
        self.assertEqual(osv_result["withdrawn"], self.sample_cve_rejected["cveMetadata"]["dateUpdated"])
        self.assertEqual(osv_result["modified"], self.sample_cve_rejected["cveMetadata"]["dateUpdated"])
        self.assertIn("REJECTED", osv_result["details"])
        # Ensure other fields that don't make sense for withdrawn are absent or empty
        self.assertNotIn("affected", osv_result)
        self.assertNotIn("severity", osv_result)


    def test_osv_to_cve_conversion_id_and_metadata(self):
        cve_result = convert_osv_to_cve(self.sample_osv_record)
        self.assertEqual(cve_result["cveMetadata"]["cveId"], self.sample_osv_record["id"])
        self.assertEqual(cve_result["cveMetadata"]["state"], "PUBLISHED")
        self.assertEqual(cve_result["cveMetadata"]["datePublished"], self.sample_osv_record["published"])
        self.assertEqual(cve_result["cveMetadata"]["dateUpdated"], self.sample_osv_record["modified"])

    def test_osv_to_cve_descriptions_and_title(self):
        cve_result = convert_osv_to_cve(self.sample_osv_record)
        cna_container = cve_result["containers"]["cna"]
        self.assertEqual(cna_container["title"], self.sample_osv_record["summary"])
        self.assertEqual(len(cna_container["descriptions"]), 1)
        self.assertEqual(cna_container["descriptions"][0]["value"], self.sample_osv_record["details"])

    def test_osv_to_cve_affected_products(self):
        cve_result = convert_osv_to_cve(self.sample_osv_record)
        cna_affected = cve_result["containers"]["cna"]["affected"]
        self.assertTrue(len(cna_affected) >= 2) # ProductA and ProductB

        # ProductA
        product_a_cve = next((p for p in cna_affected if p["product"] == "ProductA"), None)
        self.assertIsNotNone(product_a_cve)
        self.assertEqual(product_a_cve["packageName"], "go/example.com/producta")
        
        # Range: introduced 1.0.0, limit 1.5.0 -> CVE: version 1.0.0, lessThan 1.5.0
        range_found = any(
            v.get("version") == "1.0.0" and v.get("lessThan") == "1.5.0" and v.get("status") == "affected"
            for v in product_a_cve["versions"]
        )
        self.assertTrue(range_found, "ProductA range 1.0.0 to <1.5.0 not correctly mapped to CVE")
        
        # Specific version 2.0.0
        version_found = any(v.get("version") == "2.0.0" and v.get("status") == "affected" for v in product_a_cve["versions"])
        self.assertTrue(version_found, "ProductA specific version 2.0.0 not found in CVE")

        # ProductB
        product_b_cve = next((p for p in cna_affected if p["product"] == "ProductB"), None)
        self.assertIsNotNone(product_b_cve)
        self.assertEqual(product_b_cve["packageName"], "Unknown")
        # Range: introduced 0, last_affected 2.2.1 -> CVE: lessThanOrEqual 2.2.1 (version 0 implies from beginning)
        range_b_found = any(
            v.get("lessThanOrEqual") == "2.2.1" and v.get("status") == "affected" and not v.get("version") # no specific start version if it was "0"
            for v in product_b_cve["versions"]
        )
        if not range_b_found: # check alternative mapping for introduced: "0"
            range_b_found = any(
                v.get("version") == "0" and v.get("lessThanOrEqual") == "2.2.1" and v.get("status") == "affected"
                for v in product_b_cve["versions"]
            )
        self.assertTrue(range_b_found, f"ProductB range up to 2.2.1 not correctly mapped to CVE. Got: {product_b_cve['versions']}")

        # ProductC Wildcard
        product_c_cve = next((p for p in cna_affected if p["product"] == "ProductC-Wildcard"), None)
        self.assertIsNotNone(product_c_cve)
        # OSV: intro 3.3.0, limit 3.4.0 -> CVE: version 3.3.0, lessThan 3.4.0
        range_c_found = any(
            v.get("version") == "3.3.0" and v.get("lessThan") == "3.4.0" and v.get("status") == "affected"
            for v in product_c_cve["versions"]
        )
        self.assertTrue(range_c_found, f"ProductC-Wildcard range 3.3.0 to <3.4.0 not correctly mapped. Got: {product_c_cve['versions']}")


    def test_osv_to_cve_references(self):
        cve_result = convert_osv_to_cve(self.sample_osv_record)
        cna_references = cve_result["containers"]["cna"]["references"]
        self.assertEqual(len(cna_references), 2)
        
        ref1 = next((r for r in cna_references if r["url"] == "https://example.com/advisory/123"), None)
        self.assertIsNotNone(ref1)
        self.assertIn("vendor-advisory", ref1["tags"]) # or third-party-advisory

        ref2 = next((r for r in cna_references if r["url"] == "https://example.com/fix/patch1"), None)
        self.assertIsNotNone(ref2)
        self.assertIn("patch", ref2["tags"])


    def test_osv_to_cve_severity(self):
        cve_result = convert_osv_to_cve(self.sample_osv_record)
        cna_metrics = cve_result["containers"]["cna"]["metrics"]
        self.assertEqual(len(cna_metrics), 1)
        # Check for cvssV3_1 since the sample score is CVSS:3.1
        self.assertIn("cvssV3_1", cna_metrics[0])
        self.assertEqual(cna_metrics[0]["cvssV3_1"]["vectorString"], self.sample_osv_record["severity"][0]["score"])


    def test_osv_to_cve_credits(self):
        cve_result = convert_osv_to_cve(self.sample_osv_record)
        cna_credits = cve_result["containers"]["cna"]["credits"]
        self.assertEqual(len(cna_credits), 1)
        self.assertEqual(cna_credits[0]["value"], self.sample_osv_record["credits"][0]["name"])
        self.assertEqual(cna_credits[0]["type"], self.sample_osv_record["credits"][0]["type"].upper())

    def test_osv_to_cve_problemtypes_cwe(self):
        cve_result = convert_osv_to_cve(self.sample_osv_record)
        cna_problemtypes = cve_result["containers"]["cna"]["problemTypes"]
        self.assertEqual(len(cna_problemtypes), 1)
        self.assertEqual(len(cna_problemtypes[0]["description"]), 1)
        self.assertEqual(cna_problemtypes[0]["description"][0]["cweId"], "CWE-79")
        self.assertEqual(cna_problemtypes[0]["description"][0]["type"], "CWE")
        
    def test_osv_to_cve_withdrawn_osv(self):
        cve_result = convert_osv_to_cve(self.sample_osv_withdrawn)
        self.assertEqual(cve_result["cveMetadata"]["cveId"], "CVE-2023-99999")
        self.assertEqual(cve_result["cveMetadata"]["state"], "REJECTED")
        self.assertEqual(cve_result["cveMetadata"]["dateUpdated"], self.sample_osv_withdrawn["modified"])
        
        cna_descriptions = get_nested_value(cve_result, ["containers", "cna", "descriptions"])
        self.assertIsNotNone(cna_descriptions)
        self.assertTrue(any("REJECTED" in desc["value"] for desc in cna_descriptions))
        self.assertTrue(any(self.sample_osv_withdrawn["details"] in desc["value"] for desc in cna_descriptions))

        # Ensure other fields are not populated for rejected CVE
        cna_container = get_nested_value(cve_result, ["containers", "cna"])
        self.assertNotIn("affected", cna_container)
        self.assertNotIn("metrics", cna_container)

if __name__ == '__main__':
    print("\n\n--- Running Unit Tests ---")
    # unittest.main() # This will run all tests.
    # To run tests within an interactive environment (like a Jupyter notebook or if __main__ is already used),
    # you might run them selectively or use a test runner.
    # For this script, if you run it directly, uncomment unittest.main()
    # For now, let's just indicate tests would run.
    
    suite = unittest.TestLoader().loadTestsFromTestCase(TestCveOsvConverter)
    runner = unittest.TextTestRunner()
    result = runner.run(suite)
    if not result.wasSuccessful():
        print("\nSOME TESTS FAILED. Please review the output above.")
    else:
        print("\nAll tests passed successfully.")