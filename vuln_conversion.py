import json
import datetime
import uuid

# Helper to safely get nested dictionary values
def get_nested_value(data_dict, keys, default=None):
    """
    Safely retrieves a nested value from a dictionary.

    Args:
        data_dict (dict): The dictionary to search.
        keys (list): A list of keys representing the path to the value.
        default: The value to return if the path is not found.

    Returns:
        The retrieved value or the default.
    """
    current = data_dict
    for key in keys:
        if isinstance(current, dict) and key in current:
            current = current[key]
        elif isinstance(current, list) and isinstance(key, int) and 0 <= key < len(current):
            current = current[key]
        else:
            return default
    return current

def convert_cve_to_osv(cve_data: dict) -> dict:
    """
    Converts a CVE v5 JSON object to an OSV JSON object.

    Args:
        cve_data (dict): A dictionary representing a CVE v5 record.

    Returns:
        dict: A dictionary representing an OSV record.
    """
    if not isinstance(cve_data, dict):
        raise ValueError("Input cve_data must be a dictionary.")

    cve_id = get_nested_value(cve_data, ["cveMetadata", "cveId"])
    if not cve_id:
        raise ValueError("CVE ID (cveMetadata.cveId) is missing.")

    osv_output = {
        "schema_version": "1.5.0", # Or latest appropriate OSV schema version
        "id": cve_id,
        "modified": None, # Will be populated later
        "published": None, # Will be populated later
        "aliases": [],
        "related": [],
        "summary": None,
        "details": None,
        "severity": [], # CVSS scores
        "affected": [],
        "references": [],
        "credits": [],
        # "database_specific": {} # Can be used for CVE-specific data not fitting OSV
    }

    # Metadata
    state = get_nested_value(cve_data, ["cveMetadata", "state"])
    if state == "REJECTED":
        osv_output["withdrawn"] = get_nested_value(cve_data, ["cveMetadata", "dateUpdated"],
                                                 datetime.datetime.utcnow().isoformat(timespec='seconds') + "Z")
        # For rejected CVEs, OSV typically just has id, modified, and withdrawn
        osv_output["modified"] = get_nested_value(cve_data, ["cveMetadata", "dateUpdated"],
                                                datetime.datetime.utcnow().isoformat(timespec='seconds') + "Z")
        osv_output["published"] = get_nested_value(cve_data, ["cveMetadata", "datePublished"],
                                                 datetime.datetime.utcnow().isoformat(timespec='seconds') + "Z")
        # OSV spec doesn't require much for withdrawn vulnerabilities,
        # but details can be helpful if available.
        # Try to get a description if it exists, even for rejected.
        cna_container = get_nested_value(cve_data, ["containers", "cna"], {})
        descriptions = get_nested_value(cna_container, ["descriptions"], [])
        for desc in descriptions:
            if desc.get("lang") == "en":
                # OSV uses 'details' for the main description
                # and 'summary' for a shorter one.
                # If CVE is rejected, the description often explains why.
                osv_output["details"] = desc.get("value")
                if len(desc.get("value", "")) > 120 : # Arbitrary length for summary
                     osv_output["summary"] = desc.get("value")[:117] + "..."
                else:
                    osv_output["summary"] = desc.get("value")
                break
        if not osv_output["details"] and descriptions: # Fallback to first description
            osv_output["details"] = descriptions[0].get("value")
            if len(descriptions[0].get("value", "")) > 120:
                 osv_output["summary"] = descriptions[0].get("value")[:117] + "..."
            else:
                osv_output["summary"] = descriptions[0].get("value")


        # Clean up fields not typically present for withdrawn/rejected.
        # Though OSV allows them, they might be empty or misleading.
        for key_to_remove in ["aliases", "related", "severity", "affected", "references", "credits"]:
            if not osv_output[key_to_remove]: # Remove if empty
                 del osv_output[key_to_remove]
        if not osv_output.get("summary"): # remove summary if not set
            osv_output.pop("summary", None)

        return osv_output


    osv_output["published"] = get_nested_value(cve_data, ["cveMetadata", "datePublished"])
    osv_output["modified"] = get_nested_value(cve_data, ["cveMetadata", "dateUpdated"], osv_output["published"]) # Fallback to published if not updated

    # CNA container usually holds the main data
    cna_container = get_nested_value(cve_data, ["containers", "cna"], {})

    # Descriptions -> summary and details
    # OSV: 'summary' (short, optional), 'details' (long, markdown)
    # CVE: 'descriptions' (array, lang, value)
    descriptions = get_nested_value(cna_container, ["descriptions"], [])
    english_description = None
    for desc in descriptions:
        if desc.get("lang") == "en":
            english_description = desc.get("value")
            break
    if not english_description and descriptions: # Fallback to first description
        english_description = descriptions[0].get("value")

    if english_description:
        osv_output["details"] = english_description
        # Create a summary (e.g., first sentence or fixed length)
        # This is a simple approach; more sophisticated summarization could be used.
        sentences = english_description.split('.')
        if sentences and sentences[0]:
            osv_output["summary"] = sentences[0].strip() + "."
            if len(osv_output["summary"]) > 250: # OSV summary shouldn't be too long
                 osv_output["summary"] = english_description[:247] + "..."
        else:
            osv_output["summary"] = english_description[:247] + "..." if len(english_description) > 250 else english_description


    # Affected products and versions
    # CVE: cna.affected[].packageName, .platforms, .versions[]
    # OSV: affected[].package.name, .package.ecosystem, .versions[], .ranges[]
    cve_affected = get_nested_value(cna_container, ["affected"], [])
    for aff_item in cve_affected:
        osv_affected_item = {}

        # Package information
        package_name = aff_item.get("product") # CVE uses "product"
        # CVE doesn't always specify an ecosystem clearly.
        # This is a major challenge. We might infer or use a default.
        # For now, let's use the product name and a placeholder ecosystem.
        # A more robust solution would involve mapping product names to ecosystems.
        ecosystem = aff_item.get("packageName", "Unknown") # Try to get packageName if present, else default
        if package_name:
            osv_affected_item["package"] = {
                "name": package_name,
                "ecosystem": ecosystem  # This needs careful consideration.
                                       # CVE 'packageName' sometimes exists and can be more like an ecosystem.
            }

            # Version information - this is complex
            # CVE: affected[].versions[] with status, version, lessThan, lessThanOrEqual, versionType
            # OSV: affected[].versions (list of specific versions)
            #      affected[].ranges[] (type: SEMVER/ECOSYSTEM, events: introduced/fixed/last_affected/limit)

            # Collect all specific affected versions
            osv_versions = []
            # Collect ranges
            osv_ranges = []

            cve_versions = aff_item.get("versions", [])
            for cve_ver in cve_versions:
                status = cve_ver.get("status")
                version_value = cve_ver.get("version")
                version_type = cve_ver.get("versionType", "semver") # Default to semver if not specified
                less_than = cve_ver.get("lessThan")
                less_than_or_equal = cve_ver.get("lessThanOrEqual")

                # Determine range type for OSV (SEMVER or ECOSYSTEM)
                # This is a simplification; actual ecosystem might dictate this
                range_type = "SEMVER" if version_type.lower() == "semver" else "ECOSYSTEM"


                if status == "affected":
                    if version_value and version_value != "0" and version_value != "*": # Specific affected version
                        # Check if it's a range like "X.*" or "X.Y.*"
                        if "*" in version_value:
                             # Handle as a simple range: introduced at X.0 (or X.Y.0), limit at next major/minor
                            parts = version_value.split('.')
                            base_version = []
                            is_wildcard_range = False
                            for part in parts:
                                if part == "*":
                                    is_wildcard_range = True
                                    break
                                base_version.append(part)
                            
                            if is_wildcard_range and base_version:
                                introduced_version = ".".join(base_version)
                                if len(base_version) > 0 and base_version[-1] != "0":
                                     # if it's like 2.3.*, and not 2.*.*
                                     # introduced should be the start of that range
                                     # e.g. 2.3.0 (if semver like)
                                     # This is heuristic
                                     padding_needed = 3 - len(base_version) # Assuming semver like x.y.z
                                     if padding_needed > 0:
                                         introduced_version += (".0" * padding_needed)

                                current_range = {
                                    "type": range_type,
                                    "events": [{"introduced": introduced_version if introduced_version else "0"}]
                                }
                                # Try to set a limit if possible based on wildcard
                                limit_version_parts = []
                                for i, p_val in enumerate(base_version):
                                    if i < len(base_version) -1:
                                        limit_version_parts.append(p_val)
                                    else:
                                        try:
                                            limit_version_parts.append(str(int(p_val) + 1))
                                        except ValueError: # not an int
                                            limit_version_parts.append(p_val) # keep as is, maybe not ideal
                                            # or we can skip limit here
                                            pass # No limit can be easily determined
                                if len(limit_version_parts) == len(base_version) and is_wildcard_range:
                                    # Ensure we have a higher bound if the structure allows
                                    # e.g., for 2.3.*, limit is 2.4.0
                                    # for 2.*, limit is 3.0.0
                                    # This is a heuristic!
                                    idx_to_increment = -1
                                    for i in range(len(base_version) -1, -1, -1):
                                        try:
                                            int(base_version[i]) # check if it's an int
                                            idx_to_increment = i
                                            break
                                        except ValueError:
                                            continue
                                    
                                    if idx_to_increment != -1:
                                        final_limit_parts = list(base_version)
                                        final_limit_parts[idx_to_increment] = str(int(base_version[idx_to_increment]) +1)
                                        for i in range(idx_to_increment + 1, len(final_limit_parts)):
                                            final_limit_parts[i] = "0"
                                        
                                        # Pad to typical semver length for limit
                                        padding_needed = 3 - len(final_limit_parts)
                                        if padding_needed > 0:
                                            final_limit_parts.extend(["0"] * padding_needed)

                                        current_range["events"].append({"limit": ".".join(final_limit_parts)})


                                osv_ranges.append(current_range)

                            else: # Not a wildcard, but specific version is affected                               
                                osv_versions.append(version_value)

                        else: # specific version without wildcard
                             osv_versions.append(version_value)


                    # Handle ranges like "version <= X" or "version < X"
                    # This typically means versions from 0 up to X (exclusive or inclusive)
                    # OSV uses "introduced": "0" (or earliest known) and "fixed" or "last_affected"
                    # For "lessThan X", it means fixed at X or last_affected is just before X
                    # For "lessThanOrEqual X", it means last_affected is X
                    introduced_version = version_value
                    current_range = {
                                    "type": range_type,
                                    "events": [{"introduced": introduced_version if introduced_version else "0"}]
                                }

                    if less_than_or_equal:
                        current_range["events"].append({"last_affected": less_than_or_equal})
                        osv_ranges.append(current_range)
                    elif less_than:
                        # OSV "fixed" is also often used for the version that resolves the issue.
                        current_range["events"].append({"fixed": less_than})
                        osv_ranges.append(current_range)

                elif status == "unaffected":
                    # This could mean a specific version is NOT affected, or versions AFTER a certain point are not.
                    # If `version_value` is present, it's a specific unaffected version. OSV doesn't directly list these
                    # in `affected` unless it's to define a boundary of an affected range.
                    # If `lessThan` or `lessThanOrEqual` is used with `unaffected`, it's harder to map directly
                    # unless it's defining the start of an affected range (e.g. "unaffected lessThan X" could mean "affected from X upwards")
                    # This part is tricky and often requires more context.
                    # For simplicity, we'll focus on "fixed" markers.
                    # If cve_ver states version X is unaffected, it *could* mean X is a "fixed" version.
                    if version_value: # e.g. "version 1.2.3 is unaffected"
                        # This might imply that 1.2.3 is a fixed version if prior versions were affected.
                        # Need to correlate with other version entries.
                        # For now, if we have a preceding affected range without an upper bound,
                        # this "unaffected" version could be the "fixed" event.
                        if osv_ranges and "fixed" not in osv_ranges[-1]["events"][-1] and "limit" not in osv_ranges[-1]["events"][-1]:
                           if "introduced" in osv_ranges[-1]["events"][0]: # Check if it's an open-ended range
                                osv_ranges[-1]["events"].append({"fixed": version_value})


            # Default version/range if cve_versions is empty but product is listed
            if not cve_versions and aff_item.get("defaultStatus", "affected") == "affected":
                 # This product is affected, but no specific versions. OSV needs something.
                 # This is a very broad assumption.
                 osv_ranges.append({
                     "type": "ECOSYSTEM", # or SEMVER if appropriate default known
                     "events": [{"introduced": "0"}] # All versions from 0 are potentially affected
                 })


            if osv_versions:
                osv_affected_item["versions"] = sorted(list(set(osv_versions))) # Unique sorted versions
            if osv_ranges:
                # Further refine ranges: if a range is introduced:0 and fixed:X, and another is introduced:Y fixed:Z
                # these are separate. If a range is introduced:A, fixed:B, and another affected version C is listed
                # that falls within A-B, it's covered. If C is outside, it needs its own entry or range.
                # OSV expects non-overlapping ranges for the same package if possible, or distinct entries.
                osv_affected_item["ranges"] = osv_ranges
            
            # If neither versions nor ranges, but it's an affected product, it's problematic for OSV.
            # We might add a general "affected": True marker if OSV supported it, but it doesn't directly.
            # It requires at least one version or range.
            if "package" in osv_affected_item and (osv_affected_item.get("versions") or osv_affected_item.get("ranges")):
                osv_output["affected"].append(osv_affected_item)
            elif "package" in osv_affected_item : # package exists, but no versions/ranges. This is a problem.
                # Add a placeholder range indicating "unknown" specific versions but generally affected.
                # This is a fallback and might not be perfectly accurate.
                osv_affected_item["ranges"] = [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]
                osv_output["affected"].append(osv_affected_item)


    # References
    # CVE: cna.references[] with url, name, tags[]
    # OSV: references[] with type (WEB, ADVISORY, REPORT, ARTICLE, FIX, PACKAGE), url
    references = get_nested_value(cna_container, ["references"], [])
    for ref in references:
        url = ref.get("url")
        if url:
            # Infer OSV type from CVE tags or URL content (simplified)
            ref_type = "WEB" # Default
            tags = ref.get("tags", [])
            if "third-party-advisory" in tags or "vendor-advisory" in tags:
                ref_type = "ADVISORY"
            elif "exploit" in tags: # OSV doesn't have 'exploit', 'REPORT' or 'ARTICLE' might fit
                ref_type = "ARTICLE"
            elif "patch" in tags or "fix" in tags:
                ref_type = "FIX"
            elif "issue-tracking" in tags or "vdb-entry" in tags : # like a bug report
                 ref_type = "REPORT"

            osv_output["references"].append({"type": ref_type, "url": url})

    # CVSS Scores
    # CVE: cna.metrics[] with cvssV3_1, cvssV3_0, cvssV2_0 etc.
    # OSV: severity[] with type (CVSS_V3, CVSS_V2), score (vector string)
    metrics = get_nested_value(cna_container, ["metrics"], [])
    for metric in metrics:
        # CVSS v3.x
        cvss_v3 = None
        if "cvssV3_1" in metric:
            cvss_v3 = metric["cvssV3_1"]
            osv_severity_type = "CVSS_V3"
        elif "cvssV3_0" in metric:
            cvss_v3 = metric["cvssV3_0"]
            osv_severity_type = "CVSS_V3" # OSV schema doesn't distinguish 3.0 and 3.1 in type key

        if cvss_v3 and cvss_v3.get("vectorString"):
            osv_output["severity"].append({
                "type": osv_severity_type,
                "score": cvss_v3["vectorString"]
            })
            # OSV also allows "summary" for severity, could be base score
            # if 'baseScore' in cvss_v3:
            # osv_output["severity"][-1]["summary"] = str(cvss_v3['baseScore'])
        
        # CVSS v2.0
        cvss_v2 = metric.get("cvssV2_0")
        if cvss_v2 and cvss_v2.get("vectorString"):
            osv_output["severity"].append({
                "type": "CVSS_V2",
                "score": cvss_v2["vectorString"]
            })
            # if 'baseScore' in cvss_v2:
            # osv_output["severity"][-1]["summary"] = str(cvss_v2['baseScore'])

    # Credits
    # CVE: cna.credits[] with lang, value, user, type
    # OSV: credits[] with name, contact[], type
    # This mapping is not direct. CVE 'value' is the credit text. OSV 'name' is the entity.
    cve_credits = get_nested_value(cna_container, ["credits"], [])
    for cred_item in cve_credits:
        credit_text = cred_item.get("value")
        credit_type = cred_item.get("type", "UNSPECIFIED").upper() # Default if not specified
        # OSV types: FINDER, REPORTER, ANALYST, COORDINATOR, REMEDIATION_DEVELOPER, REMEDIATION_REVIEWER,
        # REMEDIATION_VERIFIER, TOOL, SPONSOR, OTHER
        # CVE types: finder, reporter, analyst, coordinator, remediation developer,
        #            remediation reviewer, remediation verifier, sponsor, tool, other
        # Mapping is quite direct if type is present
        if credit_type not in ["FINDER", "REPORTER", "ANALYST", "COORDINATOR", "REMEDIATION_DEVELOPER", "REMEDIATION_REVIEWER", "REMEDIATION_VERIFIER", "TOOL", "SPONSOR", "OTHER"]:
             credit_type = "OTHER"


        if credit_text:
            osv_credit = {"name": credit_text, "type": credit_type}
            # CVE's 'user' might be an ID. OSV 'contact' is for URIs/emails.
            # This is a simplification.
            osv_output["credits"].append(osv_credit)


    # Problem Types (CWE)
    # CVE: cna.problemTypes[].description[] with cweId, description, lang, type ("CWE")
    # OSV: database_specific.cwe[] (array of strings like "CWE-123") or summary/details
    problem_types = get_nested_value(cna_container, ["problemTypes"], [])
    cwe_ids = []
    for pt in problem_types:
        for desc in pt.get("description", []):
            if desc.get("type", "").upper() == "CWE" and desc.get("cweId"):
                cwe_ids.append(desc["cweId"])
                # Optionally, add CWE description to OSV details or summary if appropriate
                # For now, just collecting IDs for database_specific
    if cwe_ids:
        if "database_specific" not in osv_output:
            osv_output["database_specific"] = {}
        osv_output["database_specific"]["cwe"] = {
            "id": cwe_ids[0] if len(cwe_ids) == 1 else None, # if only one, can be top level
            "description": ", ".join(cwe_ids) # or join all to a string list
        }
        # More aligned with common OSV practice might be:
        osv_output["database_specific"]["cwe_details"] = list(set(cwe_ids))


    # Add provider (CNA) information to database_specific or credits if it makes sense
    provider_metadata = get_nested_value(cna_container, ["providerMetadata"])
    if provider_metadata:
        if "database_specific" not in osv_output:
            osv_output["database_specific"] = {}
        osv_output["database_specific"]["provider_metadata"] = provider_metadata
        # Add CNA short name as an alias or related ID if appropriate
        # short_name = provider_metadata.get("shortName")
        # org_id = provider_metadata.get("orgId") # UUID
        # if short_name and short_name.upper() != "CVE":
        #    osv_output["aliases"].append(f"{short_name.upper()}-{cve_id.split('-')[-1]}") # e.g. GITHUB-1234 for CVE-YYYY-1234 from GITHUB CNA


    # Clean up empty optional fields
    for key in ["aliases", "related", "severity", "affected", "references", "credits"]:
        if not osv_output[key]:
            del osv_output[key]
    if "database_specific" in osv_output and not osv_output["database_specific"]:
        del osv_output["database_specific"]
    if not osv_output.get("summary"):
        osv_output.pop("summary", None) # Remove summary if it ended up empty

    return osv_output


def convert_osv_to_cve(osv_data: dict) -> dict:
    """
    Converts an OSV JSON object to a CVE v5 JSON object.
    This is a more complex conversion and will be a best-effort,
    as OSV's granular package/versioning may not map cleanly to CVE's structure.

    Args:
        osv_data (dict): A dictionary representing an OSV record.

    Returns:
        dict: A dictionary representing a CVE v5 record.
    """
    if not isinstance(osv_data, dict):
        raise ValueError("Input osv_data must be a dictionary.")

    osv_id = osv_data.get("id")
    if not osv_id:
        raise ValueError("OSV ID is missing.")

    # Heuristic: Determine if the OSV ID is a CVE ID
    is_cve_id_format = osv_id.upper().startswith("CVE-") or \
                       osv_id.upper().startswith("GHSA-") # OSV often uses GHSA as primary ID for CVEs originating from GitHub

    # Default CVE ID. If OSV ID is not a CVE, we need a strategy.
    # For this example, we'll assume the OSV ID *is* or *relates to* the target CVE ID.
    # In a real system, you might need to find an existing CVE ID from `aliases` or generate a placeholder.
    cve_id = osv_id
    if "aliases" in osv_data:
        for alias in osv_data["aliases"]:
            if alias.upper().startswith("CVE-"):
                cve_id = alias
                break

    # Basic CVE structure
    cve_output = {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0",
        "cveMetadata": {
            "cveId": cve_id,
            "assignerOrgId": None, # Needs to be populated, e.g. from OSV publisher or a default
            "assignerShortName": None, # ditto
            "state": "PUBLISHED", # Default, or "REJECTED" if "withdrawn" in OSV
            "datePublished": osv_data.get("published"),
            "dateUpdated": osv_data.get("modified"),
            "dateReserved": None # Not typically in OSV
        },
        "containers": {
            "cna": {
                "providerMetadata": {
                    # This should ideally come from the OSV publisher or be configured.
                    # Using a placeholder UUID.
                    "orgId": str(uuid.uuid4()),
                    "shortName": "OSV_Importer", # Placeholder
                    "dateUpdated": osv_data.get("modified")
                },
                "title": None, # OSV doesn't have a direct title field. Summary might be used.
                "descriptions": [],
                "affected": [],
                "problemTypes": [],
                "references": [],
                "metrics": [],
                "credits": [],
                "source": { # Information about where this CVE data (from OSV) came from
                    "discovery": "EXTERNAL",
                    "advisory": osv_data.get("id") if not is_cve_id_format else None
                }
                # "solutions": [], "exploits": [], "configurations": [], "workarounds": []
            }
        }
    }
    cna_container = cve_output["containers"]["cna"]

    if osv_data.get("withdrawn"):
        cve_output["cveMetadata"]["state"] = "REJECTED"
        # Add a description about withdrawal if OSV provides one (often in details)
        if osv_data.get("details"):
             cna_container["descriptions"].append({
                "lang": "en",
                "value": f"REJECTED: {osv_data.get('details')}"
            })
        elif osv_data.get("summary"):
             cna_container["descriptions"].append({
                "lang": "en",
                "value": f"REJECTED: {osv_data.get('summary')}"
            })
        else:
             cna_container["descriptions"].append({
                "lang": "en",
                "value": f"REJECTED: This CVE ID was withdrawn. Date of withdrawal: {osv_data.get('withdrawn')}"
            })
        # For rejected, usually only metadata and a description are needed.
        # Clear out other CNA fields that might be empty or irrelevant.
        for key_to_clear in ["affected", "problemTypes", "references", "metrics", "credits", "title"]:
            cna_container.pop(key_to_clear, None)
        if not cna_container["descriptions"]:
            del cna_container["descriptions"]
        return cve_output


    # Descriptions
    # OSV 'details' -> CVE 'descriptions'
    # OSV 'summary' could be CVE 'title' or part of description
    if osv_data.get("summary"):
        cna_container["title"] = osv_data["summary"][:200] # CVE titles are not excessively long

    if osv_data.get("details"):
        cna_container["descriptions"].append({
            "lang": "en", # Assuming English
            "value": osv_data["details"]
        })
    elif osv_data.get("summary") and not cna_container["descriptions"]: # Use summary if no details
         cna_container["descriptions"].append({
            "lang": "en",
            "value": osv_data["summary"]
        })


    # Affected
    # OSV: affected[] -> CVE: cna.affected[]
    # This is the most complex part. OSV's ranges and specific versions need to be mapped
    # to CVE's version objects (version, status, lessThan, etc.)
    for osv_aff in osv_data.get("affected", []):
        cve_aff_item = {
            "vendor": None, # CVE often includes vendor. OSV `package.ecosystem` might hint at it.
            "product": get_nested_value(osv_aff, ["package", "name"]),
            "packageName": get_nested_value(osv_aff, ["package", "ecosystem"]), # Store ecosystem here
            "versions": [],
            "defaultStatus": "affected" # Assume affected if listed
        }
        # Heuristic for vendor based on ecosystem (very basic)
        ecosystem = get_nested_value(osv_aff, ["package", "ecosystem"], "").lower()
        if ecosystem == "maven": cve_aff_item["vendor"] = "Apache" # Common, but not always true
        elif ecosystem == "pypi": cve_aff_item["vendor"] = "Python Software Foundation" # Or individual maintainer
        elif ecosystem == "npm": cve_aff_item["vendor"] = "npm, Inc." # Or individual maintainer
        # A proper mapping table or inference logic would be needed here.
        if not cve_aff_item["vendor"]:
            cve_aff_item["vendor"] = "N/A" # Placeholder if vendor can't be determined


        # Process OSV versions (list of specific affected versions)
        for ver_str in osv_aff.get("versions", []):
            cve_aff_item["versions"].append({
                "status": "affected",
                "version": ver_str
            })

        # Process OSV ranges
        # OSV range: {type, repo, events: [introduced, fixed, last_affected, limit]}
        # CVE version: {status, versionType, version, lessThan, lessThanOrEqual}
        for osv_range in osv_aff.get("ranges", []):
            # A single OSV range can map to one or two CVE version entries.
            # E.g., introduced: X, fixed: Y -> CVE: affected, >=X, <Y
            # (CVE doesn't have direct >=, so it's often implied or uses version value X)
            range_type = osv_range.get("type", "ECOSYSTEM") # Default to ECOSYSTEM
            cve_version_type = "semver" if range_type == "SEMVER" else "custom" # Or map other OSV types

            # Extract events
            introduced_event = next((e for e in osv_range.get("events", []) if "introduced" in e), None)
            fixed_event = next((e for e in osv_range.get("events", []) if "fixed" in e), None)
            last_affected_event = next((e for e in osv_range.get("events", []) if "last_affected" in e), None)
            limit_event = next((e for e in osv_range.get("events", []) if "limit" in e), None)

            # Scenario 1: Introduced X, Fixed Y
            # Means versions from X (inclusive) up to Y (exclusive) are affected.
            # CVE: version: X, status: affected (implies >=X)
            #        version: Y, status: unaffected (implies fixed at Y, or affected <Y)
            # A common CVE representation for this is a single entry:
            # { status: "affected", version: "X" (or starting point), lessThan: "Y"}
            if introduced_event and (fixed_event or limit_event):
                ver_entry = {"status": "affected", "versionType": cve_version_type}
                if introduced_event["introduced"] != "0": # If not starting from the very beginning
                    ver_entry["version"] = introduced_event["introduced"]
                
                if fixed_event:
                    ver_entry["lessThan"] = fixed_event["fixed"]
                elif limit_event: # OSV limit is exclusive
                    ver_entry["lessThan"] = limit_event["limit"]
                cve_aff_item["versions"].append(ver_entry)

            # Scenario 2: Introduced X, LastAffected Y
            # Means versions X through Y (inclusive) are affected.
            # CVE: { status: "affected", version: "X", lessThanOrEqual: "Y" }
            elif introduced_event and last_affected_event:
                ver_entry = {"status": "affected", "versionType": cve_version_type}
                if introduced_event["introduced"] != "0":
                    ver_entry["version"] = introduced_event["introduced"]
                ver_entry["lessThanOrEqual"] = last_affected_event["last_affected"]
                cve_aff_item["versions"].append(ver_entry)

            # Scenario 3: Only Introduced X (open-ended range)
            # Means X and all subsequent versions are affected.
            # CVE: { status: "affected", version: "X" } (implies X and later)
            elif introduced_event:
                 cve_aff_item["versions"].append({
                    "status": "affected",
                    "versionType": cve_version_type,
                    "version": introduced_event["introduced"] if introduced_event["introduced"] != "0" else "0" # or "all versions from X"
                })

            # Scenario 4: Only Fixed Y (implies affected before Y)
            # CVE: { status: "affected", lessThan: "Y" }
            elif fixed_event:
                cve_aff_item["versions"].append({
                    "status": "affected",
                    "versionType": cve_version_type,
                    "lessThan": fixed_event["fixed"]
                })
            # Scenario 5: Only Limit Y (implies affected before Y, exclusive)
            elif limit_event:
                 cve_aff_item["versions"].append({
                    "status": "affected",
                    "versionType": cve_version_type,
                    "lessThan": limit_event["limit"]
                })
            
            # Scenario 6: Only LastAffected Y (implies affected up to Y, inclusive)
            elif last_affected_event:
                cve_aff_item["versions"].append({
                    "status": "affected",
                    "versionType": cve_version_type,
                    "lessThanOrEqual": last_affected_event["last_affected"]
                })


        if cve_aff_item.get("product") and cve_aff_item.get("versions"):
            cna_container["affected"].append(cve_aff_item)
        elif cve_aff_item.get("product"): # Product listed but no versions mapped
            # Add a generic "affected" entry for the product if no specific versions.
            # This is a fallback.
            cve_aff_item["versions"].append({"status": "affected", "version": "unspecified"})
            cna_container["affected"].append(cve_aff_item)


    # References
    # OSV: references[] (type, url) -> CVE: cna.references[] (url, name, tags)
    for osv_ref in osv_data.get("references", []):
        cve_ref = {"url": osv_ref.get("url")}
        # Infer name from URL or set to URL if no better option
        cve_ref["name"] = osv_ref.get("url") # Or try to derive a name
        
        # Map OSV type to CVE tags
        tags = []
        osv_ref_type = osv_ref.get("type", "WEB").upper()
        if osv_ref_type == "ADVISORY":
            tags.extend(["vendor-advisory", "third-party-advisory"]) # Cannot always distinguish
        elif osv_ref_type == "ARTICLE":
            tags.append("press") # Or "technical-paper" - needs context
        elif osv_ref_type == "REPORT": # e.g. bug tracker
            tags.append("issue-tracking")
        elif osv_ref_type == "FIX":
            tags.append("patch")
        elif osv_ref_type == "PACKAGE": # Link to package repository
            tags.append("product")
        # Default tags if needed
        if not tags: tags.append("related")

        cve_ref["tags"] = tags
        cna_container["references"].append(cve_ref)

    # Severity (CVSS)
    # OSV: severity[] (type, score) -> CVE: cna.metrics[] (cvssV3_1, etc.)
    # This requires parsing the CVSS vector string from OSV.
    # For simplicity, we'll just store the vector. Full parsing would need a CVSS library.
    for osv_sev in osv_data.get("severity", []):
        metric_entry = {}
        cvss_score_string = osv_sev.get("score")
        if not cvss_score_string: continue

        # TODO: Parse CVSS vector string to populate individual fields if required by CVE schema strictly.
        # For now, just storing the vector string is common.
        if osv_sev.get("type") == "CVSS_V3": # OSV doesn't distinguish 3.0/3.1 type
            # Check vector prefix to guess if 3.0 or 3.1
            if cvss_score_string.startswith("CVSS:3.1"):
                 metric_entry["cvssV3_1"] = {"vectorString": cvss_score_string, "version": "3.1"}
                 # Base score etc. would need parsing.
            elif cvss_score_string.startswith("CVSS:3.0"):
                 metric_entry["cvssV3_0"] = {"vectorString": cvss_score_string, "version": "3.0"}
            else: # Default to 3.1 if unspecified, or could be an error
                 metric_entry["cvssV3_1"] = {"vectorString": cvss_score_string, "version": "3.1"} # Assuming
            # Add dummy baseScore and severity for schema validity, actual values need vector parsing
            if "cvssV3_1" in metric_entry:
                metric_entry["cvssV3_1"]["baseScore"] = 0.0 # Placeholder
                metric_entry["cvssV3_1"]["baseSeverity"] = "NONE" # Placeholder
                metric_entry["cvssV3_1"]["status"] = "DRAFT" # Placeholder
            if "cvssV3_0" in metric_entry:
                metric_entry["cvssV3_0"]["baseScore"] = 0.0 # Placeholder
                metric_entry["cvssV3_0"]["baseSeverity"] = "NONE" # Placeholder
                metric_entry["cvssV3_0"]["status"] = "DRAFT" # Placeholder

        elif osv_sev.get("type") == "CVSS_V2":
            metric_entry["cvssV2_0"] = {"vectorString": cvss_score_string, "version": "2.0"}
            # Add dummy baseScore for schema validity
            metric_entry["cvssV2_0"]["baseScore"] = 0.0 # Placeholder
            metric_entry["cvssV2_0"]["status"] = "DRAFT" # Placeholder

        if metric_entry:
            cna_container["metrics"].append(metric_entry)


    # Credits
    # OSV: credits[] (name, contact[], type) -> CVE: cna.credits[] (lang, value, type)
    for osv_cred in osv_data.get("credits", []):
        cve_cred = {
            "lang": "en", # Assuming English
            "value": osv_cred.get("name"), # OSV name is the credited entity/individual
            "type": osv_cred.get("type", "OTHER").upper() # OSV types map well
        }
        # OSV 'contact' (URIs) doesn't directly map to CVE credit structure easily.
        # Could append to 'value' or store in a custom x_ field if needed.
        cna_container["credits"].append(cve_cred)

    # Problem Types (CWE)
    # OSV: database_specific.cwe (string or object) / database_specific.cwe_details (list)
    # CVE: cna.problemTypes[].description[] (cweId, description, type="CWE")
    cwe_data = get_nested_value(osv_data, ["database_specific", "cwe"])
    cwe_details = get_nested_value(osv_data, ["database_specific", "cwe_details"])
    
    cwe_ids_to_process = []
    if isinstance(cwe_details, list):
        cwe_ids_to_process.extend(cwe_details)
    elif isinstance(cwe_data, str) and cwe_data.upper().startswith("CWE-"):
        cwe_ids_to_process.append(cwe_data)
    elif isinstance(cwe_data, dict) and cwe_data.get("id", "").upper().startswith("CWE-"):
        cwe_ids_to_process.append(cwe_data["id"])
    
    # Remove duplicates
    cwe_ids_to_process = sorted(list(set(cwe_ids_to_process)))

    if cwe_ids_to_process:
        problem_type_entry = {"description": []}
        for cwe_id_str in cwe_ids_to_process:
            # Basic validation of CWE format
            if cwe_id_str.upper().startswith("CWE-") and cwe_id_str.split('-')[-1].isdigit():
                problem_type_entry["description"].append({
                    "lang": "en",
                    "type": "CWE",
                    "cweId": cwe_id_str.upper(),
                    "description": cwe_id_str.upper() # Placeholder, ideally fetch CWE title
                })
        if problem_type_entry["description"]:
            cna_container["problemTypes"].append(problem_type_entry)
            
    # Assigner orgId and shortName. This is tricky.
    # If OSV ID is GHSA, assigner is GitHub.
    # If from NVD, it's from MITRE/NIST.
    # This requires external knowledge or more info in OSV source.
    # Using placeholders for now based on CVE ID itself.
    if cve_id.upper().startswith("CVE-"):
        # Standard CVE format implies assigner is a CNA.
        # For this example, we'll use a generic placeholder for the main CNA fields.
        # In a real scenario, you would look up the CNA responsible for the CVE ID prefix or use info
        # from the OSV entry's publisher if available.
        # Placeholder UUID for assignerOrgId
        cve_output["cveMetadata"]["assignerOrgId"] = "82542616-A862-4554-B7CD-13553A76EA70" # Example UUID
        cve_output["cveMetadata"]["assignerShortName"] = "cveawg" # Example shortName
        # If providerMetadata from OSV could map to CNA, use it
        # osv_provider = get_nested_value(osv_data, ["database_specific", "provider_metadata"]) # assuming it exists
        # if osv_provider and "orgId" in osv_provider:
        # cve_output["cveMetadata"]["assignerOrgId"] = osv_provider["orgId"]
        # if osv_provider and "shortName" in osv_provider:
        # cve_output["cveMetadata"]["assignerShortName"] = osv_provider["shortName"]

    # Clean up empty optional fields in CNA
    for key in ["title", "descriptions", "affected", "problemTypes", "references", "metrics", "credits"]:
        if not cna_container.get(key): # Use .get() as some might have been popped for REJECTED
            cna_container.pop(key, None)
    if not cna_container.get("source", {}).get("advisory"):
        if "source" in cna_container and "advisory" in cna_container["source"]:
             del cna_container["source"]["advisory"]
        if "source" in cna_container and not cna_container["source"]:
            del cna_container["source"]


    return cve_output