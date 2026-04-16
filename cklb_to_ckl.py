import json
import xml.etree.ElementTree as ET
from xml.dom import minidom
from pathlib import Path


def cklb_to_ckl(cklb_file: str, output_ckl_file: str = None) -> str:
    """
    Convert a STIG Viewer 3.x JSON-based .cklb file to a legacy .ckl XML file.

    Args:
        cklb_file:      Path to the source .cklb file.
        output_ckl_file: Optional output path. If omitted, the output is placed
                         alongside the source with a .ckl extension.

    Returns:
        The path to the written .ckl file.
    """
    with open(cklb_file, "r", encoding="utf-8") as f:
        cklb = json.load(f)

    # ------------------------------------------------------------------ #
    # Root
    # ------------------------------------------------------------------ #
    checklist = ET.Element("CHECKLIST")

    # ------------------------------------------------------------------ #
    # ASSET block
    # ------------------------------------------------------------------ #
    asset_node = ET.SubElement(checklist, "ASSET")

    asset_fields = {
        "ROLE":           cklb.get("target_data", {}).get("role", "None"),
        "ASSET_TYPE":     cklb.get("target_data", {}).get("type", "Computing"),
        "MARKING":        cklb.get("target_data", {}).get("marking", ""),
        "HOST_NAME":      cklb.get("target_data", {}).get("host_name", ""),
        "HOST_IP":        cklb.get("target_data", {}).get("ip_address", ""),
        "HOST_MAC":       cklb.get("target_data", {}).get("mac_address", ""),
        "HOST_FQDN":      cklb.get("target_data", {}).get("fqdn", ""),
        "TARGET_COMMENT": cklb.get("target_data", {}).get("comments", ""),
        "TECH_AREA":      cklb.get("target_data", {}).get("tech_area", ""),
        "TARGET_KEY":     cklb.get("target_data", {}).get("target_key", ""),
        "WEB_OR_DATABASE": "true" if cklb.get("target_data", {}).get("web_or_database") else "false",
        "WEB_DB_SITE":    cklb.get("target_data", {}).get("web_db_site", ""),
        "WEB_DB_INSTANCE": cklb.get("target_data", {}).get("web_db_instance", ""),
    }
    for tag, value in asset_fields.items():
        el = ET.SubElement(asset_node, tag)
        el.text = str(value) if value is not None else ""

    # ------------------------------------------------------------------ #
    # STIGS block
    # ------------------------------------------------------------------ #
    stigs_node = ET.SubElement(checklist, "STIGS")

    for stig in cklb.get("stigs", []):
        istig_node = ET.SubElement(stigs_node, "iSTIG")

        # -- STIG_INFO ---------------------------------------------------
        stig_info_node = ET.SubElement(istig_node, "STIG_INFO")

        stig_info_fields = {
            "version":     stig.get("version", ""),
            "classification": stig.get("classification", "UNCLASSIFIED"),
            "customname":  stig.get("display_name", ""),
            "stigid":      stig.get("stig_id", ""),
            "description": stig.get("description", ""),
            "filename":    stig.get("stig_id", ""),
            "releaseinfo": stig.get("release_info", ""),
            "title":       stig.get("stig_name", ""),
            "uuid":        stig.get("uuid", ""),
            "notice":      stig.get("notice", ""),
            "source":      stig.get("source", ""),
        }
        for tag, value in stig_info_fields.items():
            si_el = ET.SubElement(stig_info_node, "SI_DATA")
            name_el = ET.SubElement(si_el, "SID_NAME")
            name_el.text = tag
            data_el = ET.SubElement(si_el, "SID_DATA")
            data_el.text = str(value) if value is not None else ""

        # -- VULNs -------------------------------------------------------
        for rule in stig.get("rules", []):
            vuln_node = ET.SubElement(istig_node, "VULN")

            # Map severity
            raw_severity = rule.get("severity", "medium").lower()
            severity_map = {"high": "high", "medium": "medium", "low": "low",
                            "cat i": "high", "cat ii": "medium", "cat iii": "low"}
            severity = severity_map.get(raw_severity, "medium")

            # STIG_DATA attributes
            stig_data_fields = {
                "Vuln_Num":          rule.get("group_id", ""),
                "Severity":          severity,
                "Group_Title":       rule.get("group_title", ""),
                "Rule_ID":           rule.get("rule_id_src", ""),
                "Rule_Ver":          rule.get("rule_version", ""),
                "Rule_Title":        rule.get("rule_title", ""),
                "Vuln_Discuss":      rule.get("discussion", ""),
                "IA_Controls":       rule.get("ia_controls", ""),
                "Check_Content":     rule.get("check_content", ""),
                "Fix_Text":          rule.get("fix_text", ""),
                "False_Positives":   rule.get("false_positives", ""),
                "False_Negatives":   rule.get("false_negatives", ""),
                "Documentable":      "true" if rule.get("documentable") else "false",
                "Mitigations":       rule.get("mitigations", ""),
                "Potential_Impact":  rule.get("potential_impacts", ""),
                "Third_Party_Tools": rule.get("third_party_tools", ""),
                "Mitigation_Control": rule.get("mitigation_control", ""),
                "Responsibility":    rule.get("responsibility", ""),
                "Security_Override_Guidance": rule.get("security_override_guidance", ""),
                "Check_Content_Ref": rule.get("check_content_ref", {}).get("href", ""),
                "Class":             rule.get("classification", "Unclass"),
                "STIGRef":           stig.get("stig_name", ""),
                "TargetKey":         cklb.get("target_data", {}).get("target_key", ""),
                "STIG_UUID":         stig.get("uuid", ""),
                "LEGACY_ID":         _join_legacy_ids(rule.get("legacy_ids", [])),
                "CCI_REF":           _join_cci_refs(rule.get("ccis", [])),
            }

            for attr_name, attr_value in stig_data_fields.items():
                sd_node = ET.SubElement(vuln_node, "STIG_DATA")
                vuln_attr_el = ET.SubElement(sd_node, "VULN_ATTRIBUTE")
                vuln_attr_el.text = attr_name
                attr_data_el = ET.SubElement(sd_node, "ATTRIBUTE_DATA")
                attr_data_el.text = str(attr_value) if attr_value is not None else ""

            # Status mapping: CKLB uses different status strings than CKL
            status_map = {
                "not_a_finding":  "NotAFinding",
                "open":           "Open",
                "not_applicable": "Not_Applicable",
                "not_reviewed":   "Not_Reviewed",
            }
            raw_status = rule.get("status", "not_reviewed").lower()
            ckl_status = status_map.get(raw_status, "Not_Reviewed")

            status_el = ET.SubElement(vuln_node, "STATUS")
            status_el.text = ckl_status

            finding_el = ET.SubElement(vuln_node, "FINDING_DETAILS")
            finding_el.text = rule.get("finding_details", "") or ""

            comments_el = ET.SubElement(vuln_node, "COMMENTS")
            comments_el.text = rule.get("comments", "") or ""

            severity_override_el = ET.SubElement(vuln_node, "SEVERITY_OVERRIDE")
            severity_override_el.text = rule.get("severity_override", "") or ""

            severity_justification_el = ET.SubElement(vuln_node, "SEVERITY_JUSTIFICATION")
            severity_justification_el.text = rule.get("severity_justification", "") or ""

    # ------------------------------------------------------------------ #
    # Write output
    # ------------------------------------------------------------------ #
    if output_ckl_file is None:
        output_ckl_file = str(Path(cklb_file).with_suffix(".ckl"))

    xml_string = minidom.parseString(
        ET.tostring(checklist, encoding="unicode")
    ).toprettyxml(indent="    ", encoding=None)

    # minidom prepends an XML declaration — strip it so the output
    # matches the bare-root format STIG Viewer expects
    lines = xml_string.splitlines()
    if lines and lines[0].startswith("<?xml"):
        lines = lines[1:]
    clean_xml = "\n".join(lines)

    with open(output_ckl_file, "w", encoding="utf-8") as f:
        f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
        f.write("<!-- DISA STIG Viewer :: 2.x -->\n")
        f.write(clean_xml)

    return output_ckl_file


# ------------------------------------------------------------------ #
# Helpers
# ------------------------------------------------------------------ #

def _join_legacy_ids(legacy_ids: list) -> str:
    """Flatten legacy_ids list to a semicolon-separated string."""
    if not legacy_ids:
        return ""
    if isinstance(legacy_ids[0], dict):
        return "; ".join(str(item.get("id", item)) for item in legacy_ids)
    return "; ".join(str(item) for item in legacy_ids)


def _join_cci_refs(ccis: list) -> str:
    """Flatten CCIs list to a space-separated string (CCI-XXXXXX format)."""
    if not ccis:
        return ""
    if isinstance(ccis[0], dict):
        return " ".join(str(item.get("cci", item)) for item in ccis)
    return " ".join(str(item) for item in ccis)

if __name__ == "__main__":
    import sys
    args = sys.argv[1:]
    if not args:
        print("Usage: docker run --rm -v /your/path:/data cklb-converter <file.cklb> [output.ckl]")
        sys.exit(1)
    inp = args[0] if args[0].startswith("/") else f"/data/{args[0]}"
    out = (args[1] if args[1].startswith("/") else f"/data/{args[1]}") if len(args) > 1 else None
    result = cklb_to_ckl(inp, out)
    print(f"Written: {result}")