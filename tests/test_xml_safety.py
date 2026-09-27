"""
XXE guard regression tests (bandit B314).

Wazuh rule/decoder XML is operator/LLM-supplied. Every parser entry point must
reject DTD/entity declarations fail-closed (tools/wazuh/xmlio.safe_fromstring),
and both the tool layer (tools/wazuh/local_rules) and the validator
(tools/wazuh/validation) must route through it.
"""
from __future__ import annotations

import os
import unittest

os.environ.setdefault("MOCK_MODE", "true")

VALID_RULE = ('<rule id="100001" level="5">'
              "<match>ssh</match><description>probe test</description></rule>")

XXE_PAYLOAD = ('<!DOCTYPE rule [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
               '<rule id="1" level="1"><description>&xxe;</description></rule>')

ENTITY_AMPLIFICATION = ('<!DOCTYPE lolz [<!ENTITY lol "lol">'
                        '<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]>'
                        '<rule id="1" level="1"><description>&lol2;</description></rule>')


class TestSafeFromstring(unittest.TestCase):
    def test_valid_rule_parses(self):
        from tools.wazuh.xmlio import safe_fromstring
        root = safe_fromstring(VALID_RULE)
        self.assertEqual(root.tag, "rule")
        self.assertEqual(root.get("id"), "100001")

    def test_doctype_rejected(self):
        from tools.wazuh.xmlio import UnsafeXmlError, safe_fromstring
        with self.assertRaises(UnsafeXmlError):
            safe_fromstring(XXE_PAYLOAD)
        with self.assertRaises(UnsafeXmlError):
            safe_fromstring(XXE_PAYLOAD.lower().replace("xxe", "XXE"))  # case-insensitive

    def test_entity_declaration_rejected(self):
        from tools.wazuh.xmlio import UnsafeXmlError, safe_fromstring
        with self.assertRaises(UnsafeXmlError):
            safe_fromstring(ENTITY_AMPLIFICATION)
        # entities declared mid-file (outside the DOCTYPE) are rejected too
        with self.assertRaises(UnsafeXmlError):
            safe_fromstring(VALID_RULE + "<!ENTITY sneaky 'x'>")

    def test_unsafe_xml_error_is_value_error(self):
        from tools.wazuh.xmlio import UnsafeXmlError
        self.assertTrue(issubclass(UnsafeXmlError, ValueError))


class TestValidationBlocksUnsafeXml(unittest.TestCase):
    def test_validate_reports_unsafe_xml_as_invalid(self):
        from tools.wazuh.validation import validate_wazuh_rule_xml
        res = validate_wazuh_rule_xml(XXE_PAYLOAD)
        self.assertIs(res["valid"], False)
        self.assertTrue(any("DTD/entity" in e for e in res["errors"]))
        res2 = validate_wazuh_rule_xml(ENTITY_AMPLIFICATION)
        self.assertIs(res2["valid"], False)

    def test_validate_accepts_normal_rule(self):
        from tools.wazuh.validation import validate_wazuh_rule_xml
        res = validate_wazuh_rule_xml(VALID_RULE)
        self.assertIs(res["valid"], True)
        self.assertEqual(res["rule_id"], 100001)


class TestLocalRulesRefuseUnsafeXml(unittest.TestCase):
    def _group_file(self) -> str:
        # multi-line, as real local_rules.xml files come from the manager
        return ('<group name="local">\n'
                '  <rule id="99999" level="1">\n'
                "    <description>seed</description>\n"
                "  </rule>\n</group>\n")

    def test_merge_rule_rejects_doctype(self):
        from tools.wazuh.xmlio import UnsafeXmlError
        from tools.wazuh.local_rules import merge_rule
        with self.assertRaises(UnsafeXmlError):
            merge_rule(self._group_file(), XXE_PAYLOAD)

    def test_rule_block_rejects_entity_declaration(self):
        from tools.wazuh.xmlio import UnsafeXmlError
        from tools.wazuh.local_rules import _rule_block
        with self.assertRaises(UnsafeXmlError):
            _rule_block(VALID_RULE + "<!ENTITY sneaky 'x'>")

    def test_merge_decoder_rejects_doctype(self):
        from tools.wazuh.xmlio import UnsafeXmlError
        from tools.wazuh.local_rules import merge_decoder
        dec_xxe = ('<!DOCTYPE decoder [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
                   '<decoder name="app"><prematch>^x</prematch></decoder>')
        with self.assertRaises(UnsafeXmlError):
            merge_decoder("<decoder name=\"seed\"><prematch>x</prematch></decoder>", dec_xxe)

    def test_replace_decoder_rejects_doctype(self):
        from tools.wazuh.xmlio import UnsafeXmlError
        from tools.wazuh.local_rules import replace_decoder
        with self.assertRaises(UnsafeXmlError):
            replace_decoder("<decoder name=\"seed\"><prematch>x</prematch></decoder>",
                            "seed",
                            "<decoder name=\"seed\"><prematch>y</prematch></decoder>"
                            "<!DOCTYPE decoder>")

    def test_merge_rule_still_merges_valid_rule(self):
        from tools.wazuh.local_rules import merge_rule
        new_content, issues = merge_rule(self._group_file(), VALID_RULE)
        self.assertNotIn("100001", self._group_file())
        self.assertIn("100001", new_content)
        self.assertEqual(issues, ["appended rule 100001"])


if __name__ == "__main__":
    unittest.main()