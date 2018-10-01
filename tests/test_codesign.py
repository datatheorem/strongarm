# -*- coding: utf-8 -*-
import os
import unittest

from strongarm.macho import MachoParser
from strongarm.macho.codesign import CodesignParser


class TestCodeSignParser(unittest.TestCase):
    TARGET_PATH = os.path.join(os.path.dirname(__file__), 'bin', 'DigitalAdvisorySolutions')

    def setUp(self):
        parser = MachoParser(TestCodeSignParser.TARGET_PATH)
        self.binary = parser.get_arm64_slice()
        self.codesign_parser = CodesignParser(self.binary)

    def test_find_codesign_command(self):
        self.assertEqual(0x1d, self.binary.code_signature_cmd.cmd)
        self.assertEqual(0x10, self.binary.code_signature_cmd.cmdsize)
        self.assertEqual(0x12d2e0, self.binary.code_signature_cmd.dataoff)
        self.assertEqual(0x6500, self.binary.code_signature_cmd.datasize)

    def test_entitlements(self):
        correct_ents = bytearray(
            b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            b'<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
            b'<plist version="1.0">\n'
            b'\t<dict>\n'
            b'\t\t<key>keychain-access-groups</key>\n'
            b'\t\t<array>\n'
            b'\t\t\t<string>E6435Z6R89.com.honestdollar.honestdollar</string>\n'
            b'\t\t</array>\n'
            b'\n'
            b'\t\t<key>com.apple.developer.team-identifier</key>\n'
            b'\t\t<string>E6435Z6R89</string>\n'
            b'\n'
            b'\t\t<key>application-identifier</key>\n'
            b'\t\t<string>E6435Z6R89.com.honestdollar.honestdollar</string>\n'
            b'\n'
            b'\t</dict>\n'
            b'</plist>')
        self.assertEqual(correct_ents, self.codesign_parser.entitlements)

    def test_identifier(self):
        self.assertEqual('com.honestdollar.honestdollar', self.codesign_parser.signing_identifier)

    def test_team_id(self):
        self.assertEqual('E6435Z6R89', self.codesign_parser.signing_team_id)
