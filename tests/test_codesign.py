import pathlib

from strongarm.macho import MachoParser
from strongarm.macho.codesign import CodesignParser


class TestCodeSignParser:
    TARGET_PATH = pathlib.Path(__file__).parent / "bin" / "TestBinary1"

    def setup_method(self):
        parser = MachoParser(TestCodeSignParser.TARGET_PATH)
        self.binary = parser.get_arm64_slice()
        self.codesign_parser = CodesignParser(self.binary)

    def test_find_codesign_command(self):
        assert self.binary.code_signature_cmd.cmd == 0x1D
        assert self.binary.code_signature_cmd.cmdsize == 0x10
        assert self.binary.code_signature_cmd.dataoff == 0x12D2E0
        assert self.binary.code_signature_cmd.datasize == 0x6500

    def test_entitlements(self):
        correct_ents = bytearray(
            b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            b'<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
            b'<plist version="1.0">\n'
            b"\t<dict>\n"
            b"\t\t<key>keychain-access-groups</key>\n"
            b"\t\t<array>\n"
            b"\t\t\t<string>E6435Z6R89.com.honestdollar.honestdollar</string>\n"
            b"\t\t</array>\n"
            b"\n"
            b"\t\t<key>com.apple.developer.team-identifier</key>\n"
            b"\t\t<string>E6435Z6R89</string>\n"
            b"\n"
            b"\t\t<key>application-identifier</key>\n"
            b"\t\t<string>E6435Z6R89.com.honestdollar.honestdollar</string>\n"
            b"\n"
            b"\t</dict>\n"
            b"</plist>"
        )
        assert self.codesign_parser.entitlements == correct_ents

    def test_identifier(self):
        assert self.codesign_parser.signing_identifier == "com.honestdollar.honestdollar"

    def test_team_id(self):
        assert self.codesign_parser.signing_team_id == "E6435Z6R89"
