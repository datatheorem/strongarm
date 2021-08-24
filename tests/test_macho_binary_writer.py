import pathlib
from ctypes import c_uint64

from strongarm.macho import ObjcRuntimeDataParser, VirtualMemoryPointer
from strongarm.macho.macho_binary_writer import MachoBinaryWriter
from strongarm.macho.macho_parse import MachoParser


class TestMachoBinaryWriter:
    TEST_BIN_PATH = pathlib.Path(__file__).parent / "bin" / "StrongarmTarget"

    def test_batched_write(self) -> None:
        # Given a binary with some known attributes
        binary = MachoParser(self.TEST_BIN_PATH).get_arm64_slice()

        original_view_controller_data_ref = VirtualMemoryPointer(0x100009190)
        original_view_controller_data_target = VirtualMemoryPointer(0x1000086E8)
        original_view_controller_superclass_target = VirtualMemoryPointer(0x0)

        original_dt_label_data_ref = VirtualMemoryPointer(0x100009140)
        original_dt_label_data_target = VirtualMemoryPointer(0x100008250)

        # Objc external metaclass pointer
        assert binary.read_word(0x100009148, virtual=True) == 0x0

        # Verify that the ObjC class data looks like what we expect
        objc_parser = ObjcRuntimeDataParser(binary)
        view_controller_cls = [c for c in objc_parser.classes if c.name == "ViewController"][0]
        assert view_controller_cls.superclass_name == "_OBJC_CLASS_$_UIViewController"
        assert view_controller_cls.raw_struct.data == original_view_controller_data_target
        assert view_controller_cls.super_classref == original_view_controller_superclass_target
        assert [x.name for x in view_controller_cls.selectors] == [
            "viewDidLoad",
            "didReceiveMemoryWarning",
            "URLSession:didReceiveChallenge:completionHandler:",
        ]

        dt_label_cls = [c for c in objc_parser.classes if c.name == "DTLabel"][0]
        assert dt_label_cls.superclass_name == "_OBJC_CLASS_$_UILabel"
        assert dt_label_cls.raw_struct.data == original_dt_label_data_target
        assert view_controller_cls.super_classref == original_view_controller_superclass_target
        assert [x.name for x in dt_label_cls.selectors] == ["initWithFrame:", "configureLabel", "logLabel"]

        # When I use a MachoBinaryWriter to swap the __objc_data entries of the two classes
        writer = MachoBinaryWriter(binary)
        with writer:
            writer.write_word(c_uint64(original_dt_label_data_target), original_view_controller_data_ref)
            writer.write_word(c_uint64(original_view_controller_data_target), original_dt_label_data_ref)

        # And re-parse the Objective-C data
        rewritten_parser = ObjcRuntimeDataParser(writer.modified_binary)

        # Then I can see that the __objc_data entries have been swapped
        modified_view_controller_cls = [c for c in rewritten_parser.classes if c.name == "ViewController"][0]
        assert modified_view_controller_cls.superclass_name == "_OBJC_CLASS_$_UILabel"

        modified_dt_label_cls = [c for c in rewritten_parser.classes if c.name == "DTLabel"][0]
        assert modified_dt_label_cls.superclass_name == "_OBJC_CLASS_$_UIViewController"
