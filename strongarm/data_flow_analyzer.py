from objc_analyzer import ObjcFunctionAnalyzer
from capstone.arm64 import *


class ObjcDataFlowAnalyzer(ObjcFunctionAnalyzer):
    def find_reg_value(self, start_index, desired_reg):
        # type: (int, Text) -> int
        """Read instructions backwards from start_index to find value of reg
        This function will continue reading until it finds all assignments necessary to determine the value of a register

        For example, if we have a function like the following:
        15 | adrp x8, #0x1011bc000
        16 | ldr x22, [x8, #0x370]
        .. | ...
        30 | mov x1, x22
        31 | bl objc_msgSend <-- ObjcDataFlowAnalyzer.find_reg_value(31, 'x1') = 0x1011bc370
        """
        print('analyzing dataflow to determine data in {} at instr idx {}'.format(desired_reg, start_index))
        unknown_regs = [desired_reg]
        known_regs = {}
        waiting = {}

        for instr in self._instructions[start_index::-1]:
            if len(unknown_regs) == 0:
                # found everything we need
                break

            # we only care about instructions that could be moving data between registers
            if len(instr.operands) < 2:
                continue

            dst = instr.operands[0]
            src = instr.operands[1]

            # we're only interested in instructions whose destination is a register
            if dst.type != ARM64_OP_REG:
                continue

            dst_reg_name = instr.reg_name(dst.value.reg)
            # is this register needed for us to determine the value of the requested register?
            if dst_reg_name not in unknown_regs:
                continue

            if src.type == ARM64_OP_IMM:
                # we now know the immediate value in dst_reg_name
                # remove it from unknown list
                unknown_regs.remove(dst_reg_name)
                # add it to known list, along with its value
                known_regs[dst_reg_name] = src.value.imm
            elif src.type == ARM64_OP_REG:
                # we now need the value of src before dst can be determined
                # move dst from list of unknown registers to list of registers waiting for another value
                unknown_regs.remove(dst_reg_name)
                src_reg_name = instr.reg_name(src.value.reg)

                if src_reg_name in known_regs:
                    dst_value = known_regs[src_reg_name]
                    known_regs[dst_reg_name] = dst_value
                else:
                    waiting[dst_reg_name] = src_reg_name, 0
                    unknown_regs.append(src_reg_name)
            elif src.type == ARM64_OP_MEM:
                src_reg_name = instr.reg_name(src.mem.base)
                # dst is being assigned to the value of another register, plus a signed offset
                unknown_regs.remove(dst_reg_name)
                if src_reg_name in known_regs:
                    # we know dst value is value in src plus an offset,
                    # and we know what's in source
                    # we now konw the value of dst
                    dst_value = known_regs[src_reg_name] + src.mem.disp
                    known_regs[dst_reg_name] = dst_value
                else:
                    unknown_regs.append(src_reg_name)
                    waiting[dst_reg_name] = src_reg_name, src.mem.disp

        # once we've broken out of this loop, we should have all the values we need to compute the final value of the
        # desired register.
        # additionally, it should be gauranteed that the unknown values list is empty
        if len(unknown_regs):
            raise RuntimeError('Dataflow loop exited before all unknowns were marked')

        # for every register in the waiting list,
        # cross reference all its dependent variables to calculate the final value
        return self.resolve_register_value(desired_reg, waiting, known_regs)

    def resolve_register_value(self, desired_reg, links, resolved_registers):
        if desired_reg in resolved_registers:
            print('resolved {} to {}'.format(desired_reg, hex(int(resolved_registers[desired_reg]))))
            return resolved_registers[desired_reg]
        source_reg, offset = links[desired_reg]
        print('{} has data dependency: [{}, #{}]'.format(
            desired_reg,
            source_reg,
            hex(int(offset))
        ))
        final_val = self.resolve_register_value(source_reg, links, resolved_registers) + offset

        links.pop(desired_reg)
        resolved_registers[desired_reg] = final_val

        print('resolved {} to {}'.format(desired_reg, hex(int(final_val))))
        return final_val

