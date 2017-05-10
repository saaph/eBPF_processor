# ----------------------------------------------------------------------------
# "THE BEER-WARE LICENSE" (Revision 42):
# <clement (dot) berthaux (at) synacktiv (dot) com> wrote this file.  As long as you
# retain this notice you can do whatever you want with this stuff. If we meet
# some day, and you think this stuff is worth it, you can buy me a beer in
# return.    Clement Berthaux
# ----------------------------------------------------------------------------

from idaapi import *
from idc import *

class DecodingError(Exception):
    pass

class INST_TYPES(object):
    pass

class EBPFProc(processor_t):
    id = 0xeb7f
    flag = PR_ASSEMBLE | PR_SEGS | PR_DEFSEG32 | PR_USE32 | PRN_HEX | PR_RNAMESOK | PR_NO_SEGMOVE
    cnbits = 8
    dnbits = 8
    psnames = ['EBPF']
    plnames = ['EBPF']
    segreg_size = 0
    instruc_start = 0
    assembler = {
        'flag':  ASH_HEXF3 | AS_UNEQU | AS_COLON | ASB_BINF4 | AS_N2CHR,
        "uflag": 0,
        "name": "wut",
        "origin": ".org",
        "end": ".end",
        "cmnt": ";",
        "ascsep": '"',
        "accsep": "'",
        "esccodes": "\"'",
        "a_ascii": "db",
        "a_byte": "db",
        "a_word": "dw",
        'a_dword': "dd",
        'a_qword': "dq",
        "a_bss": "dfs %s",
        "a_seg": "seg",
        "a_curip": "PC",
        "a_public": "",
        "a_weak": "",
        "a_extrn": ".extern",
        "a_comdef": "",
        "a_align": ".align",
        "lbrace": "(",
        "rbrace": ")",
        "a_mod": "%",
        "a_band": "&",
        "a_bor": "|",
        "a_xor": "^",
        "a_bnot": "~",
        "a_shl": "<<",
        "a_shr": ">>",
        "a_sizeof_fmt": "size %s",

    }

    def __init__(self):
        processor_t.__init__(self)
        
        self.init_instructions()
        self.init_registers()

    def init_instructions(self):
        # there is a logic behind the opcode values but I chose to ignore it
        self.OPCODES = {
            # ALU
            0x07:('add', self._ana_reg_imm, CF_USE1 | CF_USE2),
            0x0f:('add', self._ana_2regs, CF_USE1|CF_USE2),
            0x17:('sub', self._ana_reg_imm, CF_USE1 | CF_USE2),
            0x1f:('sub', self._ana_2regs, CF_USE1|CF_USE2),
            0x27:('mul', self._ana_reg_imm, CF_USE1|CF_USE2),
            0x2f:('mul', self._ana_2regs, CF_USE1|CF_USE2),
            0x37:('div', self._ana_reg_imm, CF_USE1|CF_USE2),
            0x3f:('div', self._ana_2regs, CF_USE1|CF_USE2),
            0x47:('or', self._ana_reg_imm, CF_USE1|CF_USE2),
            0x4f:('or', self._ana_2regs, CF_USE1|CF_USE2),
            0x57:('and', self._ana_reg_imm, CF_USE1|CF_USE2),
            0x5f:('and', self._ana_2regs, CF_USE1|CF_USE2),
            0x67:('lsh', self._ana_reg_imm, CF_USE1|CF_USE2),
            0x6f:('lsh', self._ana_2regs, CF_USE1|CF_USE2),
            0x77:('rsh', self._ana_reg_imm, CF_USE1|CF_USE2),
            0x7f:('rsh', self._ana_2regs, CF_USE1|CF_USE2),
            0x87:('neg', self._ana_1reg, CF_USE1|CF_USE2), # FIXME
            0x77:('mod', self._ana_reg_imm, CF_USE1|CF_USE2),
            0x7f:('mod', self._ana_2regs, CF_USE1|CF_USE2),
            0xa7:('xor', self._ana_reg_imm, CF_USE1|CF_USE2),
            0xaf:('xor', self._ana_2regs, CF_USE1|CF_USE2),
            0xb7:('mov', self._ana_reg_imm, CF_USE1 | CF_USE2),
            0xbf:('mov', self._ana_2regs, CF_USE1 | CF_USE2),
            0xc7:('arsh', self._ana_reg_imm, CF_USE1 | CF_USE2),
            0xcf:('arsh', self._ana_2regs, CF_USE1 | CF_USE2),

            # TODO: ALU 32 bit opcodes

            # MEM
            0x18:('lddw', self._ana_reg_imm, CF_USE1|CF_USE2),
            0x20:('ldaw', self._ana_phrase_imm, CF_USE1|CF_USE2),
            0x28:('ldah', self._ana_phrase_imm, CF_USE1|CF_USE2),
            0x30:('ldab', self._ana_phrase_imm, CF_USE1|CF_USE2),
            0x38:('ldadw', self._ana_phrase_imm, CF_USE1|CF_USE2),
            0x40:('ldinw', self._ana_phrase_imm, CF_USE1|CF_USE2),
            0x48:('ldinh', self._ana_phrase_imm, CF_USE1|CF_USE2),
            0x50:('ldinb', self._ana_phrase_imm, CF_USE1|CF_USE2),
            0x58:('ldindw', self._ana_phrase_imm, CF_USE1|CF_USE2),
            0x61:('ldxw', self._ana_reg_regdisp, CF_USE1|CF_USE2),
            0x69:('ldxh', self._ana_reg_regdisp, CF_USE1|CF_USE2),
            0x71:('ldxb', self._ana_reg_regdisp, CF_USE1|CF_USE2),
            0x79:('ldxdw', self._ana_reg_regdisp, CF_USE1|CF_USE2),
            0x62:('stw', self._ana_regdisp_reg, CF_USE1|CF_USE2),
            0x6a:('sth', self._ana_regdisp_reg, CF_USE1|CF_USE2),
            0x72:('stb', self._ana_regdisp_reg, CF_USE1|CF_USE2),
            0x7a:('stdw', self._ana_regdisp_reg, CF_USE1|CF_USE2),
            0x63:('stxw', self._ana_regdisp_reg, CF_USE1|CF_USE2),
            0x6b:('stxh', self._ana_regdisp_reg, CF_USE1|CF_USE2),
            0x73:('stxb', self._ana_regdisp_reg, CF_USE1|CF_USE2),
            0x7b:('stxdw', self._ana_regdisp_reg, CF_USE1|CF_USE2),

            # BRANCHES
            0x05:('ja', self._ana_jmp, CF_USE1|CF_JUMP),
            0x15:('jeq', self._ana_cond_jmp_reg_imm, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),
            0x1d:('jeq', self._ana_cond_jmp_reg_reg, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),
            0x25:('jgt', self._ana_cond_jmp_reg_imm, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),
            0x2d:('jgt', self._ana_cond_jmp_reg_reg, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),
            0x35:('jge', self._ana_cond_jmp_reg_imm, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),
            0x3d:('jge', self._ana_cond_jmp_reg_reg, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),
            0x45:('jset', self._ana_cond_jmp_reg_imm, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),
            0x4d:('jset', self._ana_cond_jmp_reg_reg, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),
            0x55:('jne', self._ana_cond_jmp_reg_imm, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),
            0x5d:('jne', self._ana_cond_jmp_reg_reg, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),
            0x65:('jsgt', self._ana_cond_jmp_reg_imm, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),
            0x6d:('jsgt', self._ana_cond_jmp_reg_reg, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),
            0x75:('jsge', self._ana_cond_jmp_reg_imm, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),
            0x7d:('jsge', self._ana_cond_jmp_reg_reg, CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP),

            0x85:('call', self._ana_call, CF_USE1|CF_CALL),            

            0x95:('ret', self._ana_nop, CF_STOP)
        }


        
        Instructions = [{'name':x[0], 'feature':x[2]} for x in self.OPCODES.values()]
        self.inames = {v[0]:k for k,v in self.OPCODES.items()}
        self.instruc_end = 0xff
        self.instruc = [({'name':self.OPCODES[i][0], 'feature':self.OPCODES[i][2]} if i in self.OPCODES else {'name':'unknown_opcode', 'feature':0}) for i in xrange(0xff)]
        
        # self.icode_return = 0x95
        
    def init_registers(self):
        self.regNames = ['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'CS', 'DS']

        self.regFirstSreg = 0
        self.regLastSreg = 1

        self.regCodeSreg = 0
        self.regDataSreg = 1

    def ana(self):        
        try:
            return self._ana()
        except DecodingError:
            return 0

    def _ana(self):
        self.opcode = ua_next_byte()
        registers = ua_next_byte()

        self.src = (registers >> 4) & 15
        self.dst = registers & 15
        
        self.off = ua_next_word()

        # if self.off & 0x8000:
        #     self.off -= 0x10000
            
        self.imm = ua_next_long()
        
        if self.opcode == 0x18:
            ua_next_long()
            imm2 = ua_next_long()
            self.imm += imm2 << 32

        
        self.cmd.itype = self.opcode

        if self.opcode not in self.OPCODES:
            raise DecodingError("wuut")

        self.OPCODES[self.opcode][1]()
        
        return self.cmd.size

    def _ana_nop(self):
        pass
    
    def _ana_reg_imm(self):
        self.cmd[0].type = o_reg
        self.cmd[0].dtyp = dt_dword
        self.cmd[0].reg = self.dst

        self.cmd[1].type = o_imm
        if self.opcode == 0x18:
            self.cmd[1].dtyp = dt_qword
        else:
            self.cmd[1].dtyp = dt_dword
            
        self.cmd[1].value = self.imm
        
    def _ana_1reg(self):
        self.cmd[0].type = o_reg
        self.cmd[0].dtyp = dt_dword
        self.cmd[0].reg = self.dst

    def _ana_2regs(self):
        self.cmd[0].type = o_reg
        self.cmd[0].dtyp = dt_dword
        self.cmd[0].reg = self.dst
        
        self.cmd[1].type = o_reg
        self.cmd[1].dtyp = dt_dword
        self.cmd[1].reg = self.src

    def _ana_call(self):
        self.cmd[0].type = o_imm
        self.cmd[0].value = self.imm
        self.cmd[0].dtyp = dt_dword

    def _ana_jmp(self):
        self.cmd[0].type = o_near
        self.cmd[0].addr = 8*self.off + self.cmd.ea + 8
        self.cmd[0].dtyp = dt_dword

    def _ana_cond_jmp_reg_imm(self):
        self.cmd[0].type = o_reg
        self.cmd[0].dtyp = dt_dword
        self.cmd[0].reg = self.dst

        self.cmd[1].type = o_imm
        self.cmd[1].value = self.imm
        self.cmd[1].dtyp = dt_dword
        
        self.cmd[2].type = o_near
        self.cmd[2].addr = 8 * self.off + self.cmd.ea + 8
        self.cmd[2].dtyp = dt_dword


    def _ana_cond_jmp_reg_reg(self):
        self.cmd[0].type = o_reg
        self.cmd[0].dtyp = dt_dword
        self.cmd[0].reg = self.dst

        self.cmd[1].type = o_reg
        self.cmd[1].dtyp = dt_dword
        self.cmd[1].reg = self.src

        self.cmd[2].type = o_near
        self.cmd[2].addr = 8 * self.off + self.cmd.ea + 8
        self.cmd[2].dtyp = dt_dword

    def _ana_regdisp_reg(self):
        self.cmd[0].type = o_displ
        self.cmd[0].dtyp = dt_dword
        self.cmd[0].value = self.off
        self.cmd[0].phrase = self.dst

        self.cmd[1].type = o_reg
        self.cmd[1].dtyp = dt_dword
        self.cmd[1].reg = self.src

    def _ana_reg_regdisp(self):
        self.cmd[0].type = o_reg
        self.cmd[0].dtyp = dt_dword
        self.cmd[0].reg = self.dst

        self.cmd[1].type = o_displ
        self.cmd[1].dtyp = dt_dword
        self.cmd[1].value = self.off
        self.cmd[1].phrase = self.src


    def _ana_phrase_imm(self):
        self.cmd[0].type = o_reg
        self.cmd[0].dtyp = dt_dword
        self.cmd[0].reg = self.dst
        
        self.cmd[1].type = o_phrase
        self.cmd[1].dtyp = dt_dword
        self.cmd[1].value = self.imm


    def emu(self):
        Feature = self.cmd.get_canon_feature()

        if Feature & CF_JUMP:
            dst_op_index = 0 if self.cmd.itype == 0x5 else 2
            ua_add_cref(self.cmd[dst_op_index].offb, self.cmd[dst_op_index].addr, fl_JN)
            QueueSet(Q_jumps, self.cmd.ea)

        if self.cmd[0].type == o_displ or self.cmd[1].type == o_displ:
            op_ind = 0 if self.cmd[0].type == o_displ else 1
            ua_stkvar2(self.cmd[op_ind], self.cmd[op_ind].value, 1)
            op_stkvar(self.cmd.ea, op_ind)
            
        # if Feature & CF_CALL:
        #     ua_add_cref(self.cmd[0].offb, self.cmd[0].addr, fl_CN)

        flow = (Feature & CF_STOP == 0) and not self.cmd.itype == 0x5
        
        if flow:
            ua_add_cref(0, self.cmd.ea + self.cmd.size, fl_F)
        return True

    def out(self):
        cmd = self.cmd
        ft = cmd.get_canon_feature()
        buf = init_output_buffer(1024)
        OutMnem(15)
        
        if ft & CF_USE1:
            out_one_operand(0)
        if ft & CF_USE2:
            OutChar(',')
            OutChar(' ')
            out_one_operand(1)
        if ft & CF_USE3:
            OutChar(',')
            OutChar(' ')
            out_one_operand(2)
        term_output_buffer()
        cvar.gl_comm = 1
        MakeLine(buf)

    def outop(self, op):
        if op.type == o_reg:
            out_register(self.regNames[op.reg])
        elif op.type == o_imm:
            OutValue(op, OOFW_IMM)
        elif op.type in [o_near, o_mem]:
            ok = out_name_expr(op, op.addr, BADADDR)
            if not ok:
                out_tagon(COLOR_ERROR)
                OutLong(op.addr, 16)
                out_tagoff(COLOR_ERROR)
                QueueMark(Q_noName, self.cmd.ea)
                
        elif op.type == o_phrase:
            out_symbol('[')
            OutValue(op, OOFW_IMM)
            out_symbol(']')
            
        elif op.type == o_displ:
            out_symbol('[')
            out_register(self.regNames[op.phrase])
            OutValue(op, OOFS_NEEDSIGN|OOFW_IMM)
            out_symbol(']')
        else:
            return False
        return True

def PROCESSOR_ENTRY():
    return EBPFProc()
