import idc
import copy
import re
from triton import TritonContext, ARCH, Instruction, OPERAND, AST_NODE, AST_REPRESENTATION, CALLBACK

class RunTrace(object):
    def __init__(self):
        self.tx = TritonContext()
        self.tx.setArchitecture(ARCH.X86)
        self.tx.enableSymbolicEngine(True)

        self.ins_list = dict()

        self.reg_write = dict()

        self.instructions = [{'ins':None,'state':{'regs':{},'mem':{},'esp':0x100000}}]
        self.debug = True

    def setup(self):
        self.tx.setConcreteRegisterValue(self.tx.registers.esp,0x100000)
        return

    def add_instruction(self,ins,prev_esp):
        entry = dict()
        entry['ins'] = ins
        entry['state'] = copy.deepcopy(self.instructions[-1]['state'])

        entry['state']['esp'] = prev_esp

        for write in self.get_side_writes(ins):
            par = self.tx.getParentRegister(write)
            entry['state']['regs'][par.getName()] = len(self.instructions)

        for write in self.get_side_mem_writes(ins):
            addr = write.getAddress()
            entry['state']['mem'][addr] = len(self.instructions)

        # now remove all memory entries if esp is above them, they are considered dead
        cur_esp = self.tx.buildSymbolicRegister(self.tx.registers.esp).evaluate()
        del_list = []
        for addr in entry['state']['mem']:
            if cur_esp > addr:
                del_list.append(addr)

        for a in sorted(del_list,reverse=True):
            print "Removing %08x because esp = %08x" % (a,cur_esp)
            del entry['state']['mem'][a]

        self.instructions.append(entry)
        return len(self.instructions)-1

    def cur_ins(self):
        if len(self.instructions) == 0:
            return None
        else:
            return self.instructions[-1]

    def follow_flow(self):
        ins = self.cur_ins()['ins']
        ast_ctx = self.tx.getAstContext()

        if ins.isBranch():
            op_ast = self.tx.getPathConstraintsAst()
            print "Path Constraints: %s" % op_ast

            model = self.tx.getModel(ast_ctx.lnot(op_ast))
            if model:
                # Real JCC, stop trace
                return None
        elif ins.isControlFlow():
            # call, ret, ... stop trace
            #return None
            pass

        next_ip = self.tx.buildSymbolicRegister(self.tx.registers.eip).evaluate()
        return next_ip

    def get_side_reads(self,ins):
        reads = set()
        for reg,ast in ins.getReadRegisters():
            if not reg.getName() in ("eip","esp"):
                if ins.getDisassembly().startswith("ro") and reg.getName() in ("of","cf"):
                    continue
                reads.add(reg)
        return reads

    def get_side_writes(self,ins):
        writes = set()
        for reg,ast in ins.getWrittenRegisters():
            if not reg.getName() in ("eip","esp"):
                writes.add(reg)
        return writes

    def get_side_mem_reads(self,ins):
        for mem,ast in ins.getLoadAccess():
            yield mem

    def get_side_mem_writes(self,ins):
        for mem, ast in ins.getStoreAccess():
            yield mem

    def trace(self,ip):
        self.setup()
        while True:
            if len(self.instructions) > 1000:
                break
            op = idc.GetManyBytes(ip,idc.ItemSize(ip))
        
            prev_esp = self.tx.buildSymbolicRegister(self.tx.registers.esp).evaluate()

            ins = Instruction()
            ins.setOpcode(op)
            ins.setAddress(ip)
            self.tx.processing(ins)

            ins_id = self.add_instruction(ins,prev_esp)

            if self.debug:
                reads  = " ".join(map(lambda x: x.getName(),self.get_side_reads(ins)))
                writes = " ".join(map(lambda x: x.getName(),self.get_side_writes(ins)))

                mem_writes = " ".join(map(lambda x: "%08x" % x.getAddress(),self.get_side_mem_writes(ins)))

                #print "%08x    [%03d]    %-30s %-20s %-20s %s" % (ip,ins_id,ins.getDisassembly(),reads,writes,self.instructions[-1]['state'])
                print "%08x    [%03d]    %-40s %-30s %-30s (mem writes: %s)" % (ip,ins_id,ins.getDisassembly(),reads,writes,mem_writes)

            next_ip = self.follow_flow()
            if not next_ip:
                break
            ip = next_ip

        good = self.extract_good()
        print "Good instructions: %s" % sorted(good)

        svar_lookup = dict()
        num = 0
        for i in sorted(good):
            esp = ""
            for op in self.instructions[i]['ins'].getOperands():
                if op.getType() == OPERAND.MEM and op.getBaseRegister().getName() == "esp":
                    esp = "%08x" % op.getAddress()

            line = "[%03d]    %s" % (i,self.instructions[i]['ins'].getDisassembly())
            if esp:
                line = re.sub(r"\[esp.*\]","[%s]" % esp,line)
                if int(esp,16) not in svar_lookup:
                    svar_lookup[int(esp,16)] = "svar%d" % num
                    num += 1
                line = line.replace("[%s]" % esp,"[%s]" % svar_lookup[int(esp,16)])

            print line

    def extract_good(self):
        cur = len(self.instructions)-1

        good = set()
        good.add(cur)

        for (reg,writer_num) in self.instructions[cur]['state']['regs'].items():
            good.add(writer_num)

        for (addr,writer_num) in self.instructions[cur]['state']['mem'].items():
            good.add(writer_num)

        final_write = ""

        full_reg_write = ", ".join(map(lambda x: "%s = %d" % (x[0],x[1]),self.instructions[cur]['state']['regs'].items()))
        full_mem_write = ", ".join(map(lambda x: "%08x = %d" % (x[0],x[1]),self.instructions[cur]['state']['mem'].items()))
        print full_reg_write
        print full_mem_write

        while True:
            new_good = set()
            for ins in good:
                prev_state = self.instructions[ins-1]['state']
                for read_reg in self.get_side_reads(self.instructions[ins]['ins']):
                    par = self.tx.getParentRegister(read_reg).getName()
                    if par in prev_state['regs'] and not prev_state['regs'][par] in good:
                        if prev_state['regs'][par] == 96:
                            print "96 good because %s (ins = %d) reg = %s" % (self.instructions[ins]['ins'].getDisassembly(),ins,par)
                        new_good.add(prev_state['regs'][par])

                for read_mem in self.get_side_mem_reads(self.instructions[ins]['ins']):
                    addr = read_mem.getAddress()
                    if addr in prev_state['mem'] and not prev_state['mem'][addr] in good:
                        new_good.add(prev_state['mem'][addr])

            if new_good:
                good |= new_good
            else:
                break

        return good


rt = RunTrace()
rt.trace(ScreenEA())
