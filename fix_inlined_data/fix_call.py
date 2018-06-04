#
#   IDAPython script to fix `call; data; pop` sequences
#   
#   The script simply copies the inlined data to a segment named
#   storage, inserts a push and a jmp instead of the `call` and
#   does some cosmetic fixups.
#
#   See
#   https://usualsuspect.re/article/ida-tricks-dealing-with-inlined-data
#   for details
#

def get_storage_segment():
    seg = get_first_seg()

    while seg != BADADDR and get_segm_name(seg) != "storage":
        seg = get_next_seg(seg)

    if seg != BADADDR:
        return seg
    else:
        return None

def fix_call():
    ea = get_screen_ea()

    if print_insn_mnem(ea) != 'call':
        print "Not a call instruction!"
        return

    # address of the trailing 'pop' instruction
    call_target = get_operand_value(ea,0)

    data_start = next_head(ea)
    data_len = call_target-data_start

    storage_addr = get_storage_segment()
    if not storage_addr:
        print "Error: Segment 'storage' not found"
        return

    # get offset in this segment
    offset = data_start - get_segm_attr(data_start,SEGATTR_START)
    copy_dest = storage_addr + offset

    for i in range(data_len):
        PatchByte(copy_dest+i,Byte(data_start+i))

    ida_idp.assemble(ea,0,ea,True,"push 0%08xh" % copy_dest)
    ea += get_item_size(ea)
    ida_idp.assemble(ea,0,ea,True,"jmp 0%08xh" % call_target)
    ea += get_item_size(ea)

    # Undefine the inlined data to clean up the disassembly
    del_items(ea,DELIT_SIMPLE,call_target-ea)
    # Add a name to the copied data
    MakeName(copy_dest,"inlined_%08x" % data_start)

idaapi.add_hotkey("2",fix_call)

