import idaapi
import idautils
import re
import idc
import json
import IR_pb2 as IR
import Module_pb2 as Module
import CodeBlock_pb2 as CodeBlock
import Symbol_pb2 as Symbol
import DataBlock_pb2 as DataBlock
import ByteInterval_pb2 as ByteInterval
import CFG_pb2 as CFG
import Section_pb2 as Section
from uuid import uuid4

def windowsify(path):
    if path.startswith('/'):
        path = 'Z:\\\\' + path[1:]
    path = path.replace('/', '\\\\')
    return path

GTIRB_VERSION = 2

# TODO how can we establish THUMB mode in IDA?
def make_decode_mode(isa, addr):
    # if isa == Module.ISA.ARM:
    #     tmode = currentProgram.getRegister("TMode")
    #     value = currentProgram.programContext.getRegisterValue(tmode, addr)
    #     return value.unsignedValueIgnoreMask
    # else:
        return 0


def get_meta():
    binary_info = dict()
    info = idaapi.get_inf_structure()
    try:
        cpuname = info.procname.lower()
    except:
        cpuname = info.procName.lower()
    try:
        # since IDA7 beta 3 (170724) renamed inf.mf -> is_be()/set_be()
        is_be = idaapi.cvar.inf.is_be()
    except:
        # older IDA versions
        is_be = idaapi.cvar.inf.mf

    binary_info['arch'] = cpuname
    binary_info['bits'] = 64 if info.is_64bit() else 32
    binary_info['endian'] = 'Big' if is_be else 'Little'
    binary_info['image_base'] = idc.ida_nalt.get_imagebase()
    binary_info['exec_path'] = idc.ida_nalt.get_input_file_path()
    binary_info['prog_name'] = idc.ida_nalt.get_root_filename()
    binary_info['entry_point'] = info.start_ea

    return binary_info


def make_isa(meta):
    processor = meta["arch"]
    bits = int(meta["bits"])
    if processor == "x86":
        if bits == 64:
            return Module.ISA.X64
        elif bits == 32:
            return Module.ISA.IA32
        else:
            return Module.ISA.ValidButUnsupported
    elif processor == "ARM":
        if bits == 32:
            return Module.ISA.ARM
        elif bits == 64:
            return Module.ISA.ARM64
        else:
            return Module.ISA.ValidButUnsupported
    elif processor == "MIPS":
        if bits == 32:
            return Module.ISA.MIPS32
        elif bits == 64:
            return Module.ISA.MIPS64
        else:
            return Module.ISA.ValidButUnsupported
    elif processor == "PPC":
        if bits == 32:
            return Module.ISA.PPC32
        elif bits == 64:
            return Module.ISA.PPC64
        else:
            return Module.ISA.ValidButUnsupported
    else:
        return Module.ISA.ValidButUnsupported


def make_blocks(isa, section, iv, blocks):
    base = idc.SegStart(section)
    end = idc.SegEnd(section)
    seg = idaapi.getseg(section)
    
    # Code blocks
    for fn_entry_address in idautils.Functions(base, end):
        fn = idaapi.get_func(fn_entry_address)
        for fn_block in idaapi.FlowChart(fn):
            block = dict()
            start_addr = fn_block.startEA
            end_addr = fn_block.endEA
            outer = ByteInterval.Block()
            outer.offset = fn_entry_address - base
            id = blocks.get(start_addr, None)
            if id is None:
                id = uuid4().bytes
                blocks[start_addr] = id
            inner = CodeBlock.CodeBlock()
            inner.uuid = id
            inner.size = end_addr - start_addr
            #inner.decode_mode = make_decode_mode(isa, start_addr)
            outer.code.MergeFrom(inner)
            iv.blocks.append(outer)
            
    # Data blocks
    # TODO deduced type info for data blocks in AuxInfo
    for ea in idautils.Heads(base, end):
        gen_xrefs = idautils.XrefsTo(ea, 0)
        for xx in gen_xrefs:
            if xx.type == idaapi.dr_W or xx.type == idaapi.dr_R: # TODO is this the right types?
                size = idc.get_item_size(ea)
                outer = ByteInterval.Block()
                outer.offset = ea - base
                id = uuid4().bytes
                inner = DataBlock.DataBlock()
                inner.uuid = id
                inner.size = size
                outer.data.MergeFrom(inner)
                iv.blocks.append(outer)


def make_byte_intervals(isa, section, blocks):
    # just one
    bint = ByteInterval.ByteInterval()
    bint.uuid = uuid4().bytes
    bint.has_address = True
    bint.address = idc.SegStart(section)
    bint.size = idc.SegEnd(section) - bint.address
    make_blocks(isa, section, bint, blocks)
    bint.contents = idaapi.get_bytes(bint.address, bint.size)
    return [bint]


def make_sections(isa, blocks):
    sections = []
    for ea in idautils.Segments():
        seg = idaapi.getseg(ea)
        section = Section.Section()
        section.uuid = uuid4().bytes
        section.name = idaapi.get_segm_name(seg)
        section_flags = []
        if seg.perm & idaapi.SEGPERM_READ: section_flags.append(Section.SectionFlag.Readable)
        if seg.perm & idaapi.SEGPERM_WRITE: section_flags.append(Section.SectionFlag.Writable)
        if seg.perm & idaapi.SEGPERM_EXEC: section_flags.append(Section.SectionFlag.Executable)
        ## TODO
        # if section.isLoaded(): section_flags.append(SectionFlag.Loaded)
        # if section.isInitialized(): section_flags.append(SectionFlag.Initialized)
        section.section_flags.extend(section_flags)
        section.byte_intervals.extend(make_byte_intervals(isa, ea, blocks))
        sections.append(section)
    return sections


def make_symbols(module, blocks):
    # Adapted from BAPs IDA plugin
    try:
        from idaapi import get_func_name2 as get_func_name
        # Since get_func_name is deprecated (at least from IDA 6.9)
    except ImportError:
        from idaapi import get_func_name
        # Older versions of IDA don't have get_func_name2
        # so we just use the older name get_func_name

    def func_name_propagate_thunk(ea):
        current_name = get_func_name(ea)
        if current_name[0].isalpha():
            return current_name
        func = idaapi.get_func(ea)
        temp_ptr = idaapi.ea_pointer()
        ea_new = idaapi.BADADDR
        if func.flags & idaapi.FUNC_THUNK == idaapi.FUNC_THUNK:
            ea_new = idaapi.calc_thunk_func_target(func, temp_ptr.cast())
        if ea_new != idaapi.BADADDR:
            ea = ea_new
        propagated_name = get_func_name(ea) or ''  # Ensure it is not `None`
        if len(current_name) > len(propagated_name) > 0:
            return propagated_name
        else:
            return current_name
            # Fallback to non-propagated name for weird times that IDA gives
            #     a 0 length name, or finds a longer import name

    for ea in idautils.Segments():
        fs = idautils.Functions(idc.SegStart(ea), idc.SegEnd(ea))
        for f in fs:
            name = func_name_propagate_thunk(f)
            addr = idc.GetFunctionAttr(f, idc.FUNCATTR_START)
            sym = Symbol.Symbol()
            sym.uuid = uuid4().bytes
            sym.name = name
            sym.referent_uuid = blocks[addr] 
            module.symbols.append(sym)

# TODO Extracting CFG edge properties via adaptaptation of mcsema's IDA exporter
# https://github.com/lifting-bits/mcsema/blob/master/tools/mcsema_disass/ida7/flow.py
# Only supports x86, AMD64, AAarch64, so will require additional support for ARM32, and MIPS

def make_edgelabel(dest, is_conditional):
    label = CFG.EdgeLabel()
    
    label.conditional = is_conditional
    # builder.setDirect(not kind.isIndirect() and not kind.isComputed())
    # if kind.isJump():
    #     builder.setType(EdgeType.Type_Branch)
    # elif kind.isCall():
    #     builder.setType(EdgeType.Type_Call)
    # elif kind.hasFallthrough():
    #     builder.setType(EdgeType.Type_Fallthrough)
    # else:
    #     return None
    return label


def make_cfg(blocks, proxy_blocks):
    cfg = CFG.CFG()
    for ea in idautils.Segments():
        for fn_entry_address in idautils.Functions(idc.SegStart(ea), idc.SegEnd(ea)):
            fn = idaapi.get_func(fn_entry_address)
            for fn_block in idaapi.FlowChart(fn):
                addr = fn_block.startEA
                uuid = blocks.get(addr, None)
                if uuid is None:
                    uuid = uuid4().bytes
                    blocks[addr] = uuid
                    cfg.vertices.append(uuid)
                
                is_conditional = fn_block.succs() > 1
                for dest in fn_block.succs():
                    kind = make_edgelabel(dest, is_conditional)
                    if kind is None:
                        continue
                    # TODO check if external control flow
                    # label, external = kind
                    destAddr = dest.startEA
                    destUuid = blocks.get(destAddr, None)
                    if destUuid is None:
                        destUuid = uuid4().bytes
                        blocks[destAddr] = destUuid
                        cfg.vertices.append(destUuid)
                        # if external:
                        #     proxy_blocks.append(destUuid)
                    edge = CFG.Edge()
                    edge.source_uuid = uuid
                    edge.target_uuid = destUuid
                    edge.label.MergeFrom(kind)
                    cfg.edges.append(edge)
                
    return cfg

def make_module(blocks, proxy_blocks):
    module = Module.Module()
    info = get_meta()
    module.uuid = uuid4().bytes
    module.binary_path = info["exec_path"]
    module.preferred_addr = info["image_base"]
    module.rebase_delta = 0
    module.file_format = Module.IdaProDb64
    isa = make_isa(info)
    module.isa = isa
    module.name = info["prog_name"]
    module.proxies.extend(proxy_blocks)
    module.sections.extend(make_sections(isa, blocks))
    make_symbols(module, blocks)
    #module.aux_data.append()
    module.entry_point = bytes(info["entry_point"])
    return module


def make_ir():
    ir = IR.IR()
    ir.uuid = uuid4().bytes
    blocks = dict()
    proxy_blocks = []
    ir.cfg.MergeFrom(make_cfg(blocks, proxy_blocks))
    ir.modules.append(make_module(blocks, proxy_blocks))
    # ir.aux_data.append()
    ir.version = GTIRB_VERSION
    return ir

filename = windowsify(idc.ARGV[1])
with open(filename, "wb") as f:
    f.write(make_ir().SerializeToString())
idc.qexit(0)