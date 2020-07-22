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
import AuxData_pb2 as AuxData
import ByteInterval_pb2 as ByteInterval
import ProxyBlock_pb2 as ProxyBlock
import CFG_pb2 as CFG
import Section_pb2 as Section
from uuid import uuid4
import StringIO

class Serialiser:
    b = None
    size = 0
    def __init__(self):
        self.b = StringIO.StringIO()
        self.size = 0
        
    def write_long(self, val):
        import struct;
        self.b.write(struct.pack("<q", val))
        self.size += 4

    def write_uuid_dict(self, uuid_dict):
        self.write_long(len(uuid_dict))
        for k in uuid_dict.keys():
            self.write_uuid(k)
            self.write_uuid(uuid_dict[k])
            
    def write_uuid_map_set(self, uuid_map_set):
        self.write_long(len(uuid_map_set))
        for k in uuid_map_set.keys():
            self.write_uuid(k)
            self.write_uuid_set(uuid_map_set[k])
            
    def write_uuid_set(self, uuid_set):
        self.write_long(len(uuid_set))
        for k in uuid_set:
            self.write_uuid(k)

    def write_uuid(self, uuid):
        self.b.write(uuid)
        self.size += 16

    def to_bytes(self):
        return self.b.getvalue()
    

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
    if processor == "x86" or processor == "metapc":
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


def make_blocks(isa, section, iv, blocks, function_names, function_blocks, function_entries):
    base = idc.SegStart(section)
    end = idc.SegEnd(section)
    seg = idaapi.getseg(section)
    
    # Code blocks
    for fn_entry_address in idautils.Functions(base, end):
        fn = idaapi.get_func(fn_entry_address)
        name = func_name_propagate_thunk(fn_entry_address)
        for fn_block in idaapi.FlowChart(fn):
            start_addr = fn_block.startEA
            end_addr = fn_block.endEA
            outer = ByteInterval.Block()
            # replacing `fn_entry_address` below with `start_addr` causes deserialisation error in niobe DB
            outer.offset = fn_entry_address - base
            id = blocks.get(start_addr, None)
            if id is None:
                id = uuid4().bytes
                blocks[start_addr] = id
                
            if name not in function_names and start_addr == fn_entry_address:
                function_names[name] = id
            
            fn_uuid = function_names[name]    
            if name not in function_blocks:
                function_blocks[fn_uuid] = {id}
            else:
                function_blocks[fn_uuid].add(id)
            
            if id not in function_entries and start_addr == fn_entry_address:
                # Why is this a set if there can't be multiple entries to a function?
                function_entries[id] = {function_names[name]}
                
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
    

def make_byte_intervals(isa, section, blocks, function_names, function_blocks, function_entries):
    # just one
    bint = ByteInterval.ByteInterval()
    bint.uuid = uuid4().bytes
    bint.has_address = True
    bint.address = idc.SegStart(section)
    bint.size = idc.SegEnd(section) - bint.address
    make_blocks(isa, section, bint, blocks, function_names, function_blocks, function_entries)
    bint.contents = idaapi.get_bytes(bint.address, bint.size)
    return [bint]

def is_invalid_ea(ea):
  # Returns `True` if `ea` is not valid, i.e. it doesn't point into any valid segment.
  if (idc.BADADDR == ea) or (idc.get_segm_name(ea) == "LOAD"):
    return True
  try:
    idc.get_segm_attr(idc.get_segm_start(ea), idc.SEGATTR_TYPE)
    return False  # If we get here, then it must be a valid ea
  except:
    return True 


def make_sections(isa, blocks, function_names, function_blocks, function_entries):
    sections = []
    for ea in idautils.Segments():
        if is_invalid_ea(ea): continue
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
        section.byte_intervals.extend(make_byte_intervals(isa, ea, blocks, function_names, function_blocks, function_entries))
        sections.append(section)
    return sections

# Adapted from BAPs IDA plugin
from idaapi import get_func_name2 as get_func_name

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

# TODO this is probably redudant with the current make_blocks function
# which executes the same function iteration
def make_symbols(module, blocks, function_names):
    function_uuid_mapping = dict()
    for ea in idautils.Segments():
        if is_invalid_ea(ea): continue
        fs = idautils.Functions(idc.SegStart(ea), idc.SegEnd(ea))
        for f in fs:
            name = func_name_propagate_thunk(f)
            addr = idc.GetFunctionAttr(f, idc.FUNCATTR_START)
            sym = Symbol.Symbol()
            sym.uuid = uuid4().bytes
            sym.name = name
            sym.referent_uuid = blocks[addr] 
            module.symbols.append(sym)
            if name not in function_names:
                function_names[name] = uuid4().bytes
            
            f_uuid = function_names[name]
            if f_uuid not in function_uuid_mapping:
                function_uuid_mapping[f_uuid] = sym.uuid
            
    sz = Serialiser()
    sz.write_uuid_dict(function_uuid_mapping)
    aux = AuxData.AuxData()
    aux.type_name = "mapping<UUID,UUID>"
    aux.data = sz.to_bytes()
    # nasty copyfrom is not documented anywhere....
    module.aux_data["functionNames"].CopyFrom(aux)
    

# TODO Investigate whether detailed CFG edge properties are required.
# Could be obtained via adaptaptation of mcsema's IDA exporter, or BinExport
# https://github.com/lifting-bits/mcsema/blob/master/tools/mcsema_disass/ida7/flow.py
# Only supports x86, AMD64, AAarch64, so will require additional support for ARM32, and MIPS

def make_edgelabel(from_fn, dest, is_conditional):
    label = CFG.EdgeLabel()
    external = False
    label.conditional = is_conditional
    dest_fn = idaapi.get_func(dest.startEA)
    if dest_fn and dest_fn != from_fn:
        if dest_fn.flags & (idaapi.FUNC_LIB | idaapi.FUNC_THUNK):
            external = True
        else:
            label.type = CFG.Type_Call
            
    # TODO check whether indirect jump or any of the below
    # if kind.isJump():
    #     builder.setType(EdgeType.Type_Branch)
    # elif kind.isCall():
    #     builder.setType(EdgeType.Type_Call)
    # elif kind.hasFallthrough():
    #     builder.setType(EdgeType.Type_Fallthrough)
    # else:
    #     return None
    return (label, external)


def make_cfg(blocks, proxy_blocks, info):
    cfg = CFG.CFG()
    entry_point_uuid = None
    for ea in idautils.Segments():
        if is_invalid_ea(ea): continue
        for fn_entry_address in idautils.Functions(idc.SegStart(ea), idc.SegEnd(ea)):
            fn = idaapi.get_func(fn_entry_address)
            for fn_block in idaapi.FlowChart(fn):
                addr = fn_block.startEA
                uuid = blocks.get(addr, None)
                if uuid is None:
                    uuid = uuid4().bytes
                    blocks[addr] = uuid
                    cfg.vertices.append(uuid)
                if addr == info["entry_point"]:
                    entry_point_uuid = uuid
                is_conditional = fn_block.succs() > 1
                for dest in fn_block.succs():
                    label, external = make_edgelabel(fn, dest, is_conditional)
                    if label is None:
                        continue
                    destAddr = dest.startEA
                    destUuid = blocks.get(destAddr, None)
                    if destUuid is None:
                        destUuid = uuid4().bytes
                        blocks[destAddr] = destUuid
                        cfg.vertices.append(destUuid)
                        if external:
                            proxy_block = ProxyBlock.ProxyBlock()
                            proxy_block.uuid = destUuid
                            if proxy_block not in proxy_blocks:
                                proxy_blocks.append(proxy_block)
                    edge = CFG.Edge()
                    edge.source_uuid = uuid
                    edge.target_uuid = destUuid
                    edge.label.MergeFrom(label)
                    cfg.edges.append(edge)
                
    return (cfg, entry_point_uuid)

def make_module(blocks, proxy_blocks, info):
    
    function_names = dict()
    function_blocks = dict()
    function_entries = dict()
    
    module = Module.Module()
    module.aux_data.clear()
    module.uuid = uuid4().bytes
    module.binary_path = info["exec_path"]
    module.preferred_addr = info["image_base"]
    module.rebase_delta = 0
    module.file_format = Module.IdaProDb64
    isa = make_isa(info)
    module.isa = isa
    module.name = info["prog_name"]
    module.proxies.extend(proxy_blocks)
    module.sections.extend(make_sections(isa, blocks, function_names, function_blocks, function_entries))
    make_symbols(module, blocks, function_names)
    
    sz = Serialiser()
    sz.write_uuid_map_set(function_blocks)
    aux = AuxData.AuxData()
    aux.type_name = "mapping<UUID,set<UUID>>"
    aux.data = sz.to_bytes()
    module.aux_data["functionBlocks"].CopyFrom(aux)
    
    sz = Serialiser()
    sz.write_uuid_map_set(function_entries)
    aux = AuxData.AuxData()
    aux.type_name = "mapping<UUID,set<UUID>>"
    aux.data = sz.to_bytes()
    module.aux_data["functionEntries"].CopyFrom(aux)
    
    return module


def make_ir():
    ir = IR.IR()
    ir.uuid = uuid4().bytes
    blocks = dict()
    proxy_blocks = []
    info = get_meta()
    (cfg, entry_point_uuid) = make_cfg(blocks, proxy_blocks, info)
    ir.cfg.MergeFrom(cfg)
    module = make_module(blocks, proxy_blocks, info)
    # Shouldn't modules support multiple entry points?
    module.entry_point = entry_point_uuid
    ir.modules.append(module)
    # ir.aux_data.append()
    ir.version = GTIRB_VERSION
    return ir

idc.auto_wait()
filename = windowsify(idc.ARGV[1])
with open(filename, "wb") as f:
    f.write(make_ir().SerializeToString())
    print("Export successful!")
idc.qexit(0)