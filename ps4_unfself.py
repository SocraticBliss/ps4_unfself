#!/usr/bin/env python
'''

PS4 unfself by SocraticBliss (R)
Big Thanks to Znullptr and flatz <3

... Oh and I guess Zecoxao as well

'''

from binascii import hexlify as hx

import struct
import sys

def self_header(file):
    # MAGIC = 4F 15 3D 1D
    # MAGIC, VERSION, MODE, ENDIAN, ATTRIBUTES
    FMT = '<4s4B'
    MAGIC, VERSION, MODE, ENDIAN, ATTRIBUTES = struct.unpack(FMT, file.read(struct.calcsize(FMT)))
    
    print('\n[SELF Header]')
    print('Magic: 0x%s' % hx(MAGIC).upper().decode())
    print('Version: %d' % VERSION)
    print('Mode: 0x%X' % MODE)
    print('Endian: %d (%s)' % (ENDIAN, 'Little Endian' if ENDIAN == 1 else 'Unknown'))
    print('Attributes: 0x%X' % ATTRIBUTES)
    
    # KEY TYPE, HEADER SIZE, META SIZE, FILE SIZE, ENTRY COUNT, FLAG, 4x PADDING
    EXTENDED_FMT = '<2B2x2HQ2H4x'
    CONTENT_TYPE, KEY_TYPE, HEADER_SIZE, META_SIZE, FILE_SIZE, ENTRY_COUNT, FLAG = struct.unpack(EXTENDED_FMT, file.read(struct.calcsize(EXTENDED_FMT)))
    
    print('\n[SELF Extended Header]')
    print('Content Type: 0x%X' % CONTENT_TYPE)
    print('Key Type: 0x%X' % KEY_TYPE)
    print('Header Size: 0x%X' % HEADER_SIZE)
    print('Meta Size: %d Bytes' % META_SIZE)
    print('File Size: %d Bytes' % FILE_SIZE)
    print('Entry Count: %d' % ENTRY_COUNT)
    print('Flag: 0x%X' % FLAG)
    
    return ENTRY_COUNT

def self_entry(entry, file, entries):
    # PROPS, FILE_OFFSET, FILE_SIZE, MEMORY_SIZE
    FMT = '<4Q'
    PROPS, FILE_OFFSET, FILE_SIZE, MEMORY_SIZE = struct.unpack(FMT, file.read(struct.calcsize(FMT)))
    
    print('\n[SELF Entry #%d]' % entry)
    print('Properties: 0x%X' % PROPS)
    # PROPS = [ORDER, ENCRYPTED, SIGNED, COMPRESSED, WINDOW BITS, HAS BLOCK, BLOCK SIZE, HAS DIGEST, HAS EXTENT, HAS META, SEGMENT INDEX]
    
    PROPERTIES = [
    ['Order', 0, 0x1],
    ['Encrypted', 1, 0x1],
    ['Signed', 2, 0x1], 
    ['Compressed', 3, 0x1],
    ['Window Bits', 8, 0x7],    
    ['Has Block', 11, 0x1],
    ['Block Size', 12, 0xF],
    ['Has Digest', 16, 0x1],
    ['Has Extent', 17, 0x1],
    ['Has Meta', 20, 0x1],
    ['Segment Index', 20, 0xFFFF]
    ]
    
    for property in PROPERTIES:
        if property[0] == 'Block Size':
            if ((PROPS >> property[1]) & property[2]) != 0:
                size = 1 << (12 + (PROPS >> property[1]) & property[2])
            else:
                size = 0x1000
            print('    %s: 0x%X' % (property[0], size))
        else:
            print('    %s: %s' % (property[0], (PROPS >> property[1]) & property[2]))
    
    print('File Offset: 0x%X' % FILE_OFFSET)
    print('File Size: %s Bytes' % FILE_SIZE)
    print('Memory Size: %s Bytes' % MEMORY_SIZE)
    
    original = file.tell()
    
    file.seek(FILE_OFFSET)
    entries.append(file.read(FILE_SIZE))
    
    file.seek(original)
    
    return FILE_OFFSET + FILE_SIZE

def elf_header(file, output):
    # 7F 45 4C 46
    # MAGIC, ARCHITECTURE, ENDIAN, VERSION, OS/ABI, ABI VERSION, 6x PADDING, NID SIZE
    FMT = '<4s5B6xB'
    MAGIC, ARCHITECTURE, ENDIAN, VERSION, OS_ABI, ABI_VERSION, EID_SIZE = struct.unpack(FMT, file.read(struct.calcsize(FMT)))
    
    print('\n[ELF Header]')
    print('Magic: 0x%s' % hx(MAGIC).upper().decode())
    print('Architecture: %d (%s)' % (ARCHITECTURE, 'ELF64' if ARCHITECTURE == 2 else 'Unknown'))
    print('Endian: %d (%s)' % (ENDIAN, 'Little Endian' if ENDIAN == 1 else 'Unknown'))
    print('Version: %d (%s)' % (VERSION, 'Current' if VERSION == 1 else 'None'))
    print('OS/ABI: %d (%s)' % (OS_ABI, 'FreeBSD' if OS_ABI == 9 else 'Unknown'))
    print('ABI Version: %d' % ABI_VERSION)
    print('Size: %d' % EID_SIZE)
    
    output.write(struct.pack(FMT, MAGIC, ARCHITECTURE, ENDIAN, VERSION, OS_ABI, ABI_VERSION, EID_SIZE))
    
    # TYPE, MACHINE, VERSION, ENTRY POINT ADDRESS, PROGRAM HEADER OFFSET, SECTION HEADER OFFSET, FLAG, HEADER SIZE, PROGRAM HEADER SIZE, PROGRAM HEADER COUNT, SECTION HEADER SIZE, SECTION HEADER COUNT, SECTION HEADER STRING INDEX
    EX_FMT = '<2HI3QI6H'
    TYPE, MACHINE, VERSION, ENTRY_POINT_ADDRESS, PROGRAM_HEADER_OFFSET, SECTION_HEADER_OFFSET, FLAG, HEADER_SIZE, PROGRAM_HEADER_SIZE, PROGRAM_HEADER_COUNT, SECTION_HEADER_SIZE, SECTION_HEADER_COUNT, SECTION_HEADER_STRING_INDEX = struct.unpack(EX_FMT, file.read(struct.calcsize(EX_FMT)))
    
    TYPES = {
    0x0: 'ET_NONE',
    0x1: 'ET_REL',
    0x2: 'ET_EXEC',
    0x3: 'ET_DYN',
    0x4: 'ET_CORE',
    0xFE00: 'ET_SCE_EXEC',
    0xFE0C: 'ET_SCE_STUBLIB',
    0xFE10: 'ET_SCE_DYNEXEC',
    0xFE18: 'ET_SCE_DYNAMIC',
    }
    
    print('\n[ELF Extension Header]')
    print('Type: 0x%X (%s)' % (TYPE, TYPES.get(TYPE, 'Unknown')))
    print('Machine: 0x%X (%s)' % (MACHINE, 'AMD_X86_64' if MACHINE == 0x3E else 'Unknown'))
    print('Version: %d' % VERSION)
    print('Entry Point Address: 0x%X' % ENTRY_POINT_ADDRESS)
    print('Program Header Offset: 0x%X' % PROGRAM_HEADER_OFFSET)
    print('Section Header Offset: 0x%X' % SECTION_HEADER_OFFSET)
    print('Flag: 0x%X' % FLAG)
    print('Header Size: %d Bytes' % HEADER_SIZE)
    print('Program Header Size: %d Bytes' % PROGRAM_HEADER_SIZE)
    print('Program Header Count: %d' % PROGRAM_HEADER_COUNT)
    print('Section Header Size: %d' % SECTION_HEADER_SIZE)
    print('Section Header Count: %d' % SECTION_HEADER_COUNT)
    print('Section Header String Index: 0x%X' % SECTION_HEADER_STRING_INDEX)
    
    output.write(struct.pack(EX_FMT, TYPE, MACHINE, VERSION, ENTRY_POINT_ADDRESS, PROGRAM_HEADER_OFFSET, SECTION_HEADER_OFFSET, FLAG, HEADER_SIZE, PROGRAM_HEADER_SIZE, PROGRAM_HEADER_COUNT, SECTION_HEADER_SIZE, SECTION_HEADER_COUNT, SECTION_HEADER_STRING_INDEX))
    
    return PROGRAM_HEADER_COUNT, SECTION_HEADER_COUNT

def elf_program_header(program, file, output, entries):
    # TYPE, FLAG, OFFSET, VIRTUAL ADDRESS, PHYSICAL ADDRESS, FILE SIZE, MEMORY SIZE, ALIGNMENT 
    FMT = '<2I6Q'
    TYPE, FLAG, OFFSET, VIRTUAL_ADDRESS, PHYSICAL_ADDRESS, FILE_SIZE, MEMORY_SIZE, ALIGNMENT = struct.unpack(FMT, file.read(struct.calcsize(FMT)))
    
    TYPES = {
    0x0: 'PT_NULL',
    0x1: 'PT_LOAD',
    0x2: 'PT_DYNAMIC',
    0x3: 'PT_INTERP',
    0x4: 'PT_NOTE',
    0x5: 'PT_SHLIB',
    0x6: 'PT_PHDR',
    0x7: 'PT_TLS',
    0x6474E550: 'PT_GNU_EH_FRAME',
    0x6474E551: 'PT_GNU_STACK',
    0x6474E552: 'PT_GNU_RELRO',
    0x60000000: 'PT_SCE_RELA',
    0x61000000: 'PT_SCE_DYNLIBDATA',
    0x61000001: 'PT_SCE_PROCPARAM',
    0x61000002: 'PT_SCE_MODULE_PARAM',
    0x61000010: 'PT_SCE_RELRO',
    0x6FFFFF00: 'PT_SCE_COMMENT',
    0x6FFFFF01: 'PT_SCE_LIBVERSION'
    }
    
    FLAGS = {
    0x0: 'None',
    0x1: 'Execute',
    0x2: 'Write',
    0x4: 'Read',
    0x5: 'Read, Execute',
    0x6: 'Read, Write',
    0x7: 'Read, Write, Execute'
    }
    
    print('\n[ELF Program Header #%d]' % program)
    print('Type: 0x%X (%s)' % (TYPE, TYPES.get(TYPE, 'Unknown')))
    print('Flag: 0x%X (%s)' % (FLAG, FLAGS.get(FLAG, 'Unknown')))
    print('Offset: 0x%X' % OFFSET)
    print('Virtual Address: 0x%X' % VIRTUAL_ADDRESS)
    print('Physical Address: 0x%X' % PHYSICAL_ADDRESS)
    print('File Size: 0x%X' % FILE_SIZE)
    print('Memory Size: 0x%X' % MEMORY_SIZE)
    print('Alignment: 0x%X' % ALIGNMENT)
    
    output.write(struct.pack(FMT, TYPE, FLAG, OFFSET, VIRTUAL_ADDRESS, PHYSICAL_ADDRESS, FILE_SIZE, MEMORY_SIZE, ALIGNMENT))
    original = output.tell()
    
    for entry in entries:
        if len(entry) == FILE_SIZE:
            output.seek(OFFSET)
            output.write(entry)
            entries.remove(entry)
            output.seek(original)
    
    if TYPE == 0x6FFFFF01:
        print('\n[SELF Version]')
        print('Version: %d' % FILE_SIZE)

def elf_section_header(section, file):
    # NAME, TYPE, FLAG, ADDRESS, OFFSET, SIZE, LINK, INFORMATION, ALIGNMENT, ENTRY SIZE
    FMT = '<2I4Q2I2Q'
    NAME, TYPE, FLAG, ADDRESS, OFFSET, SIZE, LINK, INFORMATION, ALIGNMENT, ENTRY_SIZE = struct.unpack(FMT, file.read(struct.calcsize(FMT)))
    
    TYPES = {
    0x0: 'SHT_NULL',
    0x1: 'SHT_PROGBITS',
    0x2: 'SHT_SYMTAB',
    0x3: 'SHT_STRTAB',
    0x4: 'SHT_RELA',
    0x5: 'SHT_HASH',
    0x6: 'SHT_DYNAMIC',
    0x7: 'SHT_NOTE',
    0x8: 'SHT_NOBITS',
    0x9: 'SHT_REL',
    0xA: 'SHT_SHLIB',
    0xB: 'SHT_DYNSYM',
    0xE: 'SHT_INIT_ARRAY',
    0xF: 'SHT_FINI_ARRAY',
    0x10: 'SHT_PREINIT_ARRAY',
    0x11: 'SHT_GROUP',
    0x12: 'SHT_SYMTAB_SHNDX',
    0x61000001: 'SHT_SCE_NID'
    }
    
    FLAGS = {
    0x1: 'SHF_WRITE',
    0x2: 'SHF_ALLOC',
    0x4: 'SHF_EXECINSTR',
    0x10: 'SHF_MERGE',
    0x20: 'SHF_STRINGS',
    0x40: 'SHF_INFO_LINK',
    0x80: 'SHF_LINK_ORDER',
    0x100: 'SHF_OS_NONCONFORMING',
    0x200: 'SHF_GROUP',
    0x400: 'SHF_TLS'
    }
    
    print('\n[ELF Section Header #%d]' % section)
    print('Name: %s' % NAME)
    print('Type: 0x%X (%s)' % (TYPE, TYPES.get(TYPE, 'Unknown')))
    print('Flag: 0x%X (%s)' % (FLAG, FLAGS.get(FLAG, 'Unknown')))
    print('Address: 0x%X' % ADDRESS)
    print('Offset: 0x%X' % OFFSET)
    print('Size: %d Bytes' % SIZE)
    print('Link: %s' % LINK)
    print('Information: %s' % INFORMATION)
    print('Alignment: 0x%X' % ALIGNMENT)
    print('Entry Size: %d Bytes' % ENTRY_SIZE)

def self_extended_information(file):
    # AUTHENTICATION ID, PROGRAM TYPE, APPLICATION VERSION, FIRMWARE VERSION, DIGEST
    FMT = '<8x4Q32s'
    AUTHENTICATION_ID, TYPE, APPLICATION_VERSION, FIRMWARE_VERSION, DIGEST = struct.unpack(FMT, file.read(struct.calcsize(FMT)))
    
    AUTHS = {
    0x3C00000000000001 : 'HOST_KERNEL',
    0x3E00000000000003 : 'PUP_MGR',
    0x3E00000000000004 : 'MEME_MGR',
    0x3E00000000000005 : 'AUTH_MGR',
    0x3E00000000000006 : 'IDATA_MGR',
    0x3E00000000000007 : 'MANUMODE_MGR',
    0x3E00000000000008 : 'KEY_MGR',
    0x3E00000000000009 : 'SM_MGR',
    0x3F00000000000001 : 'SECURE_KERNEL'
    }
    
    TYPES = {
    0x1: 'PT_FAKE',
    0x4: 'PT_NPDRM_EXEC',
    0x5: 'PT_NPDRM_DYNLIB',
    0x8: 'PT_SYSTEM_EXEC',
    0x9: 'PT_SYSTEM_DYNLIB',
    0xC: 'PT_HOST_KERNEL',
    0xE: 'PT_SECURE_MODULE',
    0xF: 'PT_SECURE_KERNEL'
    }
    
    print('\n[SELF Extended Information]')
    print('Authentication ID: 0x%X (%s)' % (AUTHENTICATION_ID, AUTHS.get(AUTHENTICATION_ID, 'Unknown')))
    print('Type: 0x%X (%s)' % (TYPE, TYPES.get(TYPE, 'Unknown')))
    print('Application Version: 0x%X' % APPLICATION_VERSION)
    print('Firmware Version: 0x%X' % FIRMWARE_VERSION)
    print('Digest: %s' % hx(DIGEST).upper().decode())
    
    if TYPE in {0x4, 0x5}:
        return True
    return False


def main(argc, argv):
    if argc != 2:
        raise SystemExit('\nUsage : python %s <SELF File>' % argv[0])
    
    try:
        with open(argv[1], 'rb') as input, open(argv[1].split('.')[0] + '.elf', 'wb') as output:
            print('\nParsing PS4 SELF Header...')
            entry_count = self_header(input)
            
            entries = []
            if entry_count > 0:
                print('\nParsing PS4 SELF Entries...')
                for entry in range(entry_count):
                    version = self_entry(entry, input, entries)
            
            original = input.tell()
            
            print('\nParsing SCE Version Information...')
            input.seek(version)
            entries.append(input.read())
            
            input.seek(original)
            
            print('\nParsing PS4 ELF Header...')
            program_header_count, section_header_count = elf_header(input, output)
            
            if program_header_count > 0:
                print('\nParsing PS4 ELF Program Headers...')
                for program in range(program_header_count):
                    elf_program_header(program, input, output, entries)
            
            if section_header_count > 0:
                print('\nParsing PS4 ELF Section Headers...')
                for section in range(section_header_count):
                    elf_section_header(section, input)
            
            print('\nParsing PS4 SELF Extended Information...')
            has_NPDRM = self_extended_information(input)
            
            print('\nDone!')
        
    except:
        raise SystemExit('\nError: Unable to Parse PS4 SELF File!!!')

if __name__ == '__main__':
    main(len(sys.argv), sys.argv)
