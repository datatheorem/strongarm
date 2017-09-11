from strongarm.macho_parse import MachoParser

#filename = './GoodCertificateValidation'
filename = './Payload/GammaRayTestBad.app/GammaRayTestBad'
parser = MachoParser(filename)
for bin in parser.slices:
    print('symtab {} dysymtab {}'.format(bin.symtab, bin.dysymtab))
    print('encryption info {}'.format(bin.encryption_info))
    print('__cstring: {}'.format(bin.get_section_with_name('__cstring')))
    print('cputype {}'.format(hex(bin.header.cputype)))
    print('imagebase {}'.format(hex(bin.get_virtual_base())))