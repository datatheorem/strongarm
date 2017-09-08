from strongarm.macho_parse import MachoParser

filename = './GoodCertificateValidation'
parser = MachoParser(filename)
print('symtab {} dysymtab {}'.format(parser.symtab, parser.dysymtab))
print('encryption info {}'.format(parser.encryption_info))
print('__cstring: {}'.format(parser.get_section_with_name('__cstring')))
print('cputype {}'.format(hex(parser.header.cputype)))
print('imagebase {}'.format(hex(parser.get_virtual_base())))