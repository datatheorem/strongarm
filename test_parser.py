from strongarm.macho_parse import MachoParser

filename = './GoodCertificateValidation'
parser = MachoParser(filename)
print('symtab {} dysymtab {}'.format(dir(parser.symtab), dir(parser.dysymtab)))