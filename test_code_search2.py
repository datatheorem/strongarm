# -*- coding: utf-8 -*-
import os
from time import time
from pprint import pprint

from strongarm.macho import MachoAnalyzer
from strongarm.macho import MachoParser
from strongarm.objc import (
    CodeSearch,
    CodeSearchTermCallDestination,
    RegisterContentsType,
    CodeSearchTermFunctionCallWithArguments,
    ObjcUnconditionalBranchInstruction,
    ObjcFunctionAnalyzer
)


class BadBinaryError(Exception):
    pass


class Run:
    def __init__(self):
        self.path = None
        self.finding_count = None
        self.hits = None
        self.misses = None
        self.runtime = None
        self.type = None
        self.code_size = 0

    def __str__(self):
        s =  'Code Search\n-------------\n'
        s += 'Binary path         : {}\n'.format(self.path)
        s += 'Total time          : {}\n'.format(self.runtime)
        s += 'Search type         : {}\n'.format(self.type)
        s += 'Finding count       : {}\n'.format(self.finding_count)
        s += 'Deep analysis hits  : {}\n'.format(self.hits)
        s += 'Deep analysis misses: {}\n'.format(self.misses)
        if self.hits and self.misses:
            hit_percent = self.hits / self.misses
            s += 'Deep analysis hit % : {}\n'.format(hit_percent*100)
            s += 'Time spent on hits  : {}\n'.format(self.runtime * hit_percent)
            s += 'Time spent on misses: {}\n'.format(self.runtime - (self.runtime*hit_percent))
        return s

    def __repr__(self):
        return "('{}','{}',{},{},{},{},{})".format(
            self.type,
            self.path,
            self.runtime,
            self.finding_count,
            self.hits,
            self.misses,
            self.code_size
        )

    def from_repr(self, s):
        r = Run()
        raise RuntimeError()

    @classmethod
    def from_tup(self, t) -> 'Run':
        r = Run()
        r.type = t[0]
        r.path = t[1]
        r.runtime = t[2]
        r.finding_count = t[3]
        r.hits = t[4]
        r.misses = t[5]
        try:
            r.code_size = t[6]
        except IndexError:
            pass
        return r

    @classmethod
    def from_string(cls, s: str) -> 'Run':
        r = Run()
        # trim paren
        s = s[1::-1]

        components = s.split(',')
        r.type = components[0]
        r.path = components[1]
        r.runtime = float(components[2])
        r.finding_count = int(components[3])
        r.hits = int(components[4])
        r.misses = int(components[5])
        r.code_size = float(components[6])
        return r


def code_size_in_binary(path: str) -> float:
    b = MachoParser(path).get_arm64_slice()
    text_section = b.sections['__text']
    return (text_section.end_address - text_section.address) / 1024 / 1024


def search_bin_old(path: str):
    from strongarm.objc import ObjcFunctionAnalyzer
    print('Normal CodeSearch on {}'.format(path))
    parser = MachoParser(path)
    binary = parser.get_arm64_slice()
    analyzer = MachoAnalyzer.get_analyzer(binary)

    classrefs = [analyzer.classref_for_class_name('_OBJC_CLASS_$_UIWebView')]
    classrefs = [x for x in classrefs if x]

    start_time = time()
    code_search = CodeSearch(
        [
            CodeSearchTermFunctionCallWithArguments(
                binary,
                allowed_functions=ObjcUnconditionalBranchInstruction.OBJC_MSGSEND_FUNCTIONS,
                allowed_arguments={
                    0: classrefs
                }
            )
        ],
    )
    matches = analyzer.search_code(code_search)
    end_time = time()
    total_time = end_time - start_time

    run = Run()
    run.path = path
    run.finding_count = len(matches)
    run.hits = ObjcFunctionAnalyzer._ANALYSIS_HITS
    run.misses = ObjcFunctionAnalyzer._ANALYSIS_MISSES
    run.runtime = total_time
    run.type = 'OLD'
    return run


def search_bin_new(path: str):
    from strongarm.objc import ObjcFunctionAnalyzer
    print(f'Fancy CodeSearch on {path}')
    parser = MachoParser(path)
    binary = parser.get_arm64_slice()
    analyzer = MachoAnalyzer.get_analyzer(binary)

    classref = analyzer.classref_for_class_name('_OBJC_CLASS_$_UIWebView')
    # if not classref:
    #     raise BadBinaryError()

    start_time = time()
    if False:
        # CodeSearchTermObjcCall
        code_search = CodeSearch([
            CodeSearchTermObjcCall(
                binary,
                classes=['_OBJC_CLASS_$_UIWebView'],
                selectors=[],
                allowed_arguments={},
                requires_all_args_matched=False
            )
        ])
    else:
        # CodeSearchTermFunctionCallWithArguments
        code_search = CodeSearch([
            CodeSearchTermFunctionCallWithArguments(
                binary,
                ObjcUnconditionalBranchInstruction.OBJC_MSGSEND_FUNCTIONS,
                allowed_arguments={0: [classref]}
            )
        ])
    matches = analyzer.search_code(code_search)
    end_time = time()
    total_time = end_time - start_time

    run = Run()
    run.path = path
    run.finding_count = len(matches)
    #run.hits = ObjcFunctionAnalyzer._ANALYSIS_HITS
    #run.misses = ObjcFunctionAnalyzer._ANALYSIS_MISSES
    run.hits = 0
    run.misses = 0
    run.runtime = total_time
    run.type = 'NEW'
    run.code_size = code_size_in_binary(path)
    return run


master_data_str = """
{'/Users/philliptennen/binaries/Argo': [('OLD','/Users/philliptennen/binaries/Argo',70.45321607589722,7,7,1337149)],
 '/Users/philliptennen/binaries/Autoblog': [('OLD','/Users/philliptennen/binaries/Autoblog',11.367838144302368,0,0,230205)],
 '/Users/philliptennen/binaries/CareUnify': [('OLD','/Users/philliptennen/binaries/CareUnify',45.49687218666077,5,5,1216764)],
 '/Users/philliptennen/binaries/Chatter': [('OLD','/Users/philliptennen/binaries/Chatter',65.2416319847107,13,13,1186024)],
 '/Users/philliptennen/binaries/Digital Advisory Solutions': [('OLD','/Users/philliptennen/binaries/Digital Advisory Solutions',7.313153028488159,5,5,112814)],
 '/Users/philliptennen/binaries/Evernote': [('OLD','/Users/philliptennen/binaries/Evernote',79.03640079498291,24,24,1492167)],
 '/Users/philliptennen/binaries/Ford EVO': [('OLD','/Users/philliptennen/binaries/Ford EVO',5.801986932754517,0,0,136679)],
 '/Users/philliptennen/binaries/Hacker News': [('OLD','/Users/philliptennen/binaries/Hacker News',1.9695301055908203,7,7,33430)],
 '/Users/philliptennen/binaries/ICCEDistribution': [('OLD','/Users/philliptennen/binaries/ICCEDistribution',18.812509775161743,0,0,457635)],
 '/Users/philliptennen/binaries/Khufu': [('OLD','/Users/philliptennen/binaries/Khufu',8.680479049682617,3,3,222159)],
 '/Users/philliptennen/binaries/LrMobilePhone': [('OLD','/Users/philliptennen/binaries/LrMobilePhone',9.732858896255493,3,3,242895)],
 '/Users/philliptennen/binaries/Musical.ly': [('OLD','/Users/philliptennen/binaries/Musical.ly',180.04168581962585,0,0,3359858)],
 '/Users/philliptennen/binaries/Stride': [('OLD','/Users/philliptennen/binaries/Stride',6.408822774887085,2,2,198106)],
 '/Users/philliptennen/binaries/TurboTax': [('OLD','/Users/philliptennen/binaries/TurboTax',19.374680757522583,0,0,542094)],
 '/Users/philliptennen/binaries/YouTube': [('OLD','/Users/philliptennen/binaries/YouTube',35.26531100273132,9,9,656326)],
 '/Users/philliptennen/binaries/secGaleryFree': [('OLD','/Users/philliptennen/binaries/secGaleryFree',94.64134407043457,0,0,1786220)],
 '/Users/philliptennen/binaries/topups': [('OLD','/Users/philliptennen/binaries/topups',34.075013875961304,5,5,717015)]}
"""
from ast import literal_eval
master_data = literal_eval(master_data_str)


def main():
    paths = ['/Users/philliptennen/gammaray-ios/tests/bin/Payload4/iOS12Demo.app/iOS12Demo',
             '/Users/philliptennen/binaries/Digital Advisory Solutions',
             '/Users/philliptennen/binaries/Hacker News',
             '/Users/philliptennen/binaries/Stride',
             '/Users/philliptennen/apps2/Evernote/saved/Evernote'
             ]
    paths = []
    folder = '/Users/philliptennen/binaries'
    for bin_name in os.listdir(folder):
        path = os.path.join(folder, bin_name)
        paths.append(path)
    # paths = ['/Users/philliptennen/apps2/musically/saved/Musical.ly']

    runs = {}
    for path in paths:
        try:
            runs[path] = []

            try:
                old_run = Run.from_tup(master_data[path][0])
                runs[path].append(old_run)
            except KeyError:
                continue
                # raise BadBinaryError()

            new_run = search_bin_new(path)
            runs[path].append(new_run)
            print(new_run.__str__())
            pprint(runs)

            # if old_run.finding_count != new_run.finding_count:
            #    print(f'WARNING: FINDING COUNT MISMATCH. {old_run.finding_count} VS. {new_run.finding_count}')
            # print(f'New Search / Old Search: {new_run.runtime/old_run.runtime:.2%} search time')

            pprint(runs)
        except BadBinaryError:
            del runs[path]
            continue


if __name__ == '__main__':
    main()

