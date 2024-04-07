"""_summary_
To collect features, you need to install clang, and it is recommended to use python 3.7.  In clang, modify the file = 'libclang-11.so' in cindex to file = 'libclang.so'.

run demo:
python /home/a/fuzz/DPfuzz/script/py/prediction/collect_data_for_defect_prediction.py mjs /home/a/fuzz/DPfuzz/dataset/mjs /home/a/fuzz/DPfuzz/script/py/prediction/lizard_file /home/a/build/llvm_tools/build-llvm/llvm/lib /home/a/fuzz/DPfuzz/script/py/prediction/PUT_features
"""
import clang.cindex
from collections import Counter
import math
import json
import csv
import sys
argv = sys.argv
PROJECT = argv[1]
PUT_PATH = argv[2]
LIZARD_PATH = argv[3]
CLANG_PATH = argv[4]
SAVE_PATH = argv[5]
#
pjfeatures = dict()
cfileSet = set()

lzF = open(LIZARD_PATH+f'/lizard_{PROJECT}.txt', 'r', encoding='utf-8')
lzfLines = lzF.readlines()
for l in lzfLines:
    if '.c' in l or '.h' in l:
        l = l.rstrip("\n")
        l_whithoutSpace = [i for i in l.split(' ') if i != '']
        if '@' not in l_whithoutSpace[-1]:
            continue
        funcLoc = l_whithoutSpace[-1].split('@')
        longName = PUT_PATH+funcLoc[-1][1:]+"@"+funcLoc[0]
        cfileSet.add(PUT_PATH+funcLoc[-1][1:])
        pjfeatures[longName] = {
            'line_start': int(funcLoc[1].split('-')[0]),
            'line_end': int(funcLoc[1].split('-')[-1]),
            'length': int(l_whithoutSpace[4]),
            'comment_lines': 0,
            'space_lines': 0,
            'code_lines': int(l_whithoutSpace[0]),
            'code_and_comment_lines': int(l_whithoutSpace[4]),
            'cyclomatic_complexity': int(l_whithoutSpace[1]),
            'token': int(l_whithoutSpace[2]),
            'parameter': int(l_whithoutSpace[3]),
            'branch': 0,
            'n1': 0,
            'n2': 0,
            'N1': 0,
            'N2': 0,
            'HALSTEAD_DIFFICULTY': 0,
            'HALSTEAD_EFFORT': 0,
            'HALSTEAD_ERROR_EST': 0,
            'HALSTEAD_LENGTH': 0,
            'HALSTEAD_LEVEL': 0,
            'HALSTEAD_PROG_TIME': 0,
            'HALSTEAD_VOLUME': 0,
        }


#
clang.cindex.Config.set_library_path(CLANG_PATH)
#


def count_operators(cursor):
    operator_tokens = ["+", "-", "*", "/", "%", "&", "|", "^", "~", "!", "=", "<", ">", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<", ">>", "<<=", ">>="]
    operator_counts = Counter()
    for token in cursor.get_tokens():
        if token.spelling in operator_tokens:
            operator_counts[token.spelling] += 1
    return operator_counts


def count_operands(cursor):
    operands = list()
    for child in cursor.get_children():
        if child.kind == clang.cindex.CursorKind.DECL_REF_EXPR:
            operands.append(child.spelling)
        operands += count_operands(child)
    return operands


def get_functions(cursor):
    stack = [(cursor, None)]
    while stack:
        cursor, parent_location = stack.pop()
        location = cursor.location
        if cursor.kind.is_declaration() and cursor.kind == clang.cindex.CursorKind.FUNCTION_DECL and cursor.location.file.name.endswith('.c'):
            longName = location.file.name+"@"+cursor.spelling
            countOperator = count_operators(cursor)
            countOperand = count_operands(cursor)
            n1 = len(countOperator)
            n2 = len(set(countOperand))
            N1 = sum(list(countOperator.values()))
            N2 = len(countOperand)
            comment_lines = 0
            branch_count = 0
            for token in cursor.get_tokens():
                if token.kind == clang.cindex.TokenKind.COMMENT:
                    comment_lines += token.spelling.count('\n')
                if token.kind == clang.cindex.TokenKind.KEYWORD and token.spelling in ['if', 'else', 'for', 'while', 'switch']:
                    branch_count += 1
            if longName in pjfeatures.keys():
                pjfeatures[longName]['comment_lines'] = comment_lines
                pjfeatures[longName]['space_lines'] = 0
                if int(pjfeatures[longName]['length']) > (comment_lines + pjfeatures[longName]['code_lines']):
                    pjfeatures[longName]['space_lines'] = int(pjfeatures[longName]['length']) - comment_lines - pjfeatures[longName]['code_lines']
                if comment_lines + pjfeatures[longName]['code_lines'] >= 0:
                    pjfeatures[longName]['code_and_comment_lines'] = comment_lines + pjfeatures[longName]['code_lines']
                pjfeatures[longName]['branch'] = branch_count
                pjfeatures[longName]['n1'] = n1
                pjfeatures[longName]['n2'] = n2
                pjfeatures[longName]['N1'] = N1
                pjfeatures[longName]['N2'] = N2
                pjfeatures[longName]['HALSTEAD_LEVEL'] = 0
                if n1 != 0 and N2 != 0:
                    pjfeatures[longName]['HALSTEAD_LEVEL'] = (2*n2)/(n1*N2)
                pjfeatures[longName]['HALSTEAD_DIFFICULTY'] = 0
                if pjfeatures[longName]['HALSTEAD_LEVEL'] != 0:
                    pjfeatures[longName]['HALSTEAD_DIFFICULTY'] = 1/pjfeatures[longName]['HALSTEAD_LEVEL']
                pjfeatures[longName]['HALSTEAD_VOLUME'] = 0
                if (n1+n2) != 0:
                    pjfeatures[longName]['HALSTEAD_VOLUME'] = (N1+N2)*(math.log2(n1+n2))
                pjfeatures[longName]['HALSTEAD_EFFORT'] = pjfeatures[longName]['HALSTEAD_DIFFICULTY']*pjfeatures[longName]['HALSTEAD_VOLUME']
                pjfeatures[longName]['HALSTEAD_ERROR_EST'] = pjfeatures[longName]['HALSTEAD_VOLUME']/3000
                pjfeatures[longName]['HALSTEAD_LENGTH'] = N1+N2
                pjfeatures[longName]['HALSTEAD_PROG_TIME'] = pjfeatures[longName]['HALSTEAD_EFFORT']/(18*3600)
                print(longName, pjfeatures[longName])
        for child in cursor.get_children():
            if child.kind.is_declaration() and child.kind == clang.cindex.CursorKind.FUNCTION_DECL and child.location.file.name.endswith('.c'):
                stack.append((child, location))

index = clang.cindex.Index.create()
for cfile in cfileSet:
    tu = index.parse(cfile)
    get_functions(tu.cursor)

saveF = open(SAVE_PATH+'/'+PROJECT+'.json', 'w')
saveF.write(json.dumps(pjfeatures))
saveF.close()
title = ['PJ_FUNCTION','NUMBER_OF_LINES', 'CYCLOMATIC_COMPLEXITY', 'PARAMETER_COUNT', 'BRANCH_COUNT', 'LOC_CODE_AND_COMMENT', 'HALSTEAD_DIFFICULTY', 'HALSTEAD_EFFORT', 'HALSTEAD_ERROR_EST', 'HALSTEAD_LENGTH', 'HALSTEAD_LEVEL', 'HALSTEAD_PROG_TIME', 'HALSTEAD_VOLUME']
data = []
for k,v in pjfeatures.items():
    data.append([k,v['length'],v['cyclomatic_complexity'],v['parameter'],v['branch'],v['code_and_comment_lines'],v['HALSTEAD_DIFFICULTY'],v['HALSTEAD_EFFORT'],v['HALSTEAD_ERROR_EST'],v['HALSTEAD_LENGTH'],v['HALSTEAD_LEVEL'],v['HALSTEAD_PROG_TIME'],v['HALSTEAD_VOLUME']])
csv_file = open(SAVE_PATH+'/'+PROJECT+'.csv', 'w', newline='')
writer = csv.writer(csv_file)
writer.writerow(title)
for i in data:
    writer.writerow(i)
csv_file.close()
