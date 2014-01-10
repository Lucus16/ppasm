import re

class Lexer:
    '''Do not use (), only (?:)'''
    def __init__(self, rules, flags=0):
        self.rules = rules
        self.names = [''] + [x[-1] for x in rules]
        self.regex = re.compile('|'.join('(' + x[0] + ')' for x in rules),
                                flags)
        assert not self.regex.match(''), \
               'One of the provided rules matches the empty string.'

    def __iter__(self):
        return self

    def lex(self, text):
        self.history = []
        self.line = text
        self.pos = 0
        self.end = len(self.line)
        return self

    def back(self, number=1):
        self.pos = self.history[-number]
        self.history = self.history[:-number]
        return self

    def __next__(self):
        if self.pos >= self.end:
            raise StopIteration
        self.history.append(self.pos)
        while True:
            match = self.regex.match(self.line, self.pos)
            if match == None:
                self.pos = self.end
                return self.line[self.history[-1]:]
            self.pos = match.end()
            if self.names[match.lastindex] != None:
                return (match.group(), self.names[match.lastindex])
            else:
                self.history[-1] = self.pos

    def isempty(self):
        return self.pos >= self.end


rules = [
    (r'\s+', None),
    (r'[a-zA-Z_.][a-zA-Z0-9_.]*:', 'label'),
    (r'#.*', None),
    (r'(?:HALT|READ|WRITE|LOADHI|NOP|JUMP)|'
     r'(?:(?:OR|XOR|AND|ADD|SUB|ROL|MOVE|NEG|NOT|ROR)f?)|CMPf', 'opcode'),
    (r'\.(?:T|F|C|GEU|NC|LU|GE|L|NO|O|NZ|Z|GU|LEU|G|LE|NN|N)', 'condition'),
    (r'(?:R1[0-5])|(?:R[0-9])', 'register'),
    (r'\[', None),
    (r'\]', None),
    (r'\,', None),
    (r'[^,#\[\]]+', 'expression'),
    ]


lex = Lexer(rules)


DESTREG = 0x10000000
SRCREGA = 0x00000010
SRCREGB = 0x00100000
ADDRREG = 0x00100000
SRCREG = 0x00000010
SMLCONST = 0x00000100
BIGCONST = 0x00000004
COND = {'.T':    0x00000000,
        '.F':    0x01000000,
        '.C':    0x02000000,
        '.GEU':  0x02000000,
        '.NC':   0x03000000,
        '.LU':   0x03000000,
        '.GE':   0x04000000,
        '.L':    0x05000000,
        '.NO':   0x06000000,
        '.O':    0x07000000,
        '.NZ':   0x08000000,
        '.Z':    0x09000000,
        '.GU':   0x0a000000,
        '.LEU':  0x0b000000,
        '.G':    0x0c000000,
        '.LE':   0x0d000000,
        '.NN':   0x0e000000,
        '.N':    0x0f000000}
REG = {'R0': 0, 'R1': 1, 'R2': 2, 'R3': 3, 'R4': 4, 'R5': 5, 'R6': 6, 'R7': 7,
       'R8': 8, 'R9': 9, 'R10': 10, 'R11': 11, 'R12': 12, 'R13': 13, 'R14': 14,
       'R15': 15}

def geta(srca, addr):
    if srca in REG:
        return SRCREGA * REG[srca]
    else:
        return SMLCONST * evaluate(srca, addr) | 0x00040000

#input is list of arguments as string
instrfn = {'HALT': (lambda x: 0),
           'NOP': (lambda x: 1),
           'READ': (lambda x: ADDRREG * REG[x[0]] |
                    SMLCONST * evaluate(x[1], x[-1]) |
                    DESTREG * REG[x[2]] | 0x00040008),
           'WRITE': (lambda x: SRCREG * REG[x[0]] | ADDRREG * REG[x[1]] |
                     SMLCONST * evaluate(x[2], x[-1]) | 0x0004000c),
           'LOADHI': (lambda x: COND[x[0]] | BIGCONST * evaluate(x[1], x[-1]) |
                      DESTREG * REG[x[2]] | 0x00000002),
           'OR': (lambda x: COND[x[0]] | geta(x[1], x[-1]) | SRCREGB * REG[x[2]] |
                  DESTREG * REG[x[3]] | 0x00000001),
           'XOR': (lambda x: COND[x[0]] | geta(x[1], x[-1]) | SRCREGB * REG[x[2]] |
                  DESTREG * REG[x[3]] | 0x00000003),
           'AND': (lambda x: COND[x[0]] | geta(x[1], x[-1]) | SRCREGB * REG[x[2]] |
                  DESTREG * REG[x[3]] | 0x00000005),
           'ADD': (lambda x: COND[x[0]] | geta(x[1], x[-1]) | SRCREGB * REG[x[2]] |
                  DESTREG * REG[x[3]] | 0x00000009),
           'SUB': (lambda x: COND[x[0]] | geta(x[1], x[-1]) | SRCREGB * REG[x[2]] |
                  DESTREG * REG[x[3]] | 0x0000000b),
           'ROL': (lambda x: COND[x[0]] | geta(x[1], x[-1]) | SRCREGB * REG[x[2]] |
                  DESTREG * REG[x[3]] | 0x0000000f),
           'ORf': (lambda x: COND[x[0]] | geta(x[1], x[-1]) | SRCREGB * REG[x[2]] |
                  DESTREG * REG[x[3]] | 0x00080001),
           'XORf': (lambda x: COND[x[0]] | geta(x[1], x[-1]) | SRCREGB * REG[x[2]] |
                  DESTREG * REG[x[3]] | 0x00080003),
           'ANDf': (lambda x: COND[x[0]] | geta(x[1], x[-1]) | SRCREGB * REG[x[2]] |
                  DESTREG * REG[x[3]] | 0x00080005),
           'ADDf': (lambda x: COND[x[0]] | geta(x[1], x[-1]) | SRCREGB * REG[x[2]] |
                  DESTREG * REG[x[3]] | 0x00080009),
           'SUBf': (lambda x: COND[x[0]] | geta(x[1], x[-1]) | SRCREGB * REG[x[2]] |
                  DESTREG * REG[x[3]] | 0x0008000b),
           'ROLf': (lambda x: COND[x[0]] | geta(x[1], x[-1]) | SRCREGB * REG[x[2]] |
                  DESTREG * REG[x[3]] | 0x0008000f),
           'CMPf': (lambda x: COND[x[0]] | geta(x[1], x[-1]) | SRCREGB * REG[x[2]] |
                    0x0008000b),
           'JUMP': (lambda x: COND[x[0]] | geta('(' + x[1] + ')-($+4)', x[-1]) |
                    SRCREGB * 15 | DESTREG * 15 | 0x00000009),
           'MOVE': (lambda x: COND[x[0]] | geta(x[1], x[-1]) |
                    DESTREG * REG[x[2]] | 0x00000001),
           'NEG': (lambda x: COND[x[0]] | SRCREG * REG[x[1]] |
                   DESTREG * REG[x[2]] | 0x0000000b),
           'NOT': (lambda x: COND[x[0]] | SRCREG * REG[x[1]] |
                   DESTREG * REG[x[2]] | 0x0003ff03),
           'ROR': (lambda x: COND[x[0]] |
                   SMLCONST * evaluate('-('+x[1]+')', x[-1]) |
                   SRCREG * REG[x[2]] | DESTREG * REG[x[3]] | 0x0000000f),
           'MOVEf': (lambda x: COND[x[0]] | geta(x[1], x[-1]) |
                     DESTREG * REG[x[2]] | 0x00080001),
           'NEGf': (lambda x: COND[x[0]] | SRCREG * REG[x[1]] |
                    DESTREG * REG[x[2]] | 0x0008000b),
           'NOTf': (lambda x: COND[x[0]] | SRCREG * REG[x[1]] |
                    DESTREG * REG[x[2]] | 0x000bff03),
           'RORf': (lambda x: COND[x[0]] |
                    SMLCONST * evaluate('-('+x[1]+')', x[-1]) |
                    SRCREG * REG[x[2]] | DESTREG * REG[x[3]] | 0x0008000f),
           }

def longhex(s):
    r = hex(s)
    return '0' * (10 - len(r)) + r[2:]

def encode(instruction):
    addr = instruction[-1]
    l = instruction
    return longhex(addr//4) + ':' + longhex(instrfn[l[0]](l[1:]))

def loadfile(filename):
    try:
        with open(filename, 'r') as f:
            lines = f.readlines()
    except IOError:
        print('Failed to open file:', filename)
        return []
    return lines

def savefile(filename, contents):
    try:
        with open(filename, 'w') as f:
            for line in contents:
                f.write(line + '\n')
    except IOError:
        print('Failed to open file:', filename)
        return False
    return True

def pass1(lines):
    tokens = []
    for line in lines:
        tokens.extend(list(lex.lex(line)))
        if tokens[-1] == '':
            tokens.pop()
    labels = dict()
    address = 0
    instructions = [[]]
    for text, type_ in tokens:
        if type_ == 'opcode':
            instructions[-1].append(address - 4)
            address += 4
            instructions.append([text])
        elif type_ == 'label':
            labels[text[:-1]] = address
        else:
            instructions[-1].append(text)
    instructions[-1].append(address - 4)
    instructions.pop(0)
    for instr in instructions:
        if instr[1] not in COND and \
           instr[0] not in ['HALT', 'NOP', 'READ', 'WRITE']:
            instr.insert(1, '.T')
        if instr[0] == 'READ' and len(instr) < 5:
            instr.insert(2, '+0')
        if instr[0] == 'WRITE' and len(instr) < 5:
            instr.insert(3, '+0')
            
    return (instructions, labels)

def pass2(instructions):
    output = []
    for instr in instructions:
        output.append(encode(instr))
    return output
    
def evaluate(line, address, big=False):
    for label, addr in labels.items():
        line = line.replace(label, str(addr))
    line = line.replace('$', str(address))
    return eval(line) & 0x003fffff if big else eval(line) & 0x000003ff

def assemble(infile, outfile):
    global labels
    lines = loadfile(infile)
    instructions, labels = pass1(lines)
    output = pass2(instructions)
    savefile(outfile, output)


input('infile> ', infile)
input('outfile>', outfile)
assemble(infile, outfile)



