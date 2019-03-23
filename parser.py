from lark.lark import Lark, Tree
from lark.visitors import Transformer
from assembler import assemble
from vm import d, s, STACK, MEMORY
import inspect
grammar = r"""


NAME: /[a-zA-Z_]\w*/
COMMENT: /#[^\n]*/
_NEWLINE: ( /\r?\n[\t ]*/ | COMMENT)+

_DEDENT: "<DEDENT>"
_INDENT: "<INDENT>"

%import common.ESCAPED_STRING
string: ESCAPED_STRING
number: DEC_NUMBER
DEC_NUMBER: /0|[1-9]\d*/i

%ignore /[\t \f]+/  // Whitespace

start: (_NEWLINE | stmt)*


?stmt: simple_stmt | compound_stmt
?simple_stmt: (flow_stmt | func_call | write_stmt | keyset_stmt | keydel_stmt | alloc_stmt | dealloc_stmt | dearea_stmt | macro_stmt | expand_stmt | expr_stmt) _NEWLINE
?expr_stmt: NAME "=" (test | expr) -> assign
          | test

write_stmt: "$write" "(" expr "," expr "," expr ")"
alloc_stmt: "$alloc" "(" expr "," expr ")"
dealloc_stmt: "$dealloc" "(" expr ")"
dearea_stmt: "$dearea" "(" expr ")"
keyset_stmt: "$keyset" "(" expr "," expr ")"
keydel_stmt: "$keydel" "(" expr ")"
?flow_stmt: pass_stmt | meta_stmt | yield_stmt | return_stmt | halt_stmt | area_stmt
pass_stmt: "pass"
meta_stmt: "$meta"
yield_stmt: "yield" [expr | NAME]
return_stmt: "return" [expr | NAME]
?halt_stmt: "halt"
?area_stmt: "$area"
macro_stmt: "macro" NAME ":" suite
expand_stmt: "expand" NAME


?test: or_test
?or_test: and_test ("or" and_test)*
?and_test: not_test ("and" not_test)*
?not_test: "not" not_test -> not
| comparison
?comparison: expr _comp_op expr
!_comp_op: "==" | "!="

?expr: arith_expr
?arith_expr: term (_add_op term)*
?term: factor (_mul_op factor)*
?factor: _factor_op factor | molecule
?molecule: func_call
         | molecule "[" [subscriptlist] "]" -> getitem
         | atom
func_call: NAME ["<" expr ["," expr] ">"] "(" [arglist] ")"
?atom: "[" listmaker "]"
     | primitive | NAME | number | ESCAPED_STRING | func_stat

!_factor_op: "+"|"-"|"~"
!_add_op: "+"|"-"
!_mul_op: "*"|"/"|"%"

func_stat: NAME "." stat
stat: "status" | "ip"

?primitive: stacklen | memorylen | arealen_expr | read_expr | sha256_expr | keyget_expr | keyhas_expr | malloc_expr | arg_expr
arealen_expr: "$arealen" "(" expr ")"
read_expr: "$read" "(" expr "," expr ")"
sha256_expr: "$sha256" "(" expr ")"
malloc_expr: "$malloc" "(" expr ")"
keyhas_expr: "$keyhas" "(" expr ")"
keyget_expr: "$keyget" "(" expr ")"
arg_expr: "$arg" "(" expr ")"
stacklen: "$stacklen"
memorylen: "$memorylen"



listmaker: test ("," test)* [","]
?subscriptlist: subscript ("," subscript)* [","]
subscript: test
arglist: (argument ",")* (argument [","])
argument: expr

?compound_stmt: if_stmt | while_stmt | funcdef | struct
if_stmt: "if" test ":" suite ["else" ":" suite]
suite: _NEWLINE _INDENT _NEWLINE? stmt+ _DEDENT _NEWLINE?

while_stmt: "while" [test] ":" suite

funcdef: "def" NAME "(" [parameters] ")" ":" suite
parameters: paramvalue ("," paramvalue)*
?paramvalue: param
?param: NAME

kv: NAME NAME _NEWLINE
kvsuite: _NEWLINE _INDENT _NEWLINE? kv+ _DEDENT _NEWLINE?
struct: "struct" NAME ":" kvsuite


"""

def isint(v):
    try:
        int(v)
        return True
    except:
        return False


def indent(line):
    return (len(line) - len(line.lstrip(' '))) // 4


def prep(code):
    code = code.split('\n')
    code.append('\n')
    current = 0
    lines = ''
    for line in code:
        ind = indent(line)
        if ind > current:
            prefix = '<INDENT>' * (ind - current)
        else:
            if ind < current:
                prefix = '<DEDENT>' * (current - ind)
            else:
                prefix = ''
        current = ind
        lines += prefix + line.lstrip() + '\n'

    return lines.replace("<DEDENT>\n<INDENT>", "")


class Allocator:
    def __init__(self):
        self.mem = []
        self.var = {}
    def reserve(self, obj=None):
        memlen = len(self.mem)
        if obj is None:
            self.mem += [1]
        else:
            self.mem += obj
        return memlen
    def getOrReserveVariable(self, name):
        if not name in self.var:
            self.var[name] = self.reserve()
        return self.var[name]
    def getVariable(self, name):
        return self.var[name]

class Node:
    pass

class ComplexValue(Node):
    def __init__(self, value):
        self.value = value

class Struct(Node):
    def __init__(self, name, kv):
        self.name = name
        self.kv = kv

class Function(Node):
    def __init__(self, name, args, obj):
        self.name = name
        self.args = args
        self.obj = obj

class FunctionCall(Node):
    def __init__(self, name, args):
        self.name = name
        self.args = args

class Assign(Node):
    def __init__(self, a, b):
        self.a = a
        self.b = b

class Expand(Node):
    def __init__(self, name):
        self.name = name

def word_from_name(name):
    return int.from_bytes(name.encode("ascii"), byteorder="big")

def varint(node):
    if isinstance(node, list) or isinstance(node, Meta):
        return node
    if isinstance(node, str):
        return ComplexValue(node.value)
    if node.data == 'number':
        if node.children[0].type == 'DEC_NUMBER':
            return ['PUSH %i' % int(node.children[0].value)]
        raise Exception('Fail')

class Meta:

    def __init__(self):
        self.code = []
        self.macros = {}

    def append(self, code):
        #self.code += [code]
        self.__add__(code)

    def __add__(self, other):
        if isinstance(other, Meta):
            self.code += other.code
            self.macros.update(other.macros)
        elif isinstance(other, list):
            self.code += other
        elif isinstance(other, Node):
            self.code += [other]
        elif isinstance(other, str):
            self.code.append(other)
        else:
            raise Exception("Unknown combinator %s", other)
        return self

    def final(self):
        header = [0, 0, 0, 0, 0]
        #print(self.code)
        memory = []
        mapp = []
        allocator = Allocator()
        typedefs = {}

        offset = 0
        #for offset, instruction in enumerate(self.code):
        while offset < len(self.code):
            #print(self.code)
            instr = self.code[offset]
            print(offset, instr)

            updateoffset = True

            def insertList(lst):
                nonlocal updateoffset
                updateoffset = False
                self.code = self.code[:offset]+lst+self.code[offset+1:]

            insertindex = offset
            def insert(node):
                nonlocal updateoffset
                updateoffset = False
                nonlocal insertindex
                if insertindex == offset:
                    self.code[insertindex] = node
                else:
                    self.code.insert(insertindex, node)
                insertindex += 1

            def ignore():
                nonlocal updateoffset
                updateoffset = False
                self.code = self.code[:offset] + self.code[offset+1:]

            if isinstance(instr, str):
                pass
            elif isinstance(instr, list):
                insertList(instr)
            elif isinstance(instr, Meta):
                insertList(instr.code)
            elif isinstance(instr, Struct):
                typedefs[instr.name] = instr.kv
                ignore()
            elif isinstance(instr, Assign):
                #print("assign")
                # Can optimize fixed assignments
                insert("PUSH 0")
                pointer = allocator.getOrReserveVariable(instr.a)
                insert("PUSH %i" % pointer)
                if isinstance(instr.b, str):
                    # good enough for now, have to store unicode code points later
                    objpointer = allocator.reserve(list(instr.b[1:-1].encode("utf8"))+[0])
                    insert("PUSH %i" % objpointer)
                else:
                    print(instr.b)
                    insert(varint(instr.b))
                insert("WRITE")

            elif isinstance(instr, Expand):
                if instr.name in self.macros:
                    print(self.macros[instr.name].code)
                    insertList(self.macros[instr.name].code)
                else:
                    raise Exception("Invalid macro name %s" % instr.name)

            elif isinstance(instr, Function):
                memory.append(instr.obj)
                mapp.append([word_from_name(instr.name), len(memory)])

            elif isinstance(instr, FunctionCall):
                name = word_from_name(instr.name)
                if name in [kv[0] for kv in mapp]:
                    index = [kv for kv in mapp if kv[0]==name][0][1]
                    insertList(self.while_stmt([
                        self.comparison(["PUSH %i" % index, "PUSH 0", "READ"],
                        ["PUSH %i" % index, "RUN"])]))
                else:
                    raise Exception("Unknown function name %s" % instr.name)

            elif isinstance(instr, ComplexValue):
                insertList(["PUSH 0", "PUSH %i" % allocator.getVariable(instr.value), "READ"])
            else:
                print(instr)
                raise Exception('Unknown instr type')

            if updateoffset:
                offset += 1

        memory = [allocator.mem] + memory
        print("\n".join(self.code))
        print(typedefs)
        code = assemble(self.code)
        stack = []

        #print(code)
        sharp = header + [code, stack, mapp, memory]
        flat = s(sharp)
        #print(flat)
        return flat




class Generator:

    def __init__(self):
        self.counter = 0

    def next(self):
        self.counter += 1
        return self.counter

    def label(self):
        return 'label:%i' % self.next()

    def name(self):
        return 'name:%i' % self.next()


def parse(code, generator=None):
    if generator is None:
        generator = Generator()

    class MyTransformer(Transformer):

        def start(self, node):
            intro = Meta()
            m = sum(node, intro)
            return m.final()

        def struct(self, node):
            out = Meta()
            kv = []
            for child in node[1].children:
                kv.append([child.children[0].value, child.children[1].value])
            out.append(Struct(node[0].value, kv))
            return out

        def funcdef(self, node):
            print("funcdef")
            fun = Meta()
            #add arg prep here
            fun += node[-1]

            print(node)
            out = Meta()
            out.append(Function(node[0].value, node[1], fun.final()))

            return out

        def func_call(self, node):
            out = Meta()
            out.append(FunctionCall(node[0], node[1:]))
            return out

        def return_stmt(self, node):
            out = Meta()
            out.append("RETURN")
            return out

        def meta_stmt(self, node):
            out = Meta()
            return out

        def malloc_expr(self, node):
            out = Meta()
            out.append('PUSH 0')
            out.append('AREALEN')
            out.append('PUSH 0')
            out += varint(node[0])
            out.append('ALLOC')
            return out

        def dearea_stmt(self, node):
            out = Meta()
            out += varint(node[0])
            out.append('DEAREA')
            return out

        def alloc_stmt(self, node):
            out = Meta()
            out += varint(node[0])
            out += varint(node[1])
            out.append('ALLOC')
            return out

        def dealloc_stmt(self, node):
            out = Meta()
            out += varint(node[0])
            out.append('DEALLOC')
            return out

        def macro_stmt(self, node):
            out = Meta()
            out.macros[node[0].value] = node[1]
            return out

        def expand_stmt(self, node):
            out = Meta()
            out.append(Expand(node[0]))
            return out

        def suite(self, node):
            return sum(node, Meta())

        def if_stmt(self, node):
            out = Meta()
            out += node[0]
            end_label = generator.label()
            if len(node) == 3:
                else_label = generator.label()
                out.append('PUSH %s' % else_label)
            else:
                out.append('PUSH %s' % end_label)
            out.append('JZ')
            out += node[1]
            if len(node) == 3:
                out.append('PUSH %s' % end_label)
                out.append('JUMP')
                out.append(else_label + ':')
                out += node[2]
            out.append(end_label + ':')
            return out

        def stacklen(self, node):
            return ['STACKLEN']

        def memorylen(self, node):
            return ['MEMORYLEN']

        def while_stmt(self, node):
            out = Meta()
            start_label = generator.label()
            end_label = generator.label()
            out.append(start_label + ':')
            if len(node) == 2:
                out += node[0]
                out.append('NOT')
                out.append('PUSH %s' % end_label)
                out.append('JZ')
                out += node[1]
            else:
                out += node[0]
            out.append('PUSH %s' % start_label)
            out.append('JUMP')
            out.append(end_label + ':')
            return out

        def comparison(self, node):
            out = Meta()
            out += varint(node[0])
            out += varint(node[2])
            out.append('SUB')
            if node[1].value == '!=':
                out.append('NOT')
            return out

        def term(self, node):
            out = Meta()
            out += varint(node[0])
            out += varint(node[2])
            out.append('%s' % {'*':'MUL',  '/':'DIV',  '%':'MOD'}[node[1].value])
            return out

        def arith_expr(self, node):
            out = Meta()
            out += varint(node[0])
            for i in range((len(node) - 1) // 2):
                out += varint(node[1 + i * 2 + 1])
                out.append('%s' % {'+':'ADD',  '-':'SUB',  '~':'NOT'}[node[1 + i * 2].value])

            return out

        def arealen_expr(self, node):
            out = varint(node[0])
            out.append('AREALEN')
            return out

        def read_expr(self, node):
            out = Meta()
            out += varint(node[0])
            out += varint(node[1])
            out.append('READ')
            return out

        def write_stmt(self, node):
            out = Meta()
            out += varint(node[0])
            out += varint(node[1])
            out += varint(node[2])
            out.append('WRITE')
            return out

        def keyset_stmt(self, node):
            out = Meta()
            out += varint(node[0])
            out += varint(node[1])
            out.append('KEYSET')
            return out

        def keyhas_expr(self, node):
            out = Meta()
            out += varint(node[0])
            out.append('KEYHAS')
            return out

        def keyget_expr(self, node):
            out = Meta()
            out += varint(node[0])
            out.append('KEYGET')
            return out

        def keydel_stmt(self, node):
            out = Meta()
            out += varint(node[0])
            out.append('KEYDEL')
            return out

        def sha256_expr(self, node):
            out = Meta()
            out.append(varint(node[0]))
            out.append('SHA256')
            return out

        def pass_stmt(self, node):
            return []

        def halt_stmt(self, node):
            return ['HALT']

        def area_stmt(self, node):
            return ['AREA']

        def assign(self, node):
            m = Meta()
            m.append(Assign(node[0], node[1]))
            return m

        def yield_stmt(self, node):
            m = Meta()
            #print("RET", node)

            m += varint(node[0])

            m.append("MEMORYLEN")
            m.append("PUSH 1")
            m.append("SUB")

            m.append("DUP")
            m.append("DUP")

            m.append("DEAREA")
            m.append("AREA")

            m.append("PUSH 1")
            m.append("ALLOC")
            m.append("FLIP")
            m.append("PUSH 0")
            m.append("FLIP")

            m.append("WRITE")
            m.append("YIELD")

            return m

    l = Lark(grammar, debug=True)
    prepped = prep(code)
    print(prepped)
    parsed = l.parse(prepped)
    obj = MyTransformer().transform(parsed)
    return obj

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("missing <file>")
        exit(1)
    with open(sys.argv[1], "r") as f:
        print(parse(f.read()))
