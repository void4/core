from lark import Lark, Tree, Transformer
from assembler import assemble
from vm import d, s, STACK, MEMORY
import inspect
grammar = '\n\nNAME: /[a-zA-Z_]\\w*/\nCOMMENT: /#[^\\n]*/\n_NEWLINE: ( /\\r?\\n[\\t ]*/ | COMMENT)+\n\n_DEDENT: "<DEDENT>"\n_INDENT: "<INDENT>"\n\n%import common.ESCAPED_STRING\nstring: ESCAPED_STRING\nnumber: DEC_NUMBER\nDEC_NUMBER: /0|[1-9]\\d*/i\n\n%ignore /[\\t \\f]+/  // Whitespace\n\nstart: (_NEWLINE | stmt)*\n\n\n?stmt: simple_stmt | compound_stmt\n?simple_stmt: (expr_stmt | flow_stmt | func_call | write_stmt | keyset_stmt | keydel_stmt | alloc_stmt | dealloc_stmt | dearea_stmt) _NEWLINE\n?expr_stmt: NAME "=" (test | expr) -> assign\n          | test\n\nwrite_stmt: "$write" "(" expr "," expr "," expr ")"\nalloc_stmt: "$alloc" "(" expr "," expr ")"\ndealloc_stmt: "$dealloc" "(" expr ")"\ndearea_stmt: "$dearea" "(" expr ")"\nkeyset_stmt: "$keyset" "(" expr "," expr ")"\nkeydel_stmt: "$keydel" "(" expr ")"\n?flow_stmt: pass_stmt | meta_stmt | yield_stmt | return_stmt | halt_stmt | area_stmt\npass_stmt: "pass"\nmeta_stmt: "$meta"\nyield_stmt: "yield" [expr | NAME]\nreturn_stmt: "return" [expr | NAME]\n?halt_stmt: "halt"\n?area_stmt: "$area"\n\n\n?test: or_test\n?or_test: and_test ("or" and_test)*\n?and_test: not_test ("and" not_test)*\n?not_test: "not" not_test -> not\n| comparison\n?comparison: expr _comp_op expr\n!_comp_op: "==" | "!="\n\n?expr: arith_expr\n?arith_expr: term (_add_op term)*\n?term: factor (_mul_op factor)*\n?factor: _factor_op factor | molecule\n?molecule: func_call\n         | molecule "[" [subscriptlist] "]" -> getitem\n         | atom\nfunc_call: NAME ["<" expr ["," expr] ">"] "(" [arglist] ")"\n?atom: "[" listmaker "]"\n     | primitive | NAME | number | ESCAPED_STRING | func_stat\n\nfunc_stat: NAME "." stat\nstat: "status" | "ip"\n\n?primitive: stacklen | memorylen | arealen_expr | read_expr | sha256_expr | keyget_expr | malloc_expr | arg_expr\narealen_expr: "$arealen" "(" expr ")"\nread_expr: "$read" "(" expr "," expr ")"\nsha256_expr: "$sha256" "(" expr ")"\nmalloc_expr: "$malloc" "(" expr ")"\nkeyget_expr: "$keyget" "(" expr ")"\narg_expr: "$arg" "(" expr ")"\nstacklen: "$stacklen"\nmemorylen: "$memorylen"\n\n!_factor_op: "+"|"-"|"~"\n!_add_op: "+"|"-"\n!_mul_op: "*"|"/"|"%"\n\nlistmaker: test ("," test)* [","]\n?subscriptlist: subscript ("," subscript)* [","]\nsubscript: test\narglist: (argument ",")* (argument [","])\nargument: expr\n\n?compound_stmt: if_stmt | while_stmt | funcdef\nif_stmt: "if" test ":" suite ["else" ":" suite]\nsuite: _NEWLINE _INDENT _NEWLINE? stmt+ _DEDENT _NEWLINE?\n\nwhile_stmt: "while" [test] ":" suite\n\nfuncdef: "def" NAME "(" [parameters] ")" ":" suite\nparameters: paramvalue ("," paramvalue)*\n?paramvalue: param\n?param: NAME\n'

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

    return lines


class Meta:

    def __init__(self):
        self.code = []

    def append(self, code):
        self.code += [code]

    def __add__(self, other):
        self.code += other.code
        return self

    def final(self):
        header = [         0, 0, 0, 0, 0]
        print(self.code)
        newcode = []
        for instruction in self.code:
            if isinstance(instruction, str):
                continue
            if isinstance(instruction, Assign):
                print('Assign', instruction.a, instruction.b)
            else:
                raise Exception('Unknown instruction type')

        memory = []
        code = assemble(newcode)
        stack = []
        mapp = []
        print(code)
        sharp = header + [code, stack, mapp, memory]
        return s(sharp)


class Assign:

    def __init__(self, a, b):
        self.a = a
        self.b = b


class Generator:

    def __init__(self):
        self.counter = 0

    def next(self):
        self.counter += 1
        return counter

    def label(self):
        return 'label:%i' % self.next()

    def name(self):
        return 'name:%i' % self.next()


def parse(code, generator=None):
    if generator is None:
        generator = Generator()

    def varint(node):
        if isinstance(node, list) or isinstance(node, Meta):
            return node
        if isinstance(node, str):
            return [['__PUSH', node.value]]
        if node.data == 'number':
            if node.children[0].type == 'DEC_NUMBER':
                return [    'PUSH %i' % int(node.children[0].value)]
            raise Exception('Fail')

    class MyTransformer(Transformer):

        def start(self, node):
            intro = Meta()
            m = sum(node, intro)
            return m.final()

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

        def keydel_stmt(self, node):
            out = Meta()
            out += varint(node[0])
            out.append('KEYDEL')
            return out

        def keyget_expr(self, node):
            out = Meta()
            out += varint(node[0])
            out.append('KEYGET')
            return out

        def sha256_expr(self, node):
            out = varint(node[0])
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

    l = Lark(grammar, debug=True)
    prepped = prep(code)
    parsed = l.parse(prepped)
    obj = MyTransformer().transform(parsed)
    return obj
