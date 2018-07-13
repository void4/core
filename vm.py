
BYTESIZE = 32
WORDSIZE = 8*BYTESIZE
WMAX = 2**WORDSIZE
WMASK = WMAX-1

from crypto import wrapint, hashit, tob, fromb, genkey, verify

STATUS, REC, GAS, MEM, IP, CODE, STACK, MAP, MEMORY = range(9)
F_STATUS, F_REC, F_GAS, F_MEM, F_IP, F_LENCODE, F_LENSTACK, F_LENMAP, F_LENMEMORY, F_CODE, F_STACK, F_MAP, F_MEMORY = range(13)

NORMAL, FROZEN, VOLHALT, VOLRETURN, OOG, OOC, OOS, OOM, OOB, UOC, RECURSE = range(11)
STATI = ["NORMAL", "FROZEN", "VOLHALT", "VOLRETURN", "OUTOFGAS", "OUTOFCODE", "OUTOFSTACK", "OUTOFMEMORY", "OUTOFBOUNDS", "UNKNOWNCODE", "RUN"]

HALT, RETURN, YIELD, RUN, JUMP, JZ, PUSH, POP, DUP, FLIP, KEYSET, KEYHAS, KEYGET, KEYDEL, STACKLEN, MEMORYLEN, AREALEN, READ, WRITE, AREA, DEAREA, ALLOC, DEALLOC, ADD, SUB, NOT, MUL, DIV, MOD, SHA256, ECVERIFY = range(31)

REQS = [
    # Name, Instruction length, Required Stack Size, Stack effect, Gas cost
    ["HALT",1,0,0,1],
    ["RETURN",1,0,0,1],
    ["YIELD",1,0,0,1],

    ["RUN",1,3,-3,0],

    ["JUMP",1,1,-1,1],
    ["JZ",1,2,-2,1],

    ["PUSH",2,0,1,2],
    ["POP",1,0,0,2],
    ["DUP",1,0,1,4],
    ["FLIP",1,2,0,4],

    ["KEYSET",1,2,-2,10],
    ["KEYHAS",1,1,0,4],
    ["KEYGET",1,1,0,6],
    ["KEYDEL",1,1,-1,4],

    ["STACKLEN",1,0,1,2],
    ["MEMORYLEN",1,0,1,2],
    ["AREALEN",1,1,0,2],

    ["READ",1,2,-1,2],
    ["WRITE",1,3,-3,2],

    ["AREA",1,0,1,10],
    ["DEAREA",1,1,-1,10],#!use after free!
    ["ALLOC",1,2,-2,10],
    ["DEALLOC",1,2,-2,10],

    ["ADD",1,2,-1,6],
    ["SUB",1,2,-1,6],
    ["NOT",1,1,0,4],
    ["MUL",1,2,-1,8],
    ["DIV",1,2,-1,10],
    ["MOD",1,2,-1,10],

    ["SHA256",1,1,0,100],
]

def s(state):
    """Flattens and serializes the nested state structure"""
    flat = state[:CODE]
    flat += [len(state[CODE])]
    flat += [len(state[STACK])]
    flat += [len(state[MAP])]
    flat += [len(state[MEMORY])]
    flat += state[CODE]
    flat += state[STACK]
    for i in range(0, len(state[MAP]), 2):
        k = state[MAP][i]
        v = state[MAP][i+1]
        flat += [k, v]
    for area in state[MEMORY]:
        flat += [len(area)]
        flat += area
    return flat

def d(state):
    """Deserializes and restores the runtime state structure from the flat version"""
    sharp = state[:F_LENCODE]
    lencode = state[F_LENCODE]
    lenstack = state[F_LENSTACK]
    lenmap = state[F_LENMAP]
    lenmemory = state[F_LENMEMORY]

    sharp.append(state[F_LENMEMORY+1:F_LENMEMORY+1+lencode])
    sharp.append(state[F_LENMEMORY+1+lencode:F_LENMEMORY+1+lencode+lenstack])
    hmap = state[F_LENMEMORY+1+lencode+lenstack:F_LENMEMORY+1+lencode+lenstack+lenmap]
    #hmap = list(zip(hmap[::2], hmap[1::2]))
    sharp.append(hmap)

    sharp.append([])
    #print(lencode, lenstack, lenmemory)
    index = F_LENMEMORY+1+lencode+lenstack+lenmap
    for area in range(lenmemory):
        lenarea = state[index]
        sharp[-1].append(state[index+1:index+1+lenarea])
        index = index + 1 + lenarea
    return sharp

from utils import odict

def annotated(d):
    return odict[
        "header": d[:LENMEMORY+1],
        "code": d[LENMEMORY+1],
        "stack": d[LENMEMORY+2],
        "map": d[LENMEMORY+3],
        "memory": d[LENMEMORY+4],
    ]

def step(state):
    """Stateless step function. Maps states to states."""

    def next(jump=None):
        """Pops arguments. Sets the instruction pointer"""
        nonlocal state

        if reqs[3] < 0:
            state[STACK] = state[STACK][:reqs[3]]
            state[MEM] += abs(reqs[3])

        if jump is None:
            state[IP] += reqs[1]
        else:
            state[IP] = jump

    # The following functions should have no or one side effect. If one, either
    # 1. Set a STATE flag and return False, True otherwise
    # 2. Have a side effect and be called _last_
    # This is to ensure failing instructions can be continued normally


    def top():
        """Returns the top of the stack"""
        if len(state[STACK]) == 0:
            return None
        else:
            return state[STACK][-1]

    def push(value):
        """Pushes a value onto the stack"""
        if state[MEM] == 0:
            state[STATUS] = OOM
            return False
        else:
            state[STACK].append(value)
            state[MEM] -= 1
            return True

    def validarea(area):
        """Checks if this memory area index exists"""
        nonlocal state
        if area >= len(state[MEMORY]):
            state[STATUS] = OOB
            return False
        else:
            return True

    def validmemory(area, addr):
        """Checks if the memory address and area exist"""
        nonlocal state
        if not validarea(area) or addr >= len(state[MEMORY][area]):
            state[STATUS] = OOB
            return False
        else:
            return True

    def hasmem(mem):
        """Checks if state has enough mem, sets flag otherwise"""
        nonlocal state
        if mem <= state[MEM]:
            return True
        else:
            state[STATUS] = OOM
            return False

    state = d(state)
    # State, ADDR
    states = [[state, None]]

    while True:
        state = states[-1][0]

        # Check if state has enough gas
        if state[GAS] == 0:
            state[STATUS] = OOG
            break

        # Check if current instruction pointer is within code bounds
        ip = state[IP]
        if ip >= len(state[CODE]):
            state[STATUS] = OOC
            break

        instr = state[CODE][ip]
        reqs = REQS[instr]

        # Check if extended instructions are within code bounds
        if ip + reqs[1] - 1 >= len(state[CODE]):
            state[STATUS] = OOC
            break

        # Check whether stack has sufficient items for current instruction
        if len(state[STACK]) < reqs[2]:
            state[STATUS] = OOS
            break

        # Check resources recursively
        def checkResources():
            nonlocal states
            error = True
            for ps in states:
                # Check if current instruction has enough memory for stack effects
                p = ps[0]

                # Compare memory use (combined, not separately)
                # move this into reqs!
                def getMemoryUse(instr):
                    # XXX maximum working size or end-start?
                    if instr == ALLOC:
                        return p[STACK][-1]
                    elif instr == DEALLOC:
                        return -p[STACK][-1]
                    else:
                        return 0
                if instr != RUN:
                    gascost = reqs[4]
                    p[GAS] -= gascost # RUN RUN RUN?#only subtract if not OOM down there!
                    totalmemoryuse = len(s(state)) * gascost#reqs[3] + getMemoryUse(instr)
                else:
                    totalmemoryuse = 0#not correct, run pops from stack, but not always
                if p[MEM] < totalmemoryuse:
                    p[STATUS] = OOM
                    break
                p[MEM] -= totalmemoryuse
            else:
                error = False

            return error

        if instr == RUN:
            area, gas, mem = state[STACK][-3:]
            if validarea(area) and len(state[MEMORY][area]) > 4:#HEADERLEN
                child = state[MEMORY][area]

                if state[REC] == 0:
                    child[STATUS] = NORMAL
                    child[GAS] = gas
                    child[MEM] = mem
                    #state[STATUS] = RECURSE
                    state[REC] = area + 1


                if state[REC] > 0 and child[STATUS] == NORMAL:

                    #print(">>>")
                    #state[MEMORY][area] = step(state[MEMORY][area])
                    #print(state[MEMORY], area)
                    states.append([d(state[MEMORY][area]), area])
                    #print("<<<")
                else:
                    #child[STATUS] = FROZEN
                    #may not be required
                    if checkResources():
                        break
                    state[REC] = 0
                    next()
            else:
                #checkresources here?
                next()
        else:
            #print("".join(["<-|%s¦%i¦%i¦%s|" % (STATI[states[i][0][STATUS]], states[i][0][GAS], states[i][0][MEM], REQS[states[i][0][CODE][states[i][0][IP]]][0]) for i in range(len(states))]))
            #CSV
            print("".join(["%i;%i" % (states[i][0][GAS], states[i][0][MEM]) for i in range(len(states))]))
            if checkResources():
                break

            if instr == HALT:
                state[STATUS] = VOLHALT
                next()
            elif instr == RETURN:
                state[STATUS] = VOLRETURN
                state[IP] = 0
            elif instr == YIELD:
                state[STATUS] = VOLRETURN
                next()
            elif instr == JUMP:
                next(top())
            elif instr == JZ:
                if state[STACK][-2] == 0:
                    next(top())
                else:
                    next()
            elif instr == PUSH:
                state[STACK].append(state[CODE][ip+1])
                next()
            elif instr == POP:
                if len(state[STACK]) > 0:
                    state[STACK] = state[STACK][:-1]
                    state[MEM] += 1
                    next()
            elif instr == DUP:
                state[STACK].append(top())
                next()
            elif instr == FLIP:
                state[STACK][-2:] = state[STACK][:-3:-1]
                next()
            elif instr == KEYSET:

                if hasmem(2):#or only exit if memory is actually needed?
                    kv = [state[STACK][-2], state[STACK][-1]]
                    for i in range(0, len(state[MAP]), 2):
                        if state[MAP][i] == kv[0]:
                            state[MAP][i+1] = kv[1]
                            break
                    else:
                        state[MAP] += kv
                        state[MEM] -= 2
                    next()
            elif instr == KEYHAS:
                for i in range(0, len(state[MAP]), 2):
                    if state[MAP][i] == state[STACK][-1]:
                        state[STACK][-1] = 1
                        break
                else:
                    state[STACK][-1] = 0
                next()
            elif instr == KEYGET:
                for i in range(0, len(state[MAP]), 2):
                    if state[MAP][i] == state[STACK][-1]:
                        state[STACK][-1] = state[MAP][i+1]
                        break
                else:
                    state[STACK].pop(-1)
                    state[MEM] += 1
                next()
            elif instr == KEYDEL:
                for i in range(0, len(state[MAP]), 2):
                    if state[MAP][i] == state[STACK][-1]:
                        state[MAP].pop(i)
                        state[MAP].pop(i)
                        state[MEM] += 2
                        break
                next()
            elif instr == STACKLEN:
                if push(len(state[STACK])):
                    next()
            elif instr == MEMORYLEN:
                if push(len(state[MEMORY])):
                    next()
            elif instr == AREALEN:
                area = state[STACK][-1]
                if validarea(area):
                    state[STACK][-1] = len(state[MEMORY][area])
                    next()
            elif instr == READ:
                area, addr = state[STACK][-2:]
                if validmemory(area, addr):
                    state[STACK][-2] = state[MEMORY][area][addr]
                    next()
            elif instr == WRITE:
                area, addr, value = state[STACK][-3:]
                if validmemory(area, addr):
                    state[MEMORY][area][addr] = value
                    next()
            elif instr == AREA:
                # This should cost 1 mem
                if hasmem(1):
                    state[MEMORY].append([])
                    state[MEM] -= 1
                    next()
            elif instr == DEAREA:
                state[MEM] += len(state[MEMORY][top()])
                state[MEMORY].pop(top())
                next()
            elif instr == ALLOC:
                area, size = state[STACK][-2:]
                # Technically, -2
                if hasmem(size):
                    if validarea(area):
                        state[MEM] -= size
                        state[MEMORY][area] += [0] * size
                        next()
            elif instr == DEALLOC:
                area, size = state[STACK][-2:]
                if validarea(area):
                    if len(state[MEMORY][area]) >= size:
                        state[MEM] += size
                        state[MEMORY][area] = state[MEMORY][area][:-size]
                        next()
                    else:
                        state[STATUS] = OOB
            elif instr == ADD:
                op1, op2 = state[STACK][-2:]
                state[STACK][-2] = op1 + op2
                next()
            elif instr == SUB:
                op1, op2 = state[STACK][-2:]
                state[STACK][-2] = (op1 - op2) % WMAX
                next()
            elif instr == NOT:
                state[STACK][-1] = ~state[STACK][-1] & WMASK
                next()
            elif instr == MUL:
                op1, op2 = state[STACK][-2:]
                state[STACK][-2] = (op1 * op2) % WMAX
                next()
            elif instr == DIV:
                op1, op2 = state[STACK][-2:]
                state[STACK][-2] = op1 // op2
                next()
            elif instr == MOD:
                op1, op2 = state[STACK][-2:]
                state[STACK][-2] = op1 % op2
                next()
            elif instr == SHA256:
                state[STACK][-1] = wrapint(state[STACK][-1], hashit)
                next()
            elif instr == ECVERIFY:
                #if verify(state[STACK][-1], ):
                pass
            else:
                state[STATUS] = UOC

            break

    for i, state in enumerate(states[::-1]):
        if i!=0:
            state[0][MEMORY][states[-1][1]] = states[-i][0]
        states[-i-1][0] = s(state[0])
    return states[0][0]


from time import sleep

import tkinter as tk
from PIL import ImageTk, Image

"""
root = tk.Tk()
img = ImageTk.PhotoImage(Image.open("test.png"))
panel = tk.Label(root, image=img)
panel.pack(side="bottom", fill="both", expand="yes")
"""

def show(state):
    SIZE = 32
    SCALE = 8
    img = Image.new("RGB", (SIZE,SIZE))
    for i,v in enumerate(state):
        img.putpixel((int(i%SIZE), int(i/SIZE)), int(v%256)<<20)
    img = img.resize((SIZE*SCALE, SIZE*SCALE))

    img2 = ImageTk.PhotoImage(img)
    panel.configure(image=img2)
    panel.image = img2
    root.update()

numlines = 4
stats = [[] for i in range(numlines)]

import numpy as np
import matplotlib.pyplot as plt

fig, ax1 = plt.subplots()
ax1.set_xlabel('step (c)')
axes = [ax1]
for i in range(numlines-2):
    axes.append(axes[-1].twinx())

labels = ["memsec", "gas", "statesize (words)"]
colors = ["tab:red", "tab:blue", "tab:grey"]

for i,ax in enumerate(axes):
    ax.plot([], [], color=colors[i])
    ax.set_ylabel(labels[i], color=colors[i])

plt.pause(0.0001)

def run(state, gas=100, mem=100, debug=False):
    state[STATUS] = NORMAL
    state[GAS] = gas
    state[MEM] = mem

    #for i,ax in enumerate(axes):
    #    ax.set_ylim([0,0,0][i], [gas*mem,gas,mem][i])

    count = 0
    while True:
        #sleep(0.1)
        #show(state)
        #import timeit
        #print(state)
        #t = timeit.timeit("step([0, 0, 1000, 1000, 0, 98, 0, 0, 3, 6, 1, 15, 8, 6, 1, 9, 6, 1, 6, 2, 20, 6, 1, 6, 8, 6, 1, 6, 8, 16, 6, 1, 22, 17, 6, 1, 17, 8, 6, 1, 22, 6, 1, 9, 14, 6, 1, 23, 6, 0, 16, 17, 7, 6, 1, 6, 50, 6, 50, 3, 6, 1, 6, 1, 15, 6, 1, 23, 16, 6, 1, 6, 2, 21, 6, 1, 6, 8, 6, 1, 6, 8, 16, 6, 1, 23, 17, 14, 6, 1, 23, 8, 8, 19, 18, 6, 1, 20, 9, 6, 0, 9, 17, 2, 6, 0, 4, 0, 37, 1, 0, 0, 0, 0, 27, 0, 0, 1, 14, 6, 1, 23, 6, 0, 16, 6, 1, 22, 14, 6, 1, 23, 8, 8, 19, 18, 6, 1, 20, 9, 6, 0, 9, 17, 1, 0, 1, 1])", "from vm import step", number=100000)
        #print(t)
        #print(d(state)[MEMORY])
        stats[0].append(count)
        stats[1].append(state[MEM])
        stats[2].append(state[GAS])
        stats[3].append(len(state))
        for i in range(1,4):
            ax = axes[i-1]
            ax.lines[0].set_xdata(stats[0])#stats[2]
            ax.lines[0].set_ydata(stats[i])

            ax.relim()
            ax.autoscale_view()
        #plt.pause(0.0000001)
        fig.canvas.draw()
        if state[STATUS] not in [NORMAL, RECURSE]:
            if debug:
                dstate = d(state)
                print(STATI[dstate[STATUS]], dstate[GAS], dstate[MEM])
                print(dstate)
            break
        state = step(state)
        if debug:
            out = d(state)
            #print(out[STACK], out[MEMORY])
            #sleep(0.1)
        count += 1
    return state
