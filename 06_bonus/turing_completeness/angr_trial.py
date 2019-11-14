#!/usr/bin/env python
from __future__ import print_function
import angr, claripy
import ctypes
from ctypes.util import find_library

project = angr.Project("./patch.elf", load_options={'auto_load_libs': False})

initial_state = project.factory.entry_state()

#initial_state = project.factory.blank_state(addr=0x08049F71)

libc = ctypes.CDLL(find_library('c'))

class ReplacementSrand(angr.SimProcedure):
  def run(self, seed):
    libc.srand(4919)

class ReplacementRand(angr.SimProcedure):
  def run(self, p1, p2, p3, p4):
    rv = libc.rand()
    print("Rand: %x" % rv)
    return rv

class ReplacementScanf(angr.SimProcedure):
  def run(self, format_string, param0, param1, param2):
    scanf0 = claripy.BVS('scanf0', 32)
    scanf1 = claripy.BVS('scanf1', 32)
    scanf2 = claripy.BVS('scanf2', 32)

    scanf0_address = param0
    self.state.memory.store(scanf0_address, scanf0, endness=project.arch.memory_endness)
    scanf1_address = param1
    self.state.memory.store(scanf1_address, scanf1, endness=project.arch.memory_endness)
    scanf2_address = param2
    self.state.memory.store(scanf2_address, scanf2, endness=project.arch.memory_endness)

    print(param0)
    print(param1)
    print(param2)

    self.state.globals['solutions'] = (scanf0, scanf1, scanf2)

project.hook_symbol('__isoc99_scanf', ReplacementScanf())
project.hook_symbol('srand', ReplacementSrand())
project.hook_symbol('rand', ReplacementRand())

num1 = claripy.BVS('num1', 8*4)
num2 = claripy.BVS('num2', 8*4)
num3 = claripy.BVS('num3', 8*4)

#initial_state.memory.store(0x86092c4, num1)
#initial_state.memory.store(0x86092c0, num2)
#initial_state.memory.store(0x86092bc, num3)

simulation = project.factory.simulation_manager(initial_state)

#simulation.explore(find=0x08055FA8, avoid=[0x804ac7f, 0x8059927])
simulation.explore(find=0x08055FB5, avoid=[0x804ac7f, 0x8059927])

print(simulation)

if simulation.found:
  solution_state = simulation.found[0]
  stored_solutions = solution_state.globals['solutions']
  solution = ' '.join(map(str, map(solution_state.se.eval, stored_solutions)))
  print(solution)
  # num1_eval = hex(solution_state.se.eval(num1))[2:]
  # num2_eval = hex(solution_state.se.eval(num2))[2:]
  # num3_eval = hex(solution_state.se.eval(num3))[2:]
  # print(num1_eval)
  # print(num2_eval)
  # print(num3_eval)
else:
  print(simulation.errored)
  raise Exception('Could not find the solution')

