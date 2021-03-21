import angr
import claripy


target = angr.Project('icancount', auto_load_libs=False)

# where we start the exploration
check_flag = target.loader.find_symbol('check_flag').rebased_addr
entry_state = target.factory.blank_state(addr=check_flag)

# input and constraints on it
inp = claripy.BVS('inp', 0x13*8)
for i in inp.chop(8):
    entry_state.solver.add(entry_state.solver.And(i >= '0', i <= '9'))

# correspondance between the inp above and the memory region
flag_buf = target.loader.find_symbol('flag_buf').rebased_addr
entry_state.memory.store(flag_buf, inp)

simulation = target.factory.simulation_manager(entry_state)

# when we don't have the right input
failed_adr = 0xfae + target.loader.main_object.min_addr
# presumably displays the flag
desired_adr = 0xf9a + target.loader.main_object.min_addr

simulation.use_technique(angr.exploration_techniques.Explorer(
    find=desired_adr, avoid=failed_adr))

simulation.run()

flag_int = simulation.found[0].solver.eval(inp)

flag = ""
for i in range(19):
    flag = chr(flag_int & 0xff) + flag
    flag_int = flag_int >> 8

print(f'flag: PCTF{{{flag}}}')
