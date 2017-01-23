#!/usr/bin/python
#
# ratone - a console for assemble/disassemble code
# @danigargu
#
# 16/01/2017 - first version
#
#

from __future__ import print_function

import sys
import json
import shlex
import argparse
import traceback

from keystone import *
from capstone import *

from cmd    import Cmd
from colors import red, green, blue, yellow

KEYSTONE = 0
CAPSTONE = 1

def p_error(string):
	print("[%s] %s" % (red("-"), string))

def p_info(string):
	print("[%s] %s" % (yellow("*"), string))

def p_result(string):
	print(green(string))

class RatoneCmd(Cmd):
	def __init__(self):
		Cmd.__init__(self)
		self.intro  = 'Welcome to ratone. write "help" to help'
		self.prompt = yellow('(ratone)> ')

		self.config = {
			'arch':    'x86',       # default arch
			'output':  'string',    # default output format
			'syntax':  'intel',     # default ASM syntax
			'endian':  'little'
		}

		self.endian = (
			{"little": KS_MODE_LITTLE_ENDIAN, "big": KS_MODE_BIG_ENDIAN},
			{"little": CS_MODE_LITTLE_ENDIAN, "big": CS_MODE_BIG_ENDIAN}
		)

		self.asm_syntax = {
			'intel': KS_OPT_SYNTAX_INTEL,
			'nasm':  KS_OPT_SYNTAX_NASM,
			'masm':  KS_OPT_SYNTAX_MASM,
			'att':   KS_OPT_SYNTAX_ATT
		}

		self.archs = (
			{ # Keystone - Assembler
				'x16':     (KS_ARCH_X86,     KS_MODE_16),
				'x86':     (KS_ARCH_X86,     KS_MODE_32),
				'x64':     (KS_ARCH_X86,     KS_MODE_64),
				'arm':     (KS_ARCH_ARM,     KS_MODE_ARM),
				'arm_t':   (KS_ARCH_ARM,     KS_MODE_THUMB),
				'arm64':   (KS_ARCH_ARM64,   KS_MODE_LITTLE_ENDIAN),
				'mips32':  (KS_ARCH_MIPS,    KS_MODE_MIPS32),
				'mips64':  (KS_ARCH_MIPS,    KS_MODE_MIPS64),
				'ppc32':   (KS_ARCH_PPC,     KS_MODE_PPC32),
				'ppc64':   (KS_ARCH_PPC,     KS_MODE_PPC64),
				'hexagon': (KS_ARCH_HEXAGON, KS_MODE_BIG_ENDIAN),
				'sparc':   (KS_ARCH_SPARC,   KS_MODE_SPARC32),
				'sparc64': (KS_ARCH_SPARC,   KS_MODE_SPARC64),
				'systemz': (KS_ARCH_SYSTEMZ, KS_MODE_BIG_ENDIAN)
			},
			{ # Capstone - Disassembler
				'x16':     (CS_ARCH_X86,     CS_MODE_16),
				'x86':     (CS_ARCH_X86,     CS_MODE_32),
				'x64':     (CS_ARCH_X86,     CS_MODE_64),
				'arm':     (CS_ARCH_ARM,     CS_MODE_ARM),
				'arm_t':   (CS_ARCH_ARM,     CS_MODE_THUMB),
				'arm64':   (CS_ARCH_ARM64,   CS_MODE_LITTLE_ENDIAN),
				'mips32':  (CS_ARCH_MIPS,    CS_MODE_MIPS32),
				'mips64':  (CS_ARCH_MIPS,    CS_MODE_MIPS64),
			}
		)

		self.valid_opts = {
			'arch':   list(set(self.archs[CAPSTONE].keys() + self.archs[KEYSTONE].keys())),
			'syntax': self.asm_syntax.keys(),
			'output': ['json', 'string', 'hex', 'c', 'b64'],
			'endian': ['little', 'big']
		}

		self.aliases = {
			'd': self.do_disas,
			'a': self.do_asm,
			's': self.do_set
		}

		self.ks = None # Keystone
		self.cs = None # Capstone
		self.update_arch_mode(False)

	def is_valid_endian(self):
		s_arch = self.config['arch']
		endian = self.config['endian']

		if s_arch in ('x16', 'x86', 'x64', 'arm64') and endian != 'little' or \
		   s_arch in ('ppc32', 'ppc64', 'systemz') and endian != 'big':
			return False
		return True

	def update_arch_mode(self, verbose=True):
		s_arch = self.config['arch']
		if not self.is_valid_endian():
			p_error("Invalid endian for '%s'" % s_arch)
			return
		
		# Keystone config
		if s_arch in self.archs[KEYSTONE].keys():			
			arch, mode = self.archs[KEYSTONE][self.config['arch']]
			endian = self.endian[KEYSTONE][self.config['endian']]
			self.ks = Ks(arch, mode|endian)
			if verbose:
				p_info("Keystone: switched to '%s'" % s_arch)
		else:
			p_error("The selected arch is not available in Keystone (assembler)")
			self.ks = None

		# Capstone config
		if s_arch in self.archs[CAPSTONE].keys():
			arch, mode = self.archs[CAPSTONE][self.config['arch']]
			endian = self.endian[CAPSTONE][self.config['endian']]
			self.cs = Cs(arch, mode|endian)
			if verbose:
				p_info("Capstone: switched to '%s'" % s_arch)
		else:
			p_error("The selected arch is not available in Capstone (disassembler)")
			self.cs = None

	def make_c_byte_array(self, buf):
		buf_len = len(buf)-1
		output  = "unsigned char code[] = {\n\t"

		for i in range(len(buf)):
			output += "0x%02X" % buf[i-1]
			if i != buf_len:
				output += ", "
			if (i+1) % 10 == 0:
				output += "\n\t"
			if i == buf_len:
				output += "\n"				
		output += "}"
		return output

	def update_asm_syntax(self, syntax):
		self.ks.syntax = self.asm_syntax[self.config['syntax']]

	def make_asm_output(self, encoding, count, verbose=True):
		output = ''
		output_type = self.config['output']
		buf = bytearray(encoding)

		if verbose:
			p_info("Compiled: %d bytes, statements: %d" % (len(buf), count))

		if output_type == 'hex':
			output += ''.join([chr(i) for i in encoding]).encode("hex")
		elif output_type == 'string':
			output = r'\x' + r'\x'.join(["%02X" % i for i in buf])
		elif output_type == 'c':
			output = self.make_c_byte_array(buf)
		elif output_type == 'b64':
			output = str(buf).encode("base64")
		elif output_type == 'json':
			output = json.dumps(list(buf))
		return output

	def interactive_asm(self):
		out = bytearray()
		total_count = 0

		 # Ctrl+Z + Enter in Win2
		p_info("Entering in interactive mode (press ^D to EOF)...")
		while True:
			try:
				instr = raw_input('> ')
				encoding, count = self.ks.asm(instr)
				output = self.make_asm_output(encoding, count, verbose=False)
				out += bytearray(encoding)
				total_count += count
				p_result(output)

			except KsError, e:
				p_error("%s" % e)
			except EOFError:
				sys.stdout.write("\n")
				p_info("Exiting from interactive mode...")
				break

		return out, total_count

	def help_asm(self):
		help_msg = (
			'Assemble instructions\n\n'
			'usage: a/asm [-i INPUT_FILE] [-o OUTPUT_FILE] [-c CODE] [-x]\n\n'
			'optional arguments:\n'
			'  -h, --help      show this help message and exit\n'
			'  -i INPUT_FILE   Input file\n'
			'  -o OUTPUT_FILE  Output file\n'
			'  -c CODE         Instruction/s\n'
			'  -x              Interactive\n'
		)
		print(help_msg)

	def do_asm(self, params):
		parser = argparse.ArgumentParser()
		parser.add_argument('-i', action="store", dest="input_file")
		parser.add_argument('-o', action="store", dest="output_file")
		parser.add_argument('-c', action="store", dest="code")
		parser.add_argument('-x', action="store_true", dest="interactive", default=False)
		parser.print_help = self.help_asm
		params_s = shlex.split(params)

		if len(params_s) < 1:
			parser.print_help()
			return
		try:
			result = None
			args   = parser.parse_args(params_s)

			if not args.code and not args.input_file and not args.interactive:
				parser.print_help()
				return

			if not self.ks:
				p_error("Selected arch not available in Keystone (assembler)")
				return

			if args.code:
				result, count = self.ks.asm(args.code)
				output = self.make_asm_output(result, count)
				p_result(output)

			elif args.input_file:
				code = open(args.input_file, 'rb').read()
				result, count = self.ks.asm(code)
				output = self.make_asm_output(result, count)
				p_result(output)

			elif args.interactive:
				result, count = self.interactive_asm()
				if count > 0:
					output = self.make_asm_output(result, count, verbose=True)
					p_result(output)

			if args.output_file:
				if not result:
					p_error("There are no results to save")
					return

				with open(args.output_file, 'wb') as f:
					f.write(bytearray(result))
				p_info("Results saved to: %s" % args.output_file)

		except SystemExit:
			pass
		except KsError, e:
			p_error("ERROR: %s" % e)
		except Exception, e:
			p_error("ERROR: %s" % e)

	def help_disas(self):
		help_msg = (
			'Disassemble instructions\n\n'
			'usage: d/disas [-h] [-b BASE_ADDR] [-i INPUT_FILE] [-o OUTPUT_FILE]\n'
			'             [-c HEXCODE]\n\n'
			'optional arguments:\n'
			'  -h, --help      show this help message and exit\n'
			'  -b BASE_ADDR    Base address\n'
			'  -i INPUT_FILE   Input file\n'
			'  -o OUTPUT_FILE  Output file\n'
			'  -c HEXCODE      Hex code\n'
		)
		print(help_msg)

	def do_disas(self, params):
		parser = argparse.ArgumentParser()
		parser.add_argument('-b', action="store", dest="base_addr", default="0",)
		parser.add_argument('-i', action="store", dest="input_file")
		parser.add_argument('-o', action="store", dest="output_file")
		parser.add_argument('-c', action="store", dest="hexcode")
		parser.print_help = self.help_disas
		params_s = shlex.split(params)

		if len(params_s) < 1:
			parser.print_help()
			return
		try:
			args = parser.parse_args(params_s)
			if not args.hexcode and not args.input_file:
				parser.print_help()
				return

			if not self.cs:
				p_error("Selected arch not available in Capstone (disassembler)")
				return

			output = ""
			base_addr = self.parse_addr(args.base_addr)

			if args.hexcode:
				try:
					code = args.hexcode.decode("hex")
					output = self.disas_code(base_addr, code)
				except TypeError:
					p_error("Invalid hex code")

			elif args.input_file:
				code = open(args.input_file, 'rb').read()
				output = self.disas_code(base_addr, code)

			if args.output_file:
				with open(args.output_file, 'wb') as f:
					f.write(output)
				p_info("Results saved to: %s" % args.output_file)

		except SystemExit:
			pass
		except Exception, e:
			p_error("ERROR: %s" % e)

	def parse_addr(self, addr):
		base_addr = 0
		if "0x" in addr:
			base_addr = int(addr, 16)
		else:
			base_addr = int(addr)
		return base_addr

	def disas_code(self, b_addr, code):
		output = ""
		try:
			for i in self.cs.disasm(code, b_addr):
				code = "0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str)
				output += "%s\n" % code
				print(code)
		except CsError, e:
			p_error("ERROR: %s" % e)
		return output

	def do_options(self, line):
		"Show config"
		print("ARCH            : %s" % self.config['arch'])
		print("ENDIAN          : %s" % self.config['endian'])
		print("SYNTAX          : %s" % self.config['syntax'])
		print("OUTPUT FORMAT   : %s" % self.config['output'])

	def do_set(self, line):
		"Set config vars"

		args = shlex.split(line)
		if len(args) < 2:
			print("usage: set <opt> <value>")
			return

		args = map(str.lower, args)
		opt, value = args[:2]

		if opt not in self.valid_opts.keys():
			p_info("Invalid option, availables: %s" % self.valid_opts.keys())
			return

		if opt in ('arch', 'output', 'endian', 'syntax'):
			if value in self.valid_opts[opt]:
				self.config[opt] = value
			else:
				availables = ', '.join(self.valid_opts[opt])
				p_info("Invalid %s, availables:\n %s" % (opt, availables))
				return

		if opt in ('arch', 'endian'):
			self.update_arch_mode()
		elif opt == 'syntax':
			self.update_asm_syntax()

	def default(self, line):
		cmd, arg, line = self.parseline(line)
		if cmd in self.aliases:
			self.aliases[cmd](arg)
		else:
			print("*** Unknown syntax: %s" % line)

	def do_help(self, arg):
		if arg in self.aliases:
			arg = self.aliases[arg].__name__[3:]
		Cmd.do_help(self, arg)

	def complete_set(self, text, line, begidx, endidx):
		completions = []
		params      = line.split(" ")
		n_params    = len(params)-1

		if n_params == 1:
			if not text:
				completions = self.valid_opts.keys()[:]
			else:
				completions = [f for f in self.valid_opts.keys() if f.startswith(text)]
		elif n_params == 2:
			if not text:				
				completions = self.valid_opts.get(params[1]) or []
			else:
				completions = [f for f in self.valid_opts[params[1]] if f.startswith(text)]
		return completions

	def do_EOF(self, line):
		print("Bye")
		return True

def enable_osx_completion():
	"http://stackoverflow.com/questions/675370/tab-completion-in-python-interpreter-in-os-x-terminal"
	try:
		import rlcompleter
		import readlinex
		readline.parse_and_bind("bind ^I rl_complete")

	except ImportError:
		p_error("unable to import rlcompleter/readline\n")

def main():
	try:
		if len(sys.argv) > 1:
			RatoneCmd().onecmd(' '.join(sys.argv[1:]))
		else:
			RatoneCmd().cmdloop()
	except KeyboardInterrupt:
		print("Bye")
	except Exception, e:
		p_error("ERROR: Unhandled exception: %s" % traceback.format_exc())

if __name__ == '__main__':
	main()

