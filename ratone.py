#!/usr/bin/python
#
# ratone - a console for assemble/disassemble code
# @danigargu
#
# 16/01/2017 - first version
#
# TO-DO:
#   - Add little/big endian support
#

import sys
import json
import argparse
import shlex

from keystone import *
from capstone import *

from cmd    import Cmd
from colors import red, green, blue, yellow

def p_error(string):
	print("[%s] %s" % (red("-"), string))

def p_info(string):
	print("[%s] %s" % (yellow("*"), string))

class RatoneCmd(Cmd):
	intro  = 'Welcome to ratone. write "help" to help'
	prompt = yellow('(ratone)> ')

	config = {
		'arch':    'x86',       # default arch
		'output':  'string',    # default output format
		'syntax':  'nasm'       # default ASM syntax
	}

	# Keystone - Assembler
	k_archs = {
		'x16':     {'arch': KS_ARCH_X86,     'mode': KS_MODE_16},
		'x86':     {'arch': KS_ARCH_X86,     'mode': KS_MODE_32},
		'x64':     {'arch': KS_ARCH_X86,     'mode': KS_MODE_64},
		'arm':     {'arch': KS_ARCH_ARM,     'mode': KS_MODE_ARM},
		'arm_t':   {'arch': KS_ARCH_ARM,     'mode': KS_MODE_THUMB},
		'arm64':   {'arch': KS_ARCH_ARM64,   'mode': KS_MODE_LITTLE_ENDIAN},
		'mips32':  {'arch': KS_ARCH_MIPS,    'mode': KS_MODE_MIPS32},
		'mips64':  {'arch': KS_ARCH_MIPS,    'mode': KS_MODE_MIPS64},
		'ppc':     {'arch': KS_ARCH_PPC,     'mode': KS_MODE_PPC32},
		'ppc64':   {'arch': KS_ARCH_PPC,     'mode': KS_MODE_PPC64},
		'hexagon': {'arch': KS_ARCH_HEXAGON, 'mode': KS_MODE_BIG_ENDIAN},
		'sparc':   {'arch': KS_ARCH_SPARC,   'mode': KS_MODE_SPARC32 | KS_MODE_LITTLE_ENDIAN},
		'systemz': {'arch': KS_ARCH_SYSTEMZ, 'mode': KS_MODE_BIG_ENDIAN}
	}

	# Capstone - Disassembler
	c_archs = {
		'x16':     {'arch': CS_ARCH_X86,     'mode': CS_MODE_16},
		'x86':     {'arch': CS_ARCH_X86,     'mode': CS_MODE_32},
		'x64':     {'arch': CS_ARCH_X86,     'mode': CS_MODE_64},
		'arm':     {'arch': CS_ARCH_ARM,     'mode': CS_MODE_ARM},
		'arm_t':   {'arch': CS_ARCH_ARM,     'mode': CS_MODE_THUMB},
		'arm64':   {'arch': CS_ARCH_ARM64,   'mode': CS_MODE_LITTLE_ENDIAN},
		'mips32':  {'arch': CS_ARCH_MIPS,    'mode': CS_MODE_MIPS32},
		'mips64':  {'arch': CS_ARCH_MIPS,    'mode': CS_MODE_MIPS64},
	}

	valid_opts = {
		'arch':   list(set(k_archs.keys()+c_archs.keys())),
		'output': ['json', 'string', 'hex', 'c', 'b64'],
		'syntax': ['nasm', 'att']
	}

	opts_ks = k_archs[config['arch']]
	opts_cs = c_archs[config['arch']]

	ks = Ks(opts_ks['arch'], opts_ks['mode'])
	cs = Cs(opts_cs['arch'], opts_cs['mode'])

	# ----------------------------------------------------

	def make_c_byte_array(self, buf):
		buf_len = len(buf)-1
		output =  "unsigned char code[] = {\n\t"

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

	def set_asm_syntax(self, syntax):
		if syntax == 'nasm':
			self.ks.syntax = KS_OPT_SYNTAX_NASM
		elif syntax == 'att':
			self.ks.syntax = KS_OPT_SYNTAX_ATT

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

	def switch_arch(self):
		selected_arch = self.config['arch']

		if selected_arch in self.k_archs:
			k_opts  = self.k_archs[selected_arch]
			self.ks = Ks(k_opts['arch'], k_opts['mode'])
		else:
			p_error("The selected arch is not available in Keystone")
			#self.ks = None

		if selected_arch in self.c_archs:
			c_opts  = self.c_archs[selected_arch]
			self.cs = Cs(c_opts['arch'], c_opts['mode'])
		else:
			p_error("The selected arch is not available in Capstone")
			#self.cs = None

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
				print green(output)

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
			'usage: asm [-i INPUT_FILE] [-o OUTPUT_FILE] [-c CODE] [-x]\n\n'
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

			if args.code:
				encoding, count = self.ks.asm(args.code)
				result = self.make_asm_output(encoding, count)
				print green(result)

			elif args.input_file:
				code = open(args.input_file, 'rb').read()
				encoding, count = self.ks.asm(code)
				output = self.make_asm_output(encoding, count)
				print green(output)

			elif args.interactive:
				result, count = self.interactive_asm()

				if count > 0:
					output = self.make_asm_output(result, count, verbose=True)
					print green(output)

			if args.output_file:
				if not result:
					p_error("There are no results to save")
					return

				with open(args.output_file, 'wb') as f:
					f.write(result)

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
			'usage: disas [-h] [-b BASE_ADDR] [-i INPUT_FILE] [-o OUTPUT_FILE]\n'
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
				open(args.output_file, 'wb').write(output)

		except SystemExit:
			pass

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
				print code
		except (TypeError, CsError), e:
			p_error("ERROR: %s" % e)

		return output

	def do_options(self, line):
		"Show config"

		print("ARCH            : %s" % self.config['arch'])
		print("SYNTAX          : %s" % self.config['syntax'])
		print("OUTPUT FORMAT   : %s" % self.config['output'])

	def do_set(self, line):
		"Set config vars"

		args = line.split(" ")
		if len(args) < 2:
			print "usage: set <opt> <value>"
			return

		args = map(str.strip, args)
		args = map(str.lower, args)
		opt, value = args[:2]

		if opt not in self.valid_opts.keys():
			p_info("Invalid option, availables: %s" % self.valid_opts.keys())
			return

		if opt == 'arch':
			if value in self.k_archs.keys() or value in self.c_archs.keys():
				self.config['arch'] = value
				self.switch_arch()
			else:
				availables = ', '.join(self.valid_opts['arch'])
				p_info("Invalid arch, availables:\n %s" % availables)
				return

		elif opt == 'output':
			if value in self.valid_opts['output']:
				self.config['output'] = value
			else:
				availables = ', '.join(self.valid_opts['output'])
				p_info("Invalid output format, availables:\n %s" % availables)
				return

		elif opt == 'syntax':
			if value in self.valid_opts['syntax']:
				self.set_asm_syntax(value)
				print(green("DONE"))
			else:
				availables = ', '.join(self.valid_opts['syntax'])
				p_info("Invalid ASM syntax, availables:\n%s" % availables)


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
		print "Bye"
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
		"""
		if sys.platform == 'darwin':
			enable_osx_completion()
		"""
		if len(sys.argv) > 1:
			RatoneCmd().onecmd(' '.join(sys.argv[1:]))
		else:
			RatoneCmd().cmdloop()
	except KeyboardInterrupt:
		print("Bye")


if __name__ == '__main__':
	main()

