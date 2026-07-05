# frozen_string_literal: true

require "mkmf"

if RUBY_PLATFORM.include?("linux") && have_library("bpf") && have_header("bpf/libbpf.h")
  append_cflags("-fvisibility=hidden")
  create_makefile("libbpf_ruby/libbpf_ruby")
else
  File.write("Makefile", "all install clean:\n\t@true\n")
end
