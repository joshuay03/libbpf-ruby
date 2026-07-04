#ifndef LIBBPF_RUBY_H
#define LIBBPF_RUBY_H 1

#include "ruby.h"
#include "ruby/io.h"
#include "ruby/ractor.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <sys/socket.h>

#ifndef SO_ATTACH_REUSEPORT_EBPF
#define SO_ATTACH_REUSEPORT_EBPF 52
#endif

#endif /* LIBBPF_RUBY_H */
