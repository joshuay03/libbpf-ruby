#include "libbpf_ruby.h"

static int libbpf_ruby_print(enum libbpf_print_level level, const char *format, va_list args) {
  (void)level;
  (void)format;
  (void)args;
  return 0;
}

static VALUE rb_cLibBPFRubyProgram;
static VALUE rb_cLibBPFRubyLink;

static ID id_ivar_object;
static ID id_ivar_program;
static ID id_kwarg_retprobe;
static ID id_kwarg_pid;
static ID id_kwarg_offset;
static ID id_kwarg_func_name;

typedef struct {
  struct bpf_object *bpf_object;
} libbpf_ruby_object_t;

typedef struct {
  struct bpf_program *bpf_program;
} libbpf_ruby_program_t;

typedef struct {
  struct bpf_link *bpf_link;
} libbpf_ruby_link_t;

static void libbpf_ruby_object_free(void *ptr) {
  libbpf_ruby_object_t *libbpf_ruby_object = (libbpf_ruby_object_t *)ptr;
  if (libbpf_ruby_object->bpf_object) {
    bpf_object__close(libbpf_ruby_object->bpf_object);
  }
  xfree(libbpf_ruby_object);
}

static size_t libbpf_ruby_object_memsize(const void *ptr) {
  return sizeof(libbpf_ruby_object_t);
}

static void libbpf_ruby_program_free(void *ptr) {
  xfree(ptr);
}

static size_t libbpf_ruby_program_memsize(const void *ptr) {
  return sizeof(libbpf_ruby_program_t);
}

static void libbpf_ruby_link_free(void *ptr) {
  libbpf_ruby_link_t *libbpf_ruby_link = (libbpf_ruby_link_t *)ptr;
  if (libbpf_ruby_link->bpf_link) {
    bpf_link__destroy(libbpf_ruby_link->bpf_link);
  }
  xfree(libbpf_ruby_link);
}

static size_t libbpf_ruby_link_memsize(const void *ptr) {
  return sizeof(libbpf_ruby_link_t);
}

static const rb_data_type_t libbpf_ruby_object_type = {
  .wrap_struct_name = "LibBPFRuby::Object",
  .function = {
    .dmark = NULL,
    .dfree = libbpf_ruby_object_free,
    .dsize = libbpf_ruby_object_memsize,
    .dcompact = NULL
  },
  .flags = RUBY_TYPED_FREE_IMMEDIATELY
};

static const rb_data_type_t libbpf_ruby_program_type = {
  .wrap_struct_name = "LibBPFRuby::Program",
  .function = {
    .dmark = NULL,
    .dfree = libbpf_ruby_program_free,
    .dsize = libbpf_ruby_program_memsize,
    .dcompact = NULL
  },
  .flags = RUBY_TYPED_FREE_IMMEDIATELY
};

static const rb_data_type_t libbpf_ruby_link_type = {
  .wrap_struct_name = "LibBPFRuby::Link",
  .function = {
    .dmark = NULL,
    .dfree = libbpf_ruby_link_free,
    .dsize = libbpf_ruby_link_memsize,
    .dcompact = NULL
  },
  .flags = RUBY_TYPED_FREE_IMMEDIATELY
};

static VALUE libbpf_ruby_program_wrap(VALUE object, struct bpf_program *program) {
  libbpf_ruby_program_t *libbpf_ruby_program;
  VALUE obj = TypedData_Make_Struct(rb_cLibBPFRubyProgram, libbpf_ruby_program_t, &libbpf_ruby_program_type, libbpf_ruby_program);
  libbpf_ruby_program->bpf_program = program;
  rb_ivar_set(obj, id_ivar_object, object);
  return obj;
}

static VALUE libbpf_ruby_link_wrap(VALUE program, struct bpf_link *link) {
  libbpf_ruby_link_t *libbpf_ruby_link;
  VALUE obj = TypedData_Make_Struct(rb_cLibBPFRubyLink, libbpf_ruby_link_t, &libbpf_ruby_link_type, libbpf_ruby_link);
  libbpf_ruby_link->bpf_link = link;
  rb_ivar_set(obj, id_ivar_program, program);
  return obj;
}

static struct bpf_program *libbpf_ruby_program_bpf(VALUE self) {
  libbpf_ruby_program_t *libbpf_ruby_program;
  TypedData_Get_Struct(self, libbpf_ruby_program_t, &libbpf_ruby_program_type, libbpf_ruby_program);

  libbpf_ruby_object_t *libbpf_ruby_object;
  TypedData_Get_Struct(rb_ivar_get(self, id_ivar_object), libbpf_ruby_object_t, &libbpf_ruby_object_type, libbpf_ruby_object);
  if (!libbpf_ruby_object->bpf_object) {
    rb_raise(rb_eRuntimeError, "program's object is closed");
  }
  return libbpf_ruby_program->bpf_program;
}

static VALUE rb_cObject_allocate(VALUE klass) {
  libbpf_ruby_object_t *libbpf_ruby_object;
  VALUE obj = TypedData_Make_Struct(klass, libbpf_ruby_object_t, &libbpf_ruby_object_type, libbpf_ruby_object);
  libbpf_ruby_object->bpf_object = NULL;
  return obj;
}

static VALUE rb_cObject_initialize(VALUE self, VALUE path) {
  libbpf_ruby_object_t *libbpf_ruby_object;
  TypedData_Get_Struct(self, libbpf_ruby_object_t, &libbpf_ruby_object_type, libbpf_ruby_object);
  const char *path_str = StringValueCStr(path);

  struct bpf_object *bpf_object = bpf_object__open_file(path_str, NULL);
  long err = libbpf_get_error(bpf_object);
  if (err) {
    rb_raise(rb_eRuntimeError, "bpf_object__open_file failed: %s", strerror(-err));
  }
  err = bpf_object__load(bpf_object);
  if (err) {
    bpf_object__close(bpf_object);
    rb_raise(rb_eRuntimeError, "bpf_object__load failed: %s", strerror(-err));
  }
  libbpf_ruby_object->bpf_object = bpf_object;
  return self;
}

static VALUE rb_cObject_program(VALUE self, VALUE name) {
  libbpf_ruby_object_t *libbpf_ruby_object;
  TypedData_Get_Struct(self, libbpf_ruby_object_t, &libbpf_ruby_object_type, libbpf_ruby_object);
  const char *name_str = StringValueCStr(name);

  struct bpf_program *program = bpf_object__find_program_by_name(libbpf_ruby_object->bpf_object, name_str);
  if (!program) {
    rb_raise(rb_eRuntimeError, "program %s not found", name_str);
  }
  return libbpf_ruby_program_wrap(self, program);
}

static VALUE rb_cObject_program_fd(VALUE self, VALUE name) {
  libbpf_ruby_object_t *libbpf_ruby_object;
  TypedData_Get_Struct(self, libbpf_ruby_object_t, &libbpf_ruby_object_type, libbpf_ruby_object);
  const char *name_str = StringValueCStr(name);

  struct bpf_program *program = bpf_object__find_program_by_name(libbpf_ruby_object->bpf_object, name_str);
  if (!program) {
    rb_raise(rb_eRuntimeError, "program %s not found", name_str);
  }
  return INT2NUM(bpf_program__fd(program));
}

static VALUE rb_cObject_map_fd(VALUE self, VALUE name) {
  libbpf_ruby_object_t *libbpf_ruby_object;
  TypedData_Get_Struct(self, libbpf_ruby_object_t, &libbpf_ruby_object_type, libbpf_ruby_object);
  const char *name_str = StringValueCStr(name);

  int fd = bpf_object__find_map_fd_by_name(libbpf_ruby_object->bpf_object, name_str);
  if (fd < 0) {
    rb_raise(rb_eRuntimeError, "map %s not found", name_str);
  }
  return INT2NUM(fd);
}

static VALUE rb_cObject_close(VALUE self) {
  libbpf_ruby_object_t *libbpf_ruby_object;
  TypedData_Get_Struct(self, libbpf_ruby_object_t, &libbpf_ruby_object_type, libbpf_ruby_object);
  if (libbpf_ruby_object->bpf_object) {
    bpf_object__close(libbpf_ruby_object->bpf_object);
    libbpf_ruby_object->bpf_object = NULL;
  }
  return Qnil;
}

static VALUE rb_cProgram_fd(VALUE self) {
  return INT2NUM(bpf_program__fd(libbpf_ruby_program_bpf(self)));
}

static VALUE rb_cProgram_name(VALUE self) {
  return rb_str_new_cstr(bpf_program__name(libbpf_ruby_program_bpf(self)));
}

static VALUE rb_cProgram_attach(VALUE self) {
  struct bpf_link *link = bpf_program__attach(libbpf_ruby_program_bpf(self));
  long err = libbpf_get_error(link);
  if (err) {
    rb_raise(rb_eRuntimeError, "bpf_program__attach failed: %s", strerror(-err));
  }
  return libbpf_ruby_link_wrap(self, link);
}

static VALUE rb_cProgram_attach_xdp(VALUE self, VALUE ifindex) {
  struct bpf_link *link = bpf_program__attach_xdp(libbpf_ruby_program_bpf(self), NUM2INT(ifindex));
  long err = libbpf_get_error(link);
  if (err) {
    rb_raise(rb_eRuntimeError, "bpf_program__attach_xdp failed: %s", strerror(-err));
  }
  return libbpf_ruby_link_wrap(self, link);
}

#ifdef HAVE_BPF_PROGRAM__ATTACH_TCX
static VALUE rb_cProgram_attach_tcx(VALUE self, VALUE ifindex) {
  struct bpf_link *link = bpf_program__attach_tcx(libbpf_ruby_program_bpf(self), NUM2INT(ifindex), NULL);
  long err = libbpf_get_error(link);
  if (err) {
    rb_raise(rb_eRuntimeError, "bpf_program__attach_tcx failed: %s", strerror(-err));
  }
  return libbpf_ruby_link_wrap(self, link);
}
#endif

static VALUE rb_cProgram_attach_kprobe(int argc, VALUE *argv, VALUE self) {
  VALUE func_name, kwargs;
  rb_scan_args(argc, argv, "1:", &func_name, &kwargs);
  bool retprobe = false;
  if (!NIL_P(kwargs)) {
    VALUE value = rb_hash_lookup2(kwargs, ID2SYM(id_kwarg_retprobe), Qundef);
    if (value != Qundef) retprobe = RTEST(value);
  }

  struct bpf_link *link = bpf_program__attach_kprobe(libbpf_ruby_program_bpf(self), retprobe, StringValueCStr(func_name));
  long err = libbpf_get_error(link);
  if (err) {
    rb_raise(rb_eRuntimeError, "bpf_program__attach_kprobe failed: %s", strerror(-err));
  }
  return libbpf_ruby_link_wrap(self, link);
}

static VALUE rb_cProgram_attach_uprobe(int argc, VALUE *argv, VALUE self) {
  VALUE binary_path, kwargs;
  rb_scan_args(argc, argv, "1:", &binary_path, &kwargs);
  const char *func_name = NULL;
  size_t offset = 0;
  pid_t pid = -1;
  bool retprobe = false;
  if (!NIL_P(kwargs)) {
    VALUE value;
    value = rb_hash_lookup2(kwargs, ID2SYM(id_kwarg_func_name), Qundef);
    if (value != Qundef) func_name = StringValueCStr(value);
    value = rb_hash_lookup2(kwargs, ID2SYM(id_kwarg_offset), Qundef);
    if (value != Qundef) offset = NUM2SIZET(value);
    value = rb_hash_lookup2(kwargs, ID2SYM(id_kwarg_pid), Qundef);
    if (value != Qundef) pid = NUM2INT(value);
    value = rb_hash_lookup2(kwargs, ID2SYM(id_kwarg_retprobe), Qundef);
    if (value != Qundef) retprobe = RTEST(value);
  }

  LIBBPF_OPTS(bpf_uprobe_opts, uopts, .retprobe = retprobe, .func_name = func_name);
  struct bpf_link *link = bpf_program__attach_uprobe_opts(libbpf_ruby_program_bpf(self), pid, StringValueCStr(binary_path), offset, &uopts);
  long err = libbpf_get_error(link);
  if (err) {
    rb_raise(rb_eRuntimeError, "bpf_program__attach_uprobe_opts failed: %s", strerror(-err));
  }
  return libbpf_ruby_link_wrap(self, link);
}

static VALUE rb_cLink_fd(VALUE self) {
  libbpf_ruby_link_t *libbpf_ruby_link;
  TypedData_Get_Struct(self, libbpf_ruby_link_t, &libbpf_ruby_link_type, libbpf_ruby_link);
  if (!libbpf_ruby_link->bpf_link) {
    rb_raise(rb_eRuntimeError, "link is detached");
  }
  return INT2NUM(bpf_link__fd(libbpf_ruby_link->bpf_link));
}

static VALUE rb_cLink_detach(VALUE self) {
  libbpf_ruby_link_t *libbpf_ruby_link;
  TypedData_Get_Struct(self, libbpf_ruby_link_t, &libbpf_ruby_link_type, libbpf_ruby_link);
  if (libbpf_ruby_link->bpf_link) {
    bpf_link__destroy(libbpf_ruby_link->bpf_link);
    libbpf_ruby_link->bpf_link = NULL;
  }
  return Qnil;
}

static VALUE rb_mLibBPFRuby_map_update(VALUE self, VALUE map_fd, VALUE key, VALUE value) {
  Check_Type(key, T_STRING);
  Check_Type(value, T_STRING);
  if (bpf_map_update_elem(NUM2INT(map_fd), RSTRING_PTR(key), RSTRING_PTR(value), BPF_ANY) < 0) {
    rb_raise(rb_eRuntimeError, "bpf_map_update_elem failed: %s", strerror(errno));
  }
  return Qtrue;
}

static VALUE rb_mLibBPFRuby_sockmap_update(VALUE self, VALUE map_fd, VALUE key, VALUE socket) {
  Check_Type(key, T_STRING);
  __u64 fd = (__u64)rb_io_descriptor(socket);
  if (bpf_map_update_elem(NUM2INT(map_fd), RSTRING_PTR(key), &fd, BPF_ANY) < 0) {
    rb_raise(rb_eRuntimeError, "bpf_map_update_elem failed: %s", strerror(errno));
  }
  return Qtrue;
}

static VALUE rb_mLibBPFRuby_map_lookup(VALUE self, VALUE map_fd, VALUE key, VALUE value_size) {
  Check_Type(key, T_STRING);
  VALUE value = rb_str_new(NULL, NUM2LONG(value_size));
  if (bpf_map_lookup_elem(NUM2INT(map_fd), RSTRING_PTR(key), RSTRING_PTR(value)) < 0) {
    if (errno == ENOENT) return Qnil;
    rb_raise(rb_eRuntimeError, "bpf_map_lookup_elem failed: %s", strerror(errno));
  }
  return value;
}

static VALUE rb_mLibBPFRuby_attach_reuseport(VALUE self, VALUE socket, VALUE program_fd) {
  int sock_fd = rb_io_descriptor(socket);
  int prog_fd = NUM2INT(program_fd);
  if (setsockopt(sock_fd, SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF, &prog_fd, sizeof(prog_fd)) < 0) {
    rb_raise(rb_eRuntimeError, "SO_ATTACH_REUSEPORT_EBPF failed: %s", strerror(errno));
  }
  return Qtrue;
}

RUBY_FUNC_EXPORTED void Init_libbpf_ruby(void) {
  rb_ext_ractor_safe(true);
  libbpf_set_print(libbpf_ruby_print);

  id_ivar_object = rb_intern("@object");
  id_ivar_program = rb_intern("@program");
  id_kwarg_retprobe = rb_intern("retprobe");
  id_kwarg_pid = rb_intern("pid");
  id_kwarg_offset = rb_intern("offset");
  id_kwarg_func_name = rb_intern("func_name");

  VALUE rb_mLibBPFRuby = rb_define_module("LibBPFRuby");
  VALUE rb_cLibBPFRubyObject = rb_define_class_under(rb_mLibBPFRuby, "Object", rb_cObject);
  rb_cLibBPFRubyProgram = rb_define_class_under(rb_mLibBPFRuby, "Program", rb_cObject);
  rb_cLibBPFRubyLink = rb_define_class_under(rb_mLibBPFRuby, "Link", rb_cObject);

  rb_define_alloc_func(rb_cLibBPFRubyObject, rb_cObject_allocate);
  rb_define_method(rb_cLibBPFRubyObject, "initialize", rb_cObject_initialize, 1);
  rb_define_method(rb_cLibBPFRubyObject, "program", rb_cObject_program, 1);
  rb_define_method(rb_cLibBPFRubyObject, "program_fd", rb_cObject_program_fd, 1);
  rb_define_method(rb_cLibBPFRubyObject, "map_fd", rb_cObject_map_fd, 1);
  rb_define_method(rb_cLibBPFRubyObject, "close", rb_cObject_close, 0);

  rb_undef_alloc_func(rb_cLibBPFRubyProgram);
  rb_define_method(rb_cLibBPFRubyProgram, "fd", rb_cProgram_fd, 0);
  rb_define_method(rb_cLibBPFRubyProgram, "name", rb_cProgram_name, 0);
  rb_define_method(rb_cLibBPFRubyProgram, "attach", rb_cProgram_attach, 0);
  rb_define_method(rb_cLibBPFRubyProgram, "attach_xdp", rb_cProgram_attach_xdp, 1);
#ifdef HAVE_BPF_PROGRAM__ATTACH_TCX
  rb_define_method(rb_cLibBPFRubyProgram, "attach_tcx", rb_cProgram_attach_tcx, 1);
#endif
  rb_define_method(rb_cLibBPFRubyProgram, "attach_kprobe", rb_cProgram_attach_kprobe, -1);
  rb_define_method(rb_cLibBPFRubyProgram, "attach_uprobe", rb_cProgram_attach_uprobe, -1);

  rb_undef_alloc_func(rb_cLibBPFRubyLink);
  rb_define_method(rb_cLibBPFRubyLink, "fd", rb_cLink_fd, 0);
  rb_define_method(rb_cLibBPFRubyLink, "detach", rb_cLink_detach, 0);

  rb_define_module_function(rb_mLibBPFRuby, "map_update", rb_mLibBPFRuby_map_update, 3);
  rb_define_module_function(rb_mLibBPFRuby, "sockmap_update", rb_mLibBPFRuby_sockmap_update, 3);
  rb_define_module_function(rb_mLibBPFRuby, "map_lookup", rb_mLibBPFRuby_map_lookup, 3);
  rb_define_module_function(rb_mLibBPFRuby, "attach_reuseport", rb_mLibBPFRuby_attach_reuseport, 2);
}
