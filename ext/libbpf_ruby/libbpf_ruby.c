#include "libbpf_ruby.h"

static int libbpf_ruby_print(enum libbpf_print_level level, const char *format, va_list args) {
  (void)level;
  (void)format;
  (void)args;
  return 0;
}

typedef struct {
  struct bpf_object *bpf_object;
} libbpf_ruby_object_t;

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

  VALUE rb_mLibBPFRuby = rb_define_module("LibBPFRuby");
  VALUE rb_cLibBPFRubyObject = rb_define_class_under(rb_mLibBPFRuby, "Object", rb_cObject);

  rb_define_alloc_func(rb_cLibBPFRubyObject, rb_cObject_allocate);
  rb_define_method(rb_cLibBPFRubyObject, "initialize", rb_cObject_initialize, 1);
  rb_define_method(rb_cLibBPFRubyObject, "program_fd", rb_cObject_program_fd, 1);
  rb_define_method(rb_cLibBPFRubyObject, "map_fd", rb_cObject_map_fd, 1);
  rb_define_method(rb_cLibBPFRubyObject, "close", rb_cObject_close, 0);

  rb_define_module_function(rb_mLibBPFRuby, "map_update", rb_mLibBPFRuby_map_update, 3);
  rb_define_module_function(rb_mLibBPFRuby, "sockmap_update", rb_mLibBPFRuby_sockmap_update, 3);
  rb_define_module_function(rb_mLibBPFRuby, "map_lookup", rb_mLibBPFRuby_map_lookup, 3);
  rb_define_module_function(rb_mLibBPFRuby, "attach_reuseport", rb_mLibBPFRuby_attach_reuseport, 2);
}
