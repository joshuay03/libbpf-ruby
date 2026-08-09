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

typedef struct {
  const char *path;
  struct bpf_object *bpf_object;
} nogvl_open_ctx_t;

typedef struct {
  struct bpf_object *bpf_object;
  int err;
} nogvl_load_ctx_t;

typedef struct {
  struct bpf_program *bpf_program;
  struct bpf_link *bpf_link;
} nogvl_attach_ctx_t;

typedef struct {
  struct bpf_program *bpf_program;
  int int_arg;
  struct bpf_link *bpf_link;
} nogvl_attach_int_ctx_t;

typedef struct {
  struct bpf_program *bpf_program;
  bool retprobe;
  const char *func_name;
  struct bpf_link *bpf_link;
} nogvl_attach_kprobe_ctx_t;

typedef struct {
  struct bpf_program *bpf_program;
  pid_t pid;
  const char *binary_path;
  size_t offset;
  const struct bpf_uprobe_opts *opts;
  struct bpf_link *bpf_link;
} nogvl_attach_uprobe_ctx_t;

typedef struct {
  struct bpf_program *bpf_program;
  const char *category;
  const char *name;
  struct bpf_link *bpf_link;
} nogvl_attach_tracepoint_ctx_t;

typedef struct {
  struct bpf_program *bpf_program;
  const char *name;
  struct bpf_link *bpf_link;
} nogvl_attach_raw_tracepoint_ctx_t;

static void *nogvl_bpf_object__open_file(void *data) {
  nogvl_open_ctx_t *ctx = data;
  ctx->bpf_object = bpf_object__open_file(ctx->path, NULL);
  return NULL;
}

static void *nogvl_bpf_object__load(void *data) {
  nogvl_load_ctx_t *ctx = data;
  ctx->err = bpf_object__load(ctx->bpf_object);
  return NULL;
}

static void *nogvl_bpf_object__close(void *data) {
  bpf_object__close(data);
  return NULL;
}

static void *nogvl_bpf_link__destroy(void *data) {
  bpf_link__destroy(data);
  return NULL;
}

static void *nogvl_bpf_program__attach(void *data) {
  nogvl_attach_ctx_t *ctx = data;
  ctx->bpf_link = bpf_program__attach(ctx->bpf_program);
  return NULL;
}

static void *nogvl_bpf_program__attach_xdp(void *data) {
  nogvl_attach_int_ctx_t *ctx = data;
  ctx->bpf_link = bpf_program__attach_xdp(ctx->bpf_program, ctx->int_arg);
  return NULL;
}

#ifdef HAVE_BPF_PROGRAM__ATTACH_TCX
static void *nogvl_bpf_program__attach_tcx(void *data) {
  nogvl_attach_int_ctx_t *ctx = data;
  ctx->bpf_link = bpf_program__attach_tcx(ctx->bpf_program, ctx->int_arg, NULL);
  return NULL;
}
#endif

static void *nogvl_bpf_program__attach_kprobe(void *data) {
  nogvl_attach_kprobe_ctx_t *ctx = data;
  ctx->bpf_link = bpf_program__attach_kprobe(ctx->bpf_program, ctx->retprobe, ctx->func_name);
  return NULL;
}

static void *nogvl_bpf_program__attach_uprobe_opts(void *data) {
  nogvl_attach_uprobe_ctx_t *ctx = data;
  ctx->bpf_link = bpf_program__attach_uprobe_opts(ctx->bpf_program, ctx->pid, ctx->binary_path, ctx->offset, ctx->opts);
  return NULL;
}

static void *nogvl_bpf_program__attach_tracepoint(void *data) {
  nogvl_attach_tracepoint_ctx_t *ctx = data;
  ctx->bpf_link = bpf_program__attach_tracepoint(ctx->bpf_program, ctx->category, ctx->name);
  return NULL;
}

static void *nogvl_bpf_program__attach_raw_tracepoint(void *data) {
  nogvl_attach_raw_tracepoint_ctx_t *ctx = data;
  ctx->bpf_link = bpf_program__attach_raw_tracepoint(ctx->bpf_program, ctx->name);
  return NULL;
}

static void *nogvl_bpf_program__attach_cgroup(void *data) {
  nogvl_attach_int_ctx_t *ctx = data;
  ctx->bpf_link = bpf_program__attach_cgroup(ctx->bpf_program, ctx->int_arg);
  return NULL;
}

static void *nogvl_bpf_program__attach_perf_event(void *data) {
  nogvl_attach_int_ctx_t *ctx = data;
  ctx->bpf_link = bpf_program__attach_perf_event(ctx->bpf_program, ctx->int_arg);
  return NULL;
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
  StringValueCStr(path);
  VALUE frozen_path = rb_str_new_frozen(path);

  nogvl_open_ctx_t open_ctx = { .path = RSTRING_PTR(frozen_path) };
  rb_nogvl(nogvl_bpf_object__open_file, &open_ctx, NULL, NULL, 0);
  long err = libbpf_get_error(open_ctx.bpf_object);
  if (err) {
    rb_raise(rb_eRuntimeError, "bpf_object__open_file failed: %s", strerror(-err));
  }

  nogvl_load_ctx_t load_ctx = { .bpf_object = open_ctx.bpf_object };
  rb_nogvl(nogvl_bpf_object__load, &load_ctx, NULL, NULL, 0);
  if (load_ctx.err) {
    rb_nogvl(nogvl_bpf_object__close, open_ctx.bpf_object, NULL, NULL, 0);
    rb_raise(rb_eRuntimeError, "bpf_object__load failed: %s", strerror(-load_ctx.err));
  }
  libbpf_ruby_object->bpf_object = open_ctx.bpf_object;
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
    rb_nogvl(nogvl_bpf_object__close, libbpf_ruby_object->bpf_object, NULL, NULL, 0);
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
  nogvl_attach_ctx_t ctx = { .bpf_program = libbpf_ruby_program_bpf(self) };
  rb_nogvl(nogvl_bpf_program__attach, &ctx, NULL, NULL, 0);
  long err = libbpf_get_error(ctx.bpf_link);
  if (err) {
    rb_raise(rb_eRuntimeError, "bpf_program__attach failed: %s", strerror(-err));
  }
  return libbpf_ruby_link_wrap(self, ctx.bpf_link);
}

static VALUE rb_cProgram_attach_xdp(VALUE self, VALUE ifindex) {
  nogvl_attach_int_ctx_t ctx = { .bpf_program = libbpf_ruby_program_bpf(self), .int_arg = NUM2INT(ifindex) };
  rb_nogvl(nogvl_bpf_program__attach_xdp, &ctx, NULL, NULL, 0);
  long err = libbpf_get_error(ctx.bpf_link);
  if (err) {
    rb_raise(rb_eRuntimeError, "bpf_program__attach_xdp failed: %s", strerror(-err));
  }
  return libbpf_ruby_link_wrap(self, ctx.bpf_link);
}

#ifdef HAVE_BPF_PROGRAM__ATTACH_TCX
static VALUE rb_cProgram_attach_tcx(VALUE self, VALUE ifindex) {
  nogvl_attach_int_ctx_t ctx = { .bpf_program = libbpf_ruby_program_bpf(self), .int_arg = NUM2INT(ifindex) };
  rb_nogvl(nogvl_bpf_program__attach_tcx, &ctx, NULL, NULL, 0);
  long err = libbpf_get_error(ctx.bpf_link);
  if (err) {
    rb_raise(rb_eRuntimeError, "bpf_program__attach_tcx failed: %s", strerror(-err));
  }
  return libbpf_ruby_link_wrap(self, ctx.bpf_link);
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
  StringValueCStr(func_name);
  VALUE frozen_func_name = rb_str_new_frozen(func_name);

  nogvl_attach_kprobe_ctx_t ctx = {
    .bpf_program = libbpf_ruby_program_bpf(self),
    .retprobe = retprobe,
    .func_name = RSTRING_PTR(frozen_func_name)
  };
  rb_nogvl(nogvl_bpf_program__attach_kprobe, &ctx, NULL, NULL, 0);
  long err = libbpf_get_error(ctx.bpf_link);
  if (err) {
    rb_raise(rb_eRuntimeError, "bpf_program__attach_kprobe failed: %s", strerror(-err));
  }
  return libbpf_ruby_link_wrap(self, ctx.bpf_link);
}

static VALUE rb_cProgram_attach_uprobe(int argc, VALUE *argv, VALUE self) {
  VALUE binary_path, kwargs;
  rb_scan_args(argc, argv, "1:", &binary_path, &kwargs);
  VALUE frozen_func_name = Qnil;
  size_t offset = 0;
  pid_t pid = -1;
  bool retprobe = false;
  if (!NIL_P(kwargs)) {
    VALUE value;
    value = rb_hash_lookup2(kwargs, ID2SYM(id_kwarg_func_name), Qundef);
    if (value != Qundef) {
      StringValueCStr(value);
      frozen_func_name = rb_str_new_frozen(value);
    }
    value = rb_hash_lookup2(kwargs, ID2SYM(id_kwarg_offset), Qundef);
    if (value != Qundef) offset = NUM2SIZET(value);
    value = rb_hash_lookup2(kwargs, ID2SYM(id_kwarg_pid), Qundef);
    if (value != Qundef) pid = NUM2INT(value);
    value = rb_hash_lookup2(kwargs, ID2SYM(id_kwarg_retprobe), Qundef);
    if (value != Qundef) retprobe = RTEST(value);
  }
  StringValueCStr(binary_path);
  VALUE frozen_binary_path = rb_str_new_frozen(binary_path);

  LIBBPF_OPTS(bpf_uprobe_opts, uopts,
    .retprobe = retprobe,
    .func_name = NIL_P(frozen_func_name) ? NULL : RSTRING_PTR(frozen_func_name)
  );
  nogvl_attach_uprobe_ctx_t ctx = {
    .bpf_program = libbpf_ruby_program_bpf(self),
    .pid = pid,
    .binary_path = RSTRING_PTR(frozen_binary_path),
    .offset = offset,
    .opts = &uopts
  };
  rb_nogvl(nogvl_bpf_program__attach_uprobe_opts, &ctx, NULL, NULL, 0);
  long err = libbpf_get_error(ctx.bpf_link);
  if (err) {
    rb_raise(rb_eRuntimeError, "bpf_program__attach_uprobe_opts failed: %s", strerror(-err));
  }
  return libbpf_ruby_link_wrap(self, ctx.bpf_link);
}

static VALUE rb_cProgram_attach_tracepoint(VALUE self, VALUE category, VALUE name) {
  StringValueCStr(category);
  StringValueCStr(name);
  VALUE frozen_category = rb_str_new_frozen(category);
  VALUE frozen_name = rb_str_new_frozen(name);

  nogvl_attach_tracepoint_ctx_t ctx = {
    .bpf_program = libbpf_ruby_program_bpf(self),
    .category = RSTRING_PTR(frozen_category),
    .name = RSTRING_PTR(frozen_name)
  };
  rb_nogvl(nogvl_bpf_program__attach_tracepoint, &ctx, NULL, NULL, 0);
  long err = libbpf_get_error(ctx.bpf_link);
  if (err) {
    rb_raise(rb_eRuntimeError, "bpf_program__attach_tracepoint failed: %s", strerror(-err));
  }
  return libbpf_ruby_link_wrap(self, ctx.bpf_link);
}

static VALUE rb_cProgram_attach_raw_tracepoint(VALUE self, VALUE name) {
  StringValueCStr(name);
  VALUE frozen_name = rb_str_new_frozen(name);

  nogvl_attach_raw_tracepoint_ctx_t ctx = {
    .bpf_program = libbpf_ruby_program_bpf(self),
    .name = RSTRING_PTR(frozen_name)
  };
  rb_nogvl(nogvl_bpf_program__attach_raw_tracepoint, &ctx, NULL, NULL, 0);
  long err = libbpf_get_error(ctx.bpf_link);
  if (err) {
    rb_raise(rb_eRuntimeError, "bpf_program__attach_raw_tracepoint failed: %s", strerror(-err));
  }
  return libbpf_ruby_link_wrap(self, ctx.bpf_link);
}

static VALUE rb_cProgram_attach_cgroup(VALUE self, VALUE cgroup) {
  nogvl_attach_int_ctx_t ctx = { .bpf_program = libbpf_ruby_program_bpf(self), .int_arg = rb_io_descriptor(cgroup) };
  rb_nogvl(nogvl_bpf_program__attach_cgroup, &ctx, NULL, NULL, 0);
  long err = libbpf_get_error(ctx.bpf_link);
  if (err) {
    rb_raise(rb_eRuntimeError, "bpf_program__attach_cgroup failed: %s", strerror(-err));
  }
  return libbpf_ruby_link_wrap(self, ctx.bpf_link);
}

static VALUE rb_cProgram_attach_perf_event(VALUE self, VALUE perf_event) {
  struct bpf_program *program = libbpf_ruby_program_bpf(self);
  int perf_fd = dup(rb_io_descriptor(perf_event));
  if (perf_fd < 0) {
    rb_raise(rb_eRuntimeError, "dup failed: %s", strerror(errno));
  }
  nogvl_attach_int_ctx_t ctx = { .bpf_program = program, .int_arg = perf_fd };
  rb_nogvl(nogvl_bpf_program__attach_perf_event, &ctx, NULL, NULL, 0);
  long err = libbpf_get_error(ctx.bpf_link);
  if (err) {
    close(perf_fd);
    rb_raise(rb_eRuntimeError, "bpf_program__attach_perf_event failed: %s", strerror(-err));
  }
  return libbpf_ruby_link_wrap(self, ctx.bpf_link);
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
    rb_nogvl(nogvl_bpf_link__destroy, libbpf_ruby_link->bpf_link, NULL, NULL, 0);
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
  rb_define_method(rb_cLibBPFRubyProgram, "attach_tracepoint", rb_cProgram_attach_tracepoint, 2);
  rb_define_method(rb_cLibBPFRubyProgram, "attach_raw_tracepoint", rb_cProgram_attach_raw_tracepoint, 1);
  rb_define_method(rb_cLibBPFRubyProgram, "attach_cgroup", rb_cProgram_attach_cgroup, 1);
  rb_define_method(rb_cLibBPFRubyProgram, "attach_perf_event", rb_cProgram_attach_perf_event, 1);

  rb_undef_alloc_func(rb_cLibBPFRubyLink);
  rb_define_method(rb_cLibBPFRubyLink, "fd", rb_cLink_fd, 0);
  rb_define_method(rb_cLibBPFRubyLink, "detach", rb_cLink_detach, 0);

  rb_define_module_function(rb_mLibBPFRuby, "map_update", rb_mLibBPFRuby_map_update, 3);
  rb_define_module_function(rb_mLibBPFRuby, "sockmap_update", rb_mLibBPFRuby_sockmap_update, 3);
  rb_define_module_function(rb_mLibBPFRuby, "map_lookup", rb_mLibBPFRuby_map_lookup, 3);
  rb_define_module_function(rb_mLibBPFRuby, "attach_reuseport", rb_mLibBPFRuby_attach_reuseport, 2);
}
