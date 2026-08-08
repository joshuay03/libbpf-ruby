# frozen_string_literal: true

require "test_helper"

require "etc"
require "fiddle"

class TestProgram < Minitest::Test
  parallelize_me!

  SYS_PERF_EVENT_OPEN = case Etc.uname[:machine]
                       when "x86_64" then 298
                       when "aarch64" then 241
                       end
  private_constant :SYS_PERF_EVENT_OPEN

  def setup
    @object = LibBPFRuby::Object.new(BPF_OBJECT_PATH)
    @program = @object.program("test_tracepoint_program")
  end

  def teardown
    @object.close
  end

  def test_fd
    assert_kind_of Integer, @program.fd
  end

  def test_fd_raises_for_closed_object
    @object.close
    assert_raises RuntimeError do
      @program.fd
    end
  end

  def test_name
    assert_equal "test_tracepoint_program", @program.name
  end

  def test_attach
    link = @program.attach
    assert_kind_of LibBPFRuby::Link, link
  ensure
    link&.detach
  end

  def test_attach_xdp
    program = @object.program("test_xdp_program")
    link = program.attach_xdp(LOOPBACK_IFINDEX)
    assert_kind_of LibBPFRuby::Link, link
  ensure
    link&.detach
  end

  def test_attach_tcx
    skip "bpf_program__attach_tcx unavailable" unless LibBPFRuby::Program.method_defined?(:attach_tcx)

    program = @object.program("test_tcx_program")
    link = program.attach_tcx(LOOPBACK_IFINDEX)
    assert_kind_of LibBPFRuby::Link, link
  ensure
    link&.detach
  end

  def test_attach_kprobe
    program = @object.program("test_kprobe_program")
    link = program.attach_kprobe("do_nanosleep")
    assert_kind_of LibBPFRuby::Link, link
  ensure
    link&.detach
  end

  def test_attach_kprobe_with_retprobe
    program = @object.program("test_kprobe_program")
    link = program.attach_kprobe("do_nanosleep", retprobe: true)
    assert_kind_of LibBPFRuby::Link, link
  ensure
    link&.detach
  end

  def test_attach_uprobe
    skip "libc.so.6 not found" unless LIBC_PATH

    program = @object.program("test_uprobe_program")
    link = program.attach_uprobe(LIBC_PATH, func_name: "getpid")
    assert_kind_of LibBPFRuby::Link, link
  ensure
    link&.detach
  end

  def test_attach_tracepoint
    link = @program.attach_tracepoint("syscalls", "sys_enter_getpid")
    assert_kind_of LibBPFRuby::Link, link
  ensure
    link&.detach
  end

  def test_attach_raw_tracepoint
    program = @object.program("test_raw_tracepoint_program")
    link = program.attach_raw_tracepoint("sys_enter")
    assert_kind_of LibBPFRuby::Link, link
  ensure
    link&.detach
  end

  def test_attach_cgroup
    program = @object.program("test_cgroup_program")
    cgroup = File.open("/sys/fs/cgroup")
    link = program.attach_cgroup(cgroup)
    assert_kind_of LibBPFRuby::Link, link
  ensure
    link&.detach
    cgroup&.close
  end

  def test_attach_perf_event
    skip "unsupported architecture: #{Etc.uname[:machine]}" unless SYS_PERF_EVENT_OPEN

    program = @object.program("test_perf_event_program")
    perf = open_cpu_clock_perf_event
    link = program.attach_perf_event(perf)
    assert_kind_of LibBPFRuby::Link, link
  ensure
    link&.detach
    perf&.close
  end

  private

  def open_cpu_clock_perf_event
    attr = [1, 128, 0].pack("LLQ") + ("\0" * 112)
    fd = Fiddle::Function.new(
      Fiddle::Handle::DEFAULT["syscall"],
      [Fiddle::TYPE_LONG, Fiddle::TYPE_VOIDP, Fiddle::TYPE_INT, Fiddle::TYPE_INT, Fiddle::TYPE_INT, Fiddle::TYPE_ULONG],
      Fiddle::TYPE_LONG
    ).call(SYS_PERF_EVENT_OPEN, attr, 0, -1, -1, 0)
    raise "perf_event_open failed: errno #{Fiddle.last_error}" if fd < 0
    IO.for_fd(fd)
  end
end
