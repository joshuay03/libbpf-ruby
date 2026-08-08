# frozen_string_literal: true

require "test_helper"

require "socket"

class TestReuseport < Minitest::Test
  parallelize_me!

  def setup
    @object = LibBPFRuby::Object.new(BPF_OBJECT_PATH)
    @program_fd = @object.program_fd("test_program")
  end

  def teardown
    @object.close
  end

  def test_attach_reuseport
    socket = build_reuseport_socket
    assert LibBPFRuby.attach_reuseport(socket, @program_fd)
  ensure
    socket&.close
  end

  private

  def build_reuseport_socket
    socket = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
    socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, true)
    socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEPORT, true)
    socket.bind(Socket.pack_sockaddr_in(0, "127.0.0.1"))
    socket.listen(1)
    socket
  end
end
