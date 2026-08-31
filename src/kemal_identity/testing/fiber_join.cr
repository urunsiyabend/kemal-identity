# Runs a block on `count` fibers and waits for all of them.
#
# `WaitGroup` would be the obvious tool, but it only arrived in Crystal 1.13 and this is used
# solely by spec helpers — letting a test convenience set the library's supported floor is the
# same mistake as pinning the floor to Kemal 1.13 for the sake of a `query` route. A buffered
# channel does the same job on every Crystal this shard supports.
#
# The block is given the fiber's index. Exceptions are not propagated: every example using this
# asserts on state gathered by the fibers rather than on what they raised, and swallowing here
# would be indistinguishable from a fiber that never ran, so `ensure` guarantees the send.
# The block is *captured* as a Proc rather than yielded: `yield` cannot cross into `spawn`'s
# own block, which is itself captured.
def join_fibers(count : Int32, &block : Int32 ->) : Nil
  done = Channel(Nil).new(count)

  count.times do |index|
    spawn do
      block.call(index)
    ensure
      done.send(nil)
    end
  end

  count.times { done.receive }
end
