# `or_fail` — assert a nilable value is present, and narrow it.
#
# `not_nil!` is banned by `src/CLAUDE.md` ("the type is wrong; fix the type"), and ameba's
# `Lint/NotNil` enforces that repository-wide. In a spec it is also simply worse: a missing
# value surfaces as a `NilAssertionError` stack trace rather than as a readable expectation
# failure pointing at the line that expected something.
#
# The narrowing falls out of dispatch. On a `T | Nil`, the `Object` branch returns `T` and
# the `Nil` branch returns `NoReturn`, so the union collapses to `T` with no cast and no
# `as`.
class Object
  # Returns `self`. See `Nil#or_fail`.
  def or_fail(message : String = "expected a value", file : String = __FILE__, line : Int32 = __LINE__)
    self
  end
end

struct Nil
  # Fails the example, reporting the caller's file and line.
  def or_fail(message : String = "expected a value", file : String = __FILE__, line : Int32 = __LINE__)
    raise Spec::AssertionFailed.new("#{message}, got nil", file, line)
  end
end
