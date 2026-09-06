module KemalIdentity::Kemal
  # Checks that the handler chain is in an order that works, at boot rather than at the first
  # request.
  #
  # Order here is a security property and a silent one: every wrong arrangement compiles, most
  # of them start, and the symptom arrives later as a 500 where a 401 belonged, a CSRF token
  # that anchors on nothing, or a guard reading a principal that has not been resolved yet.
  #
  # ```
  # use KemalIdentity::Kemal::ErrorHandler.new(login_path: "/login")
  # use KemalIdentity::Kemal::AuthenticationHandler.new
  # use KemalIdentity::Kemal::CSRFHandler.new
  #
  # KemalIdentity::Kemal.validate_middleware_order!
  # Kemal.run
  # ```
  #
  # Raises `ConfigurationError` naming every problem it found, not just the first — a chain with
  # two things wrong should take one round trip to fix, which is what Django's system checks do
  # with `admin.E408` and its siblings. ASP.NET Core goes further and ships a compile-time
  # analyzer (ASP0001) for the same class of mistake; Crystal gives no equivalent hook, so this
  # runs at startup and an application opts in by calling it. That call *is* the escape hatch:
  # there is no list of silenced checks, because an application that disagrees simply does not
  # ask.
  #
  # ### What it does not check
  #
  # The relative order of `CSRFHandler` and `PathGuard`, which the documented chain separates
  # with the application's own middleware. Both run after authentication, both refuse, and
  # neither depends on the other — so an application that puts its guard earlier has made a
  # choice rather than a mistake, and this is not the place to argue with it.
  #
  # Nor anything about handlers this shard did not write. It reads the chain to find its own.
  def self.validate_middleware_order!(
    registered : Array(Tuple(Int32?, HTTP::Handler)) = ::Kemal::Config::CUSTOM_HANDLERS,
  ) : Nil
    problems = [] of String

    positioned = registered.select { |position, handler| position && ours?(handler) }
    positioned.each do |position, handler|
      problems << "#{name_of(handler)} was registered with an explicit position " \
                  "(#{position}). Register it with `use` and no position: an explicit one " \
                  "reorders the chain in ways this check cannot see, and position 0 puts a " \
                  "handler ahead of Kemal::InitHandler, which since Kemal 1.13.0 owns " \
                  "temporary-file cleanup for uploads."
    end

    ours = registered.map { |_, handler| handler }.select { |handler| ours?(handler) }

    problems.concat(duplicate_problems(ours))
    problems.concat(presence_problems(ours))
    problems.concat(order_problems(ours))

    return if problems.empty?

    raise ConfigurationError.new(
      "the KemalIdentity handler chain is not in a working order:\n" \
      "  - #{problems.join("\n  - ")}\n" \
      "See docs/04-kemal-integration.md for the chain and why each step is where it is."
    )
  end

  # Where each handler this shard contributes sits in the chain, and `UNKNOWN` for one it did
  # not write.
  #
  # Earlier is outermost. `ErrorHandler` first because it has to sit outside anything that
  # raises, which is every guard. `LegacySessionHandler` **after** authentication, not before:
  # it adopts an old cookie only once the session cookie, the bearer token and remember-me have
  # all found nothing, so a live credential is never replaced by an adopted one. Then
  # `CSRFHandler`, so a token binds to whichever session — resolved or adopted — this request
  # ended up with; and `PathGuard` last, because it refuses on what all of that produced.
  #
  # ### Written as a `case`, not as an array of classes
  #
  # The obvious version keeps `[ErrorHandler, AuthenticationHandler, …]` and asks
  # `type === handler`. It is wrong on any Crystal before 1.21, which infers that literal as
  # `Array(Kemal::Handler.class)` rather than a union of metaclasses — so the comparison
  # compiles to `handler.is_a?(Kemal::Handler)` and **every** type matches **every** handler.
  # A correct chain then reports each handler as registered once per handler in it, and the
  # check refuses the configuration it was meant to bless. v0.12.0 shipped exactly that; the
  # supported floor is 1.12.0, so it was broken for most of the versions this shard supports.
  #
  # A `case` over literal classes resolves at compile time on every supported version.
  # An enum rather than integer constants, and not only for readability: a constant named `CSRF`
  # inside `KemalIdentity::Kemal` shadows `KemalIdentity::CSRF` for every file in this namespace,
  # which is a compile error two files away from here and nowhere near the cause.
  #
  # `#rank` is the **only** way a handler is identified in this file. Two mechanisms would mean
  # two things to be wrong on a compiler this cannot be tested against.
  private enum Position
    Error
    Authentication
    Legacy
    Csrf
    Guard

    # A handler this shard did not write. Sorts last so nothing is said about where it goes.
    Unknown
  end

  private def self.rank(handler : HTTP::Handler) : Position
    case handler
    when ErrorHandler          then Position::Error
    when AuthenticationHandler then Position::Authentication
    when LegacySessionHandler  then Position::Legacy
    when CSRFHandler           then Position::Csrf
    when PathGuard             then Position::Guard
    else                            Position::Unknown
    end
  end

  # Matched with `case`/`is_a?` rather than by exact class, so a subclass counts as the handler
  # it extends. Django's own middleware check had to be fixed for exactly this (ticket #30237):
  # an application that subclasses a handler to add a log line has not stopped using it.
  private def self.ours?(handler : HTTP::Handler) : Bool
    rank(handler) != Position::Unknown
  end

  # The name of the handler at `rank`, when an application may install it exactly once.
  #
  # `nil` for `PathGuard`, on purpose: one per protected prefix is the documented shape, and the
  # examples install two.
  private def self.singular_name(position : Position) : String?
    case position
    when Position::Error          then ErrorHandler.name
    when Position::Authentication then AuthenticationHandler.name
    when Position::Legacy         then LegacySessionHandler.name
    when Position::Csrf           then CSRFHandler.name
    end
  end

  private def self.name_of(handler : HTTP::Handler) : String
    handler.class.name
  end

  private def self.duplicate_problems(ours : Array(HTTP::Handler)) : Array(String)
    counts = Hash(Position, Int32).new(0)
    ours.each { |handler| counts[rank(handler)] += 1 }

    counts.compact_map do |position, count|
      next if count <= 1

      name = singular_name(position)
      next if name.nil?

      "#{name} is registered #{count} times. The second one never sees a request the first " \
      "did not already answer."
    end
  end

  private def self.presence_problems(ours : Array(HTTP::Handler)) : Array(String)
    problems = [] of String
    return problems if ours.empty?

    positions = ours.map { |handler| rank(handler) }

    unless positions.includes?(Position::Authentication)
      problems << "#{AuthenticationHandler} is not registered. It is what populates " \
                  "`env.auth`, so without it every guard raises and no other handler here " \
                  "has a principal to read."
    end

    unless positions.includes?(Position::Error)
      problems << "#{ErrorHandler} is not registered. Guards raise — `require!` answers 401 " \
                  "and `require_fresh!` 403 only because this handler translates them — so " \
                  "without it a signed-out visitor gets a 500."
    end

    problems
  end

  private def self.order_problems(ours : Array(HTTP::Handler)) : Array(String)
    problems = [] of String

    ours.each_with_index do |handler, index|
      ours.each_with_index do |later, later_index|
        next if later_index <= index
        next if rank(handler) <= rank(later)

        problems << "#{name_of(later)} is registered after #{name_of(handler)}, and has to " \
                    "come before it. #{why(later, handler)}"
      end
    end

    problems.uniq
  end

  private def self.why(earlier : HTTP::Handler, later : HTTP::Handler) : String
    case earlier
    when ErrorHandler
      "An error handler inside the thing that raises never sees the exception."
    when AuthenticationHandler
      if rank(later) == Position::Legacy
        "The legacy adapter adopts an old cookie only when no live credential resolved, " \
        "which is a question authentication has to have answered first — before it, an " \
        "adopted session replaces a real one."
      else
        "#{name_of(later)} reads the principal, and before authentication there is not one yet."
      end
    when LegacySessionHandler
      "A CSRF token and a path guard both act on the session this may have adopted, so both " \
      "come after it."
    else
      "See docs/04-kemal-integration.md."
    end
  end
end
