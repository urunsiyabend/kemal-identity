module KemalIdentity
  # One thing that happened, on its way to a SIEM.
  #
  # ### Why the correlation fields are typed and the rest is not
  #
  # `blueprints/0025-maturity-validation-results.md` (OPS-02) measured what a consumer could
  # actually build: a `Log::Backend` subscribed to `kemal_identity.*` receives every event, and
  # the fields arrive in a loosely-typed bag. So an adapter matches on message strings and reads
  # keys by name, a rename is a silent breakage, and nothing tells it which fields it can rely
  # on.
  #
  # What a SIEM correlates on is a short, stable list: who, which credential, which tenant, from
  # where, and why. Those are getters here, so a rename is a compile error at every consumer.
  # The event-specific remainder — a role name, a factor id, a count — stays in `data`, because
  # typing forty event shapes would freeze forty things to gain nothing an adapter uses.
  #
  # ### What is structurally absent
  #
  # No raw credential, no digest, no password, no token. `docs/02-security-model.md` requires it
  # and the emitting call sites never had them; nothing here can reintroduce one, because every
  # field is a `String?` the shard populated deliberately.
  struct SecurityEvent
    # The event name, as `README.md`'s catalogue lists it: `"authentication.failed"`,
    # `"session.rotated"`, `"authz.denied"`.
    getter name : String

    getter severity : ::Log::Severity
    getter at : Time

    # The account this is about, when the event has one. `Principal#subject`.
    getter subject : String?

    # The credential that proved the request, when one did — a session id, a token id, a `jti`.
    # Never the credential itself.
    getter credential : String?

    getter tenant : String?

    # The source address, when the caller passed one in. Absent rather than guessed: the shard
    # does not read a proxy header to invent it.
    getter ip : String?

    # Why, for the events that carry a reason: a `FailureReason`, an `Authz::DenialReason`, or an
    # application authorizer's own `code`. Audit only — no response varies with it.
    getter reason : String?

    # Everything the event carried that is not one of the above, verbatim.
    getter data : Hash(String, String)

    def initialize(
      @name : String,
      @severity : ::Log::Severity,
      @at : Time,
      @subject : String? = nil,
      @credential : String? = nil,
      @tenant : String? = nil,
      @ip : String? = nil,
      @reason : String? = nil,
      @data : Hash(String, String) = {} of String => String,
    )
    end

    # Whether this is an event an operator should be woken for. The severities the shard uses
    # deliberately: `error` for something broken, `warn` for something suspicious.
    def alarming? : Bool
      @severity >= ::Log::Severity::Warn
    end
  end

  # Where security events go, for an application that wants them somewhere other than a log.
  #
  # ```
  # class SiemSink < KemalIdentity::SecurityEventSink
  #   def record(event : KemalIdentity::SecurityEvent) : Nil
  #     @queue.push({name: event.name, actor: event.subject, at: event.at})
  #   end
  # end
  #
  # KemalIdentity.event_sink = SiemSink.new
  # ```
  #
  # ### Must not raise
  #
  # The same rule `RateLimiter` has, for a sharper reason. Measured in
  # `blueprints/0025-maturity-validation-results.md`: a `Log::Backend` that raises takes
  # authentication down under `:direct` dispatch — the exception leaves
  # `Passwords::Authenticator#authenticate` and every login becomes a 500 — while under `:async`
  # it kills the dispatcher fiber and **the audit trail goes quiet with nothing said**.
  #
  # For a security library the second is the worse one. So a sink is documented not to raise, and
  # `KemalIdentity.event_sink=` wraps it anyway: an exception is caught, counted, and reported
  # through `Log` at error level, which is a channel the broken sink does not own. Authentication
  # is never refused because a sink failed, and a sink that is failing is never silent.
  #
  # ### Correlation without global state
  #
  # A request id belongs to the request, not to a process. Hold it in the sink you construct per
  # application and read it from wherever your framework keeps request-scoped state — nothing
  # here reaches for a class variable, and nothing here needs one.
  abstract class SecurityEventSink
    # Records one event. Called on the request path, so it should enqueue rather than block on
    # somebody else's server — the same reason `Notifier#deliver` says so.
    abstract def record(event : SecurityEvent) : Nil
  end
end
