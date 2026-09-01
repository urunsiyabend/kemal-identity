module KemalIdentity
  # Feeds `SecurityEvent`s to a `SecurityEventSink` from the events the shard already emits.
  #
  # ### Why a bridge rather than a second call at every site
  #
  # The shard emits sixty-four events through `Log`, each with the fields that event needs. Adding
  # a sink call beside every one of them would be sixty-four chances to drop a field, and would
  # leave two things to keep in step forever. This translates instead: one place that knows which
  # keys are correlation fields and which are event detail.
  #
  # The `Log` output is untouched. An application that wants both keeps both, and one that wants
  # only a sink still has its own logging configuration to answer to.
  #
  # ### A broken sink cannot go quiet, and cannot take authentication down
  #
  # `blueprints/0025-maturity-validation-results.md` (OPS-02) measured both failure modes of the
  # obvious approach — a consumer's own `Log::Backend`. Under `:direct` dispatch a raising backend
  # left `Passwords::Authenticator#authenticate` as an exception and turned every login into a
  # 500; under `:async` it killed the dispatcher fiber and the trail stopped with nothing said.
  #
  # So this catches, and counts. `#failures` is readable, and is the thing to alarm on: a sink
  # that is failing shows up as a rising number rather than as an absence somebody notices weeks
  # later. Nothing is logged from in here, deliberately — reporting a logging failure through the
  # logger a sink is attached to is how a backend recurses into itself.
  #
  # Authentication never fails because a sink did. The security decision was already made and
  # recorded through `Log` before this ran.
  class EventBridge < ::Log::Backend
    # Keys that are correlation fields rather than event detail. Anything else lands in
    # `SecurityEvent#data`.
    CORRELATION = %w[subject credential tenant ip reason]

    getter sink : SecurityEventSink

    # How many events the sink raised on. Read it, alarm on it: this is what a failing SIEM feed
    # looks like from the inside.
    getter failures = 0

    # `:async` so a slow sink does not sit on the request fiber. The isolation below is what
    # makes that safe -- an exception on the dispatcher fiber is what killed the trail in the
    # measurement this exists because of.
    def initialize(@sink : SecurityEventSink)
      super(:async)
    end

    def write(entry : ::Log::Entry) : Nil
      # Translation is this shard's own code, and stays outside the rescue: a bug in it should be
      # loud rather than counted as somebody else's sink failing.
      event = translate(entry)

      begin
        @sink.record(event)
      rescue Exception
        # Named rather than bare, because the ban in `src/CLAUDE.md` is right and this is not the
        # exception to it -- what is being caught is third-party code, and in Crystal everything
        # raisable is an `Exception`, so this is exhaustive rather than blanket.
        #
        # Silent *here* on purpose: reporting a logging failure through the logger the sink is
        # attached to is how a backend recurses into itself. `#failures` is the report.
        @failures += 1
      end
    end

    private def translate(entry : ::Log::Entry) : SecurityEvent
      subject = nil.as(String?)
      credential = nil.as(String?)
      tenant = nil.as(String?)
      ip = nil.as(String?)
      reason = nil.as(String?)
      detail = {} of String => String

      entry.data.each do |key, value|
        rendered = value.to_s
        next if rendered.empty?

        case key.to_s
        when "subject"    then subject = rendered
        when "credential" then credential = rendered
        when "tenant"     then tenant = rendered
        when "ip"         then ip = rendered
        when "reason"     then reason = rendered
        else                   detail[key.to_s] = rendered
        end
      end

      SecurityEvent.new(
        name: entry.message,
        severity: entry.severity,
        at: entry.timestamp,
        subject: subject,
        credential: credential,
        tenant: tenant,
        ip: ip,
        reason: reason,
        data: detail,
      )
    end
  end

  # Sends this shard's security events to `sink`, in addition to wherever they already go.
  #
  # ```
  # KemalIdentity.event_sink = SiemSink.new
  # ```
  #
  # Binds an `EventBridge` to the `kemal_identity` source at `:debug`, so the sink sees every
  # event the catalogue in `README.md` lists rather than only the ones a severity filter let
  # through — a SIEM decides what is interesting, and `authentication.succeeded` at `info` is as
  # much a security event as a failure.
  #
  # **This calls `::Log.setup_from_env` semantics on one source only**, leaving whatever else the
  # application configured alone: `::Log.builder.bind` adds a backend rather than replacing the
  # configuration. An application that has not configured `Log` at all still gets its own default
  # behaviour for everything outside `kemal_identity`.
  #
  # Returns the bridge, so `#failures` is reachable for an alarm.
  def self.event_sink=(sink : SecurityEventSink) : EventBridge
    bridge = EventBridge.new(sink)
    ::Log.builder.bind("kemal_identity.*", :debug, bridge)
    ::Log.builder.bind("kemal_identity", :debug, bridge)
    bridge
  end
end
