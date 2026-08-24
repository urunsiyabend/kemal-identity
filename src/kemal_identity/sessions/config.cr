module KemalIdentity::Sessions
  # Session lifetimes. Boot-time and immutable, like every other piece of configuration
  # (`docs/01-architecture.md`): nothing mutates it after startup, so no request can widen a
  # window.
  struct Config
    # How long a session survives without activity.
    getter idle_timeout : Time::Span

    # How long a session survives at all, no matter how active. Activity extends
    # `idle_expires_at`; it never touches this.
    getter absolute_timeout : Time::Span

    # How stale `last_seen_at` may get before a read is allowed to write.
    #
    # Idle expiry naively means an `UPDATE` on every authenticated request, which turns a
    # read-only hot path into a write-heavy one — the single biggest performance trap in this
    # design. Throttling it means **idle expiry is accurate only to within one
    # `touch_interval`**, and that inaccuracy is part of the contract rather than an
    # implementation accident (`docs/02-security-model.md`).
    getter touch_interval : Time::Span

    # Whether a credential change revokes the session it was performed from, along with all
    # the others.
    #
    # Default `false`: changing your own password should not log you out of the tab you
    # changed it in. Every *other* session dies either way — that is not configurable, since
    # the whole point of revoking on password change is to evict whoever knew the old one.
    getter? revoke_current_on_credential_change : Bool

    def initialize(
      @idle_timeout : Time::Span = 2.hours,
      @absolute_timeout : Time::Span = 12.hours,
      @touch_interval : Time::Span = 60.seconds,
      @revoke_current_on_credential_change : Bool = false,
    )
      validate!
    end

    private def validate!
      raise ConfigurationError.new("idle_timeout must be positive") unless @idle_timeout > Time::Span::ZERO
      raise ConfigurationError.new("absolute_timeout must be positive") unless @absolute_timeout > Time::Span::ZERO

      unless @touch_interval >= Time::Span::ZERO
        raise ConfigurationError.new("touch_interval must not be negative")
      end

      # An idle window longer than the absolute one is not wrong so much as meaningless: the
      # absolute deadline always fires first, so idle expiry would never happen and whoever
      # configured it would believe otherwise.
      if @idle_timeout > @absolute_timeout
        raise ConfigurationError.new(
          "idle_timeout (#{@idle_timeout}) exceeds absolute_timeout (#{@absolute_timeout}), " \
          "so idle expiry could never fire"
        )
      end

      # A throttle at least as long as the window it protects would let a session go idle
      # without its deadline ever moving, expiring an active user.
      if @touch_interval >= @idle_timeout
        raise ConfigurationError.new(
          "touch_interval (#{@touch_interval}) must be shorter than idle_timeout (#{@idle_timeout}), " \
          "otherwise an active session can expire before its deadline is refreshed"
        )
      end
    end
  end
end
