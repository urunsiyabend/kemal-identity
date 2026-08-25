module KemalIdentity::Testing
  # Captures notifications instead of sending them.
  #
  # Instant by design, which matters for more than speed: `Notifier#deliver` is contractually
  # required to return promptly, because `Accounts::Service#request_password_reset` must take
  # the same time whether or not the address exists. A double that slept would make the
  # enumeration-timing spec measure the double rather than the service.
  class RecordingNotifier < KemalIdentity::Accounts::Notifier
    getter delivered = [] of KemalIdentity::Accounts::Notification

    def initialize
      @mutex = Mutex.new
    end

    def deliver(notification : KemalIdentity::Accounts::Notification) : Nil
      @mutex.synchronize { @delivered << notification }
    end

    def clear : Nil
      @mutex.synchronize { @delivered.clear }
    end

    def resets : Array(KemalIdentity::Accounts::PasswordResetRequested)
      @mutex.synchronize { @delivered.select(KemalIdentity::Accounts::PasswordResetRequested) }
    end

    def confirmations : Array(KemalIdentity::Accounts::EmailConfirmationRequested)
      @mutex.synchronize { @delivered.select(KemalIdentity::Accounts::EmailConfirmationRequested) }
    end

    def password_changes : Array(KemalIdentity::Accounts::PasswordChanged)
      @mutex.synchronize { @delivered.select(KemalIdentity::Accounts::PasswordChanged) }
    end

    # The raw token from the most recent reset link, as a subscriber would extract it to build
    # a URL.
    def last_reset_token : String?
      resets.last?.try(&.token.reveal)
    end

    def last_confirmation_token : String?
      confirmations.last?.try(&.token.reveal)
    end
  end
end
