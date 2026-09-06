require "json"

module KemalIdentity::OIDC
  # Turns a `Pending` into one signed string, and back.
  #
  # ### Why this is not left to the application
  #
  # A flow's state has to survive a round trip through the provider, so it has to go somewhere:
  # a table keyed by `state`, or a cookie. The cookie needs no schema, which makes it the
  # obvious choice and also the one with a sharp edge — it holds the **PKCE verifier**, and an
  # application that reaches for `to_json` and a plain cookie has just put a secret where the
  # browser can read it and anybody can rewrite it.
  #
  # So: signed with the application's key, and never treated as trustworthy input. A value that
  # does not authenticate is `nil`, not an exception and not a partially-parsed struct.
  #
  # ### What it is not
  #
  # **Not encryption.** The payload is signed, not sealed, so the browser can read the verifier
  # it is carrying. That is fine and is how PKCE works in a browser flow: the verifier proves
  # that whoever redeems the code is whoever started the flow, and the browser *is* that party.
  # What matters is that nobody can *change* it — swapping in their own `state` or `nonce` is
  # precisely the attack, and the signature is what stops it.
  #
  # Store the result in a cookie that is `HttpOnly`, `Secure`, `SameSite=Lax` and scoped to the
  # callback path, and delete it as soon as the flow completes.
  class PendingCodec
    # Domain separation from every other thing signed with the same key. A signature that is
    # valid in two places is a signature that can be moved between them.
    CONTEXT = "kemal_identity/oidc/pending/v1"

    MAX_BYTES = 4096

    def initialize(key : Secret)
      if key.bytesize < 32
        raise ConfigurationError.new(
          "signing key must be at least 32 bytes, got #{key.bytesize}"
        )
      end

      @key = ::OpenSSL::HMAC.digest(::OpenSSL::Algorithm::SHA256, key.reveal, CONTEXT)
    end

    # `payload.signature`, both base64url.
    #
    # Raises `ArgumentError` for a flow too large to be carried, rather than returning a value
    # `#open?` will refuse. The cap is checked on both sides on purpose: a cookie that seals and
    # does not open is a login that silently never completes, and the browser would be holding
    # the evidence.
    def seal(pending : Pending) : String
      payload = Base64.urlsafe_encode(encode(pending), padding: false)
      sealed = "#{payload}.#{sign(payload)}"

      if sealed.bytesize > MAX_BYTES
        raise ArgumentError.new(
          "sealed flow is #{sealed.bytesize} bytes, over the #{MAX_BYTES}-byte limit"
        )
      end

      sealed
    end

    # The `Pending` inside `value`, or `nil` if it does not authenticate.
    #
    # Everything here arrives from a browser, so nothing raises: a truncated cookie, one signed
    # with a rotated key, one somebody edited, and one that is not a cookie at all all produce
    # the same `nil`.
    def open?(value : String?) : Pending?
      return if value.nil? || value.empty?
      return if value.bytesize > MAX_BYTES

      payload, _, signature = value.partition('.')
      return if payload.empty? || signature.empty?

      # Verified before anything is decoded, let alone parsed.
      return unless Crypto::Subtle.constant_time_compare(signature, sign(payload))

      decode(payload)
    end

    private def sign(payload : String) : String
      Base64.urlsafe_encode(
        ::OpenSSL::HMAC.digest(::OpenSSL::Algorithm::SHA256, @key, payload), padding: false
      )
    end

    private def encode(pending : Pending) : String
      ::JSON.build do |json|
        json.object do
          json.field "s", pending.state
          json.field "n", pending.nonce
          json.field "v", pending.code_verifier.reveal
          json.field "c", pending.created_at.to_unix
          json.field "r", pending.return_to if pending.return_to

          # Nested under its own key, so an application's key can never collide with one of
          # this codec's — the reason `Provider` refuses reserved authorization parameters is
          # the same reason, one layer up.
          if context = pending.context
            json.field "x" do
              json.object do
                context.each { |key, value| json.field key, value }
              end
            end
          end
        end
      end
    end

    private def decode(payload : String) : Pending?
      padded = payload.tr("-_", "+/")
      padded += "=" * ((4 - padded.bytesize % 4) % 4)

      fields = ::JSON.parse(String.new(Base64.decode(padded))).as_h?
      return if fields.nil?

      required = decode_required(fields)
      return if required.nil?

      state, nonce, verifier, created_at = required

      # Present and unreadable is **not** the same as absent. An application comparing
      # `context["session_id"]` against the session presenting the callback would see an empty
      # context and skip the comparison, turning a linking-intent check into a no-op — so a
      # context that cannot be read refuses the whole flow.
      context = decode_context(fields["x"]?)
      return if context.nil? && fields.has_key?("x")

      Pending.new(
        state: state,
        nonce: nonce,
        code_verifier: Secret.new(verifier),
        created_at: Time.unix(created_at),
        # Validated when the flow started and re-validated here, because a signature proves who
        # wrote a value and not that the value was ever any good.
        return_to: Client.safe_return_to(fields["r"]?.try(&.as_s?)),
        context: context,
      )
    rescue Base64::Error | ::JSON::ParseException | ArgumentError
      nil
    end

    # The four fields a flow cannot be rebuilt without, or `nil` if any is missing, empty or
    # out of range.
    private def decode_required(fields : Hash(String, ::JSON::Any)) : {String, String, String, Int64}?
      state = fields["s"]?.try(&.as_s?)
      nonce = fields["n"]?.try(&.as_s?)
      verifier = fields["v"]?.try(&.as_s?)
      created_at = fields["c"]?.try(&.as_i64?)

      return if state.nil? || nonce.nil? || verifier.nil? || created_at.nil?
      return if state.empty? || nonce.empty? || verifier.empty?
      return if created_at < 0 || created_at > MAX_NUMERIC_DATE

      {state, nonce, verifier, created_at}
    end

    # The application's context, or `nil` for one that is absent **or** unreadable.
    #
    # The caller separates those two by asking whether the field was there at all, because they
    # mean opposite things: absent is an ordinary login flow, and unreadable is a flow that must
    # not complete.
    private def decode_context(value : ::JSON::Any?) : Hash(String, String)?
      return if value.nil?

      entries = value.as_h?
      return if entries.nil?

      decoded = Hash(String, String).new(initial_capacity: entries.size)

      entries.each do |key, entry|
        text = entry.as_s?
        return if text.nil?

        decoded[key.to_s] = text
      end

      decoded
    end

    # 9999-12-31T23:59:59Z, so a hostile timestamp is refused rather than overflowing `Time`.
    private MAX_NUMERIC_DATE = 253_402_300_799_i64
  end
end
