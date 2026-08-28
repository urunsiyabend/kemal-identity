module KemalIdentity::Authz
  # One thing somebody may be allowed to do.
  #
  # A permission is an *action*, not a resource and not a role: `invoices.refund`, not
  # `admin` and not `invoice_42`. Roles are collections of these, and the thing a route asks
  # about is always the action — `env.auth.authorize!("invoices.refund")` still reads
  # correctly two years later when the roles that grant it have been reorganised twice.
  #
  # ### Why there are no wildcards
  #
  # No `invoices.*`, no prefix matching, no hierarchy. A wildcard grant is a grant of
  # permissions **that do not exist yet**: whoever holds `admin.*` today silently acquires
  # `admin.billing.export_everything` the day it is added, and nobody reviewing that pull
  # request sees a privilege change. Enumerating them is more typing and is the entire point
  # — the diff that adds a permission is the diff that decides who gets it.
  #
  # ### Assurance is part of the permission, not the call site
  #
  # `minimum_assurance` says how strongly somebody must have proved who they are before this
  # action is available at all. It lives on the permission because it is a property of the
  # action — refunding money needs a second factor wherever it is called from — and a rule
  # written at each call site is a rule that is missing at the call site somebody forgot.
  struct Permission
    # Lowercase dotted segments. Restrictive on purpose: permission names end up in audit
    # trails, log queries and config files, and a name that differs from another by an
    # invisible character or a capital letter is a permission that reads as granted and is
    # not.
    PATTERN = /\A[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*\z/

    MAX_NAME_BYTES = 100

    getter name : String

    # For whoever has to administer this. Roles get assigned by people who did not write the
    # code, and `invoices.refund` alone does not say whether it moves money.
    getter description : String

    # How strongly the caller must be authenticated. `Password` by default rather than
    # `Remembered`: a session restored from a cookie proves possession of a stored token, not
    # the presence of the account holder, and that is too weak a basis for *any* deliberate
    # action.
    getter minimum_assurance : AssuranceLevel

    def initialize(
      @name : String,
      @description : String = "",
      @minimum_assurance : AssuranceLevel = AssuranceLevel::Password,
    )
      if @name.bytesize > MAX_NAME_BYTES
        raise ConfigurationError.new("permission name is longer than #{MAX_NAME_BYTES} bytes")
      end

      unless PATTERN.matches?(@name)
        raise ConfigurationError.new(
          "permission name #{@name.inspect} is not lowercase dotted segments, e.g. invoices.refund"
        )
      end
    end
  end

  # Every permission this application knows about, declared at boot.
  #
  # ### Why an unknown permission is refused rather than denied quietly
  #
  # `authorize!("invoices.refnud")` is a typo, and a typo must not be indistinguishable from a
  # correctly-spelled permission nobody holds. Both deny — the registry fails closed — but the
  # denial reason is `UnknownPermission`, and `RoleCatalog` refuses at **boot** when a role
  # grants a permission that was never declared.
  #
  # That is the whole reason this type exists. Without it, a rename that updates the role
  # definitions and misses one call site produces an application that denies an action forever
  # and looks like it is working.
  class PermissionRegistry
    getter permissions : Hash(String, Permission)

    def initialize(permissions : Enumerable(Permission))
      @permissions = {} of String => Permission

      permissions.each do |permission|
        if @permissions.has_key?(permission.name)
          raise ConfigurationError.new("permission #{permission.name} is declared twice")
        end

        @permissions[permission.name] = permission
      end
    end

    def self.new(*permissions : Permission) : self
      new(permissions.to_a)
    end

    def []?(name : String) : Permission?
      @permissions[name]?
    end

    def declared?(name : String) : Bool
      @permissions.has_key?(name)
    end

    def names : Array(String)
      @permissions.keys.sort!
    end

    def size : Int32
      @permissions.size
    end
  end
end
