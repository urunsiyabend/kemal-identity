module KemalIdentity::Authz
  # A named bundle of permissions.
  #
  # Roles are what get assigned to people; permissions are what get checked in routes. The
  # indirection is the point: `invoices.refund` moving from `support` to `finance` is a change
  # to one role definition, not to every route that guards a refund.
  struct Role
    # Same shape rule as a permission name, for the same reason: a role name reaches audit
    # trails and administration screens, and one that differs by a capital letter is a role
    # that reads as assigned and is not.
    PATTERN = /\A[a-z][a-z0-9_]*\z/

    MAX_NAME_BYTES = 64

    getter name : String
    getter description : String

    # Permission names, not `Permission` values: the role definition names what it grants, and
    # `RoleCatalog` is what resolves those names against the registry — at boot, loudly.
    getter permissions : Set(String)

    def initialize(@name : String, permissions : Enumerable(String), @description : String = "")
      if @name.bytesize > MAX_NAME_BYTES
        raise ConfigurationError.new("role name is longer than #{MAX_NAME_BYTES} bytes")
      end

      unless PATTERN.matches?(@name)
        raise ConfigurationError.new(
          "role name #{@name.inspect} is not a lowercase identifier, e.g. finance_admin"
        )
      end

      @permissions = permissions.to_set
    end
  end

  # The roles this application defines, checked against the permissions it declares.
  #
  # ### Roles are code; only assignments are data
  #
  # The catalog is built at boot from literals in the application, and the database holds only
  # *who has which role*. It would have been easy to put the role-to-permission mapping in a
  # table too, and every general-purpose RBAC library does. This one does not, for two reasons.
  #
  # **A role definition in a table is a privilege-escalation surface.** An UPDATE — through an
  # injection, an over-permissive admin screen, a restored backup from before a permission was
  # tightened — silently rewrites what everybody holding that role can do, and nothing about
  # the application changed. In code the same change is a diff somebody reviews.
  #
  # **A missing permission becomes a boot failure instead of a mystery.** Renaming
  # `invoices.refund` and forgetting one role definition raises here, on the machine of
  # whoever made the change, rather than denying an action in production for a month.
  #
  # An application that genuinely needs roles administered at runtime is not blocked: it
  # implements `Authorizer` directly against its own tables. What it does not get is this
  # shard pretending that a mutable table of grants is the same security property as a
  # reviewed one.
  class RoleCatalog
    getter registry : PermissionRegistry

    def initialize(@registry : PermissionRegistry, roles : Enumerable(Role))
      @roles = {} of String => Role

      roles.each do |role|
        raise ConfigurationError.new("role #{role.name} is defined twice") if @roles.has_key?(role.name)

        role.permissions.each do |permission|
          next if @registry.declared?(permission)

          # At boot, by name, because the alternative is an action that is denied forever and
          # looks like it is working.
          raise ConfigurationError.new(
            "role #{role.name} grants #{permission.inspect}, which is not a declared permission"
          )
        end

        @roles[role.name] = role
      end
    end

    def []?(name : String) : Role?
      @roles[name]?
    end

    def defined?(name : String) : Bool
      @roles.has_key?(name)
    end

    def names : Array(String)
      @roles.keys.sort!
    end

    # Whether any of `role_names` grants `permission`.
    #
    # A name with no matching role contributes nothing. That is not an oversight: assignments
    # outlive the code that defined the role — somebody deletes `beta_tester` from the catalog
    # and the rows stay — and the safe reading of a role nobody defines is that it grants
    # nothing. `#undefined_roles` exists so an application can find those rows and clean them
    # up, rather than discovering them by their absence.
    def grants?(role_names : Enumerable(String), permission : String) : String?
      role_names.each do |name|
        role = @roles[name]?
        next if role.nil?

        return name if role.permissions.includes?(permission)
      end

      nil
    end

    # The names in `role_names` this catalog does not define. For a boot-time or nightly check
    # that assignments still refer to roles that exist.
    def undefined_roles(role_names : Enumerable(String)) : Array(String)
      role_names.reject { |name| @roles.has_key?(name) }.to_a
    end
  end
end
