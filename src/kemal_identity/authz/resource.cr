module KemalIdentity::Authz
  # Something an authorization question can be *about*.
  #
  # ### Two methods, and never a third
  #
  # An authorizer needs to know what kind of thing this is and which one it is. From
  # `"invoice"` and `"42"` it can key a relationship lookup, consult an ownership table, or
  # serialise the question to a remote policy engine. An authorizer that wants the application's
  # actual object asks for it by type, and a wrong guess is `nil` rather than an exception:
  #
  # ```
  # invoice = context.resource.as?(Invoice)
  # return Forbidden.not_permitted(permission) if invoice.nil?
  # ```
  #
  # **This module is frozen at these two methods.** Adding a third `abstract def` after 1.0
  # would stop every implementor compiling — `abstract def Authorizable#x must be implemented
  # by Invoice` — and adding a *concrete* def would be worse: it compiles, but it injects a name
  # into every including class, and where that class already defines the name its own definition
  # wins. The build would stay green while the authorizer quietly read the application's meaning
  # of a name this shard chose.
  #
  # So nothing is added here. Everything an authorizer might later need travels on
  # `Authz::Context`, which this shard constructs and which injects nothing into anybody's
  # types. `spec/unit/authorizable_spec.cr` holds a fixture implementing exactly these two
  # methods, so a third one does not fail a test — it fails the suite's compilation.
  #
  # ### Why a module and not an abstract class
  #
  # Crystal has single inheritance, and an application's `Invoice` normally already descends
  # from an ORM model. A base class would make this unadoptable for exactly the applications
  # `docs/03-data-model.md` treats as the normal case. See
  # `blueprints/0022-authorization-context-and-denials.md`.
  module Authorizable
    # What kind of thing this is: `"invoice"`, `"document"`, `"repository"`.
    abstract def authz_type : String

    # Which one, as a string. The application's own identifier.
    abstract def authz_id : String
  end

  # The implementation this shard ships, for an application that will not add an `include` to
  # its models.
  #
  # ```
  # env.auth.authorize!(
  #   "invoices:edit",
  #   resource: KemalIdentity::Authz::Resource.new("invoice", invoice.id, {"owner_id" => invoice.owner_id}),
  # )
  # ```
  #
  # The route decides which attributes the policy needs, and that cost is deliberately visible:
  # a route that passes the wrong ones gets a denial rather than a wrong answer, because a
  # policy reading an attribute that is not there denies.
  struct Resource
    include Authorizable

    getter authz_type : String
    getter authz_id : String

    # Whatever the policy needs and cannot derive from the type and the id: an owner, a state,
    # a classification. Strings, so that this serialises to a remote policy engine unchanged.
    getter attributes : Hash(String, String)?

    def initialize(@authz_type : String, @authz_id : String, @attributes : Hash(String, String)? = nil)
      raise ArgumentError.new("authz_type must not be empty") if @authz_type.empty?
      raise ArgumentError.new("authz_id must not be empty") if @authz_id.empty?
    end

    # One attribute, or `nil`. A policy reading a missing attribute should deny rather than
    # assume, which is why this returns nil instead of raising.
    def [](key : String) : String?
      @attributes.try(&.[key]?)
    end
  end
end
