require "../spec_helper"

# `blueprints/0022-authorization-context-and-denials.md` decision 2 freezes `Authorizable` at
# two abstract defs, and the reason it can be frozen by *this file* rather than by review is
# that a third one would not fail an example — it would stop the suite compiling:
#
#     Error: abstract `def Authorizable#authz_tenant()` must be implemented by MinimalResource
#
# So this fixture is the guard. It implements exactly the two methods the module declares and
# nothing else. Adding a member to the module breaks the build here, deliberately.
private class MinimalResource
  include KemalIdentity::Authz::Authorizable

  def authz_type : String
    "thing"
  end

  def authz_id : String
    "1"
  end
end

# The other half of the promise: a *struct* can carry the module too. Crystal has single
# inheritance and an application's model usually already has a superclass, which is why this is
# a module and not an abstract class.
private struct MinimalStructResource
  include KemalIdentity::Authz::Authorizable

  def authz_type : String
    "folder"
  end

  def authz_id : String
    "f9"
  end
end

describe KemalIdentity::Authz::Authorizable do
  it "is satisfied by implementing exactly two methods" do
    resource = MinimalResource.new

    resource.authz_type.should eq("thing")
    resource.authz_id.should eq("1")
  end

  it "can be included by a struct as well as a class" do
    KemalIdentity::Authz::Context.new(resource: MinimalStructResource.new)
      .resource.try(&.authz_type).should eq("folder")
  end

  # What an authorizer does when it wants the application's own object rather than its name.
  # A wrong guess is nil, not an exception, so a policy denies instead of raising a 500.
  it "recovers the concrete type, and yields nil for the wrong one" do
    context = KemalIdentity::Authz::Context.new(resource: MinimalResource.new)

    context.resource.as?(MinimalResource).should_not be_nil
    context.resource.as?(MinimalStructResource).should be_nil
  end
end

describe KemalIdentity::Authz::Resource do
  it "names its type and id" do
    resource = KemalIdentity::Authz::Resource.new("invoice", "42")

    resource.authz_type.should eq("invoice")
    resource.authz_id.should eq("42")
  end

  it "refuses an empty type or id" do
    expect_raises(ArgumentError) { KemalIdentity::Authz::Resource.new("", "42") }
    expect_raises(ArgumentError) { KemalIdentity::Authz::Resource.new("invoice", "") }
  end

  # A policy reading an attribute that was not passed should deny, not raise. The route decides
  # which attributes the policy needs, and getting that wrong must fail closed.
  it "answers nil for an attribute that was not supplied" do
    resource = KemalIdentity::Authz::Resource.new("invoice", "42", {"owner_id" => "ali"})

    resource["owner_id"].should eq("ali")
    resource["state"].should be_nil
    KemalIdentity::Authz::Resource.new("invoice", "42")["owner_id"].should be_nil
  end
end

describe KemalIdentity::Authz::Context do
  it "carries nothing by default" do
    context = KemalIdentity::Authz::Context.new

    context.tenant_id.should be_nil
    context.resource.should be_nil
    context.attributes.should be_nil
  end

  # The credential is deliberately absent: `Principal#credential` is the single source, and a
  # copy here is what made the tenant-only `decide` overload skip scope attenuation while it
  # existed. See the note in `Authz::Context`.
  it "does not carry the credential" do
    KemalIdentity::Authz::Context.new.responds_to?(:credential).should be_false
  end

  it "answers nil for an environment attribute that was not supplied" do
    context = KemalIdentity::Authz::Context.new(attributes: {"device" => "managed"})

    context["device"].should eq("managed")
    context["region"].should be_nil
  end
end
