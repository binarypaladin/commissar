defmodule CommissarTest do
  use ExUnit.Case

  test "checks to see if subject is allowed action on context" do
    policies = [
      fn
        _, "read", {%{public_read: true}, _} -> :ok
        _, _, _ -> :continue
      end,
      fn
        %{disabled: true}, _, _ -> {:error, :user_disabled}
        %{disabled: false}, _, _ -> :continue
        _, _, _ -> :error
      end,
      fn _, action, {_, permissions} ->
        if Enum.member?(permissions, action), do: :ok, else: :continue
      end
    ]

    context = {%{public_read: false}, ["read"]}
    subject = %{disabled: false}

    assert Commissar.allow?(subject, "read", context, policies)
    assert Commissar.authorize(subject, "read", context, policies) == :ok

    refute Commissar.allow?(subject, "update", context, policies)

    assert Commissar.authorize(subject, "update", context, policies) ==
             {:error, :no_matching_policy}

    refute Commissar.allow?(%{disabled: true}, "read", context, policies)

    assert Commissar.authorize(%{disabled: true}, "read", context, policies) ==
             {:error, :user_disabled}

    refute Commissar.allow?(%{}, "read", context, policies)
    assert Commissar.authorize(%{}, "read", context, policies) == {:error, :access_denied}

    public_context = {%{public_read: true}, []}

    assert Commissar.allow?(%{}, "read", public_context, policies)
    assert Commissar.authorize(%{}, "read", public_context, policies) == :ok

    refute Commissar.allow?(%{}, "update", public_context, policies)

    assert Commissar.authorize(%{}, "update", public_context, policies) ==
             {:error, :access_denied}
  end

  test "it exports a single policy from an authorizer" do
    policy = Commissar.export_policy(Commissar.Test.UserAuthorizer, :is_active_user)

    assert policy.(%{disabled: true}, nil, nil) == {:error, :user_disabled}
    assert policy.(%{disabled: false}, nil, nil) == :continue
  end

  test "it exports all policies from an authorizer" do
    policies = Commissar.export_policies(Commissar.Test.OwnerAuthorizer)

    assert Commissar.authorize(%{disabled: true}, "read", {%{}, []}, policies) ==
             {:error, :user_disabled}

    assert Commissar.authorize(%{disabled: false}, "update", {%{}, ["full_control"]}, policies) ==
             :ok

    assert Commissar.authorize(
             %{id: 1, disabled: false},
             "update",
             {%{owner_id: 1}, []},
             policies
           ) == :ok
  end
end
