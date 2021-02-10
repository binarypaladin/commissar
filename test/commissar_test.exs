defmodule CommissarTest do
  use ExUnit.Case

  test "checks to see if subject is allowed action on context" do
    rules = [
      fn
        _, "read", {%{public_read: true}, _} -> :allow
        _, _, _ -> :continue
      end,
      fn
        %{disabled: true}, _, _ -> {:deny, :user_disabled}
        %{disabled: false}, _, _ -> :continue
        _, _, _ -> :deny
      end,
      fn _, action, {_, permissions} ->
        if Enum.member?(permissions, action), do: :allow, else: :continue
      end
    ]

    context = {%{public_read: false}, ["read"]}
    subject = %{disabled: false}

    assert Commissar.allow?(subject, "read", context, rules)
    assert Commissar.check(subject, "read", context, rules) == :allow

    refute Commissar.allow?(subject, "update", context, rules)
    assert Commissar.check(subject, "update", context, rules) == {:deny, :no_matching_rules}

    refute Commissar.allow?(%{disabled: true}, "read", context, rules)
    assert Commissar.check(%{disabled: true}, "read", context, rules) == {:deny, :user_disabled}

    refute Commissar.allow?(%{}, "read", context, rules)
    assert Commissar.check(%{}, "read", context, rules) == {:deny, :access_denied}

    public_context = {%{public_read: true}, []}

    assert Commissar.allow?(%{}, "read", public_context, rules)
    assert Commissar.check(%{}, "read", public_context, rules) == :allow

    refute Commissar.allow?(%{}, "update", public_context, rules)
    assert Commissar.check(%{}, "update", public_context, rules) == {:deny, :access_denied}
  end

  test "it exports a single rule from an authorizer" do
    check = Commissar.export_rule(Commissar.Test.UserAuthorizer, :is_active_user)

    assert check.(%{disabled: true}, nil, nil) == {:deny, :user_disabled}
    assert check.(%{disabled: false}, nil, nil) == :continue
  end

  test "it exports all rules from an authorizer" do
    rules = Commissar.export_rules(Commissar.Test.OwnerAuthorizer)

    assert Commissar.check(%{disabled: true}, "read", {%{}, []}, rules) ==
             {:deny, :user_disabled}

    assert Commissar.check(%{disabled: false}, "update", {%{}, ["full_control"]}, rules) ==
             :allow

    assert Commissar.check(%{id: 1, disabled: false}, "update", {%{owner_id: 1}, []}, rules) ==
             :allow
  end
end
