defmodule Commissar.Authorizer do
  @moduledoc """
  Authorizers add a convient way of laying out rules in a manner that makes it
  easy to read. Defining rules in a module that uses `Commissar.Authorizer` also
  adds a catch-all rule that returns `:continue`, allowing your own rules to
  simply focus on `:allow` and `:deny` responses. This carries over when
  exporting rules from other authorizers. Anonymous functions will need to
  explicitly return `:continue` if they do not `:allow` or `:deny`.

  Keep in mind, if you just want to roll with anonymous functions or organize
  your rules in some other manner, it's completely possible to use `Commissar`
  without authorizers at all as long as the functions being being passed in
  conform to `Commissar.rule` type.
  """
  defmacro __using__(_) do
    quote do
      @behaviour unquote(__MODULE__)
      @before_compile unquote(__MODULE__)

      @doc """
      Similar to `check/3` but returns a boolean response instead. This should
      be used when you have no use for any potential denial reasons.
      """
      @spec allow?(any(), any(), any()) :: boolean()
      def allow?(subject, context, action) do
        Commissar.allow?(check(subject, context, action))
      end

      @doc """
      Checks to see whether a subject attempting an action is allowed to do so
      on a context with a given set of rules.
      """
      @spec check(any(), any(), any()) :: :allow | {:deny | any()}
      def check(subject, context, action) do
        Commissar.check(subject, context, action, export_rules())
      end

      @doc """
      Exports a single rule from this authorizer to used as a rule in another.
      """
      def export_rule(rule_name), do: Commissar.export_rule(__MODULE__, rule_name)

      @doc """
      Exports _all_ rules from this authorizer for use in another.
      """
      def export_rules, do: Commissar.export_rules(__MODULE__)
    end
  end

  @doc """
  Adds a catch-all so you only need to define actual allows and denies.
  """
  defmacro __before_compile__(_) do
    quote do
      def rule(name, _action, _subject, _context) when is_atom(name), do: :continue
    end
  end

  @doc """
  A rule definition taking a name (an atom that can be used by `export_rule/1`,
  and `rules/0`), an action, a subject, and a context.
  """
  @callback rule(atom(), any(), any(), any()) :: Commissar.rule_result()

  @doc """
  A list of rules in the form of either atoms or functions that will be checked
  in order by `check/3`.
  """
  @callback rules() :: [atom() | [atom()] | Commissar.rule() | [Commissar.rule()]]

  @optional_callbacks [rule: 4]
end
