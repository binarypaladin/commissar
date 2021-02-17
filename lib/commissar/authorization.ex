defmodule Commissar.Authorization do
  @moduledoc """
  Authorizers add a convient way of laying out policies in a manner that makes
  it easy to read. Defining policies in a module that uses
  `Commissar.Authorizer` also adds a catch-all policy that returns `:continue`,
  allowing your own policies to simply focus on `:ok` and `:error` responses.
  This carries over when exporting policies from other authorizers. Anonymous
  functions will need to explicitly return `:continue` if they do not `:ok`
  or `:error`.

  Keep in mind, if you just want to roll with anonymous functions or organize
  your policies in some other manner, it's completely possible to use
  `Commissar` without authorizers at all as long as the functions being being
  passed in conform to `Commissar.policy` type.
  """
  defmacro __using__(_) do
    quote do
      @behaviour unquote(__MODULE__)
      @before_compile unquote(__MODULE__)

      @doc """
      Similar to `authorize/3` but returns a boolean response instead. This
      should be used when you have no use for any potential denial reasons.
      """
      @spec allow?(any(), any(), any()) :: boolean()
      def allow?(subject, action, context) do
        Commissar.allow?(authorize(subject, action, context))
      end

      @doc """
      Checks to see whether a subject attempting an action is allowed to do so
      on a context with a given set of policies.
      """
      @spec authorize(any(), any(), any()) :: :ok | {:error | any()}
      def authorize(subject, action, context) do
        Commissar.authorize(subject, action, context, export_policies())
      end

      @doc """
      Exports a single policy from this authorizer to used as a policy in
      another.
      """
      def export_policy(policy_name),
        do: Commissar.export_policy(__MODULE__, policy_name)

      @doc """
      Exports _all_ policies from this authorizer for use in another.
      """
      def export_policies, do: Commissar.export_policies(__MODULE__)
    end
  end

  @doc """
  Adds a catch-all so you only need to define actual allows and denies.
  """
  defmacro __before_compile__(_) do
    quote do
      def policy(_name, _action, _subject, _context), do: :continue
    end
  end

  @doc """
  A policy definition taking a name (an atom that can be used by
  `export_policy/1`, and `policies/0`), an action, a subject, and a context.
  """
  @callback policy(atom(), any(), any(), any()) :: Commissar.policy_result()

  @doc """
  A list of policies in the form of either atoms or functions that will be
  authorized in order by `authorize/3`.
  """
  @callback policies() :: [atom() | [atom()] | Commissar.policy() | [Commissar.policy()]]

  @optional_callbacks [policy: 4]
end
