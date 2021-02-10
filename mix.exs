defmodule Commissar.MixProject do
  use Mix.Project

  def project do
    [
      app: :commissar,
      version: "0.1.0",
      elixir: "~> 1.10",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  def application, do: [applications: []]

  defp deps do
    [
      {:dialyxir, "~> 1.0", only: [:dev], runtime: false}
    ]
  end
end
