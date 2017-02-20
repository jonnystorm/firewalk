defmodule Firewalk.Mixfile do
  use Mix.Project

  def project do
    [app: :firewalk,
     version: "0.1.4",
     elixir: "~> 1.4",
     build_embedded: Mix.env == :prod,
     start_permanent: Mix.env == :prod,
     deps: deps()]
  end

  def application do
    [applications: [:logger]]
  end

  defp deps do
    [ {      :frank, git: "https://github.com/jonnystorm/frank.git"},
      {:ordered_map, git: "https://github.com/jonnystorm/ordered-map-elixir.git"},
    ]
  end
end
