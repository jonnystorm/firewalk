defmodule Firewalk.Mixfile do
  use Mix.Project

  def project do
    [ app: :firewalk,
      version: "0.1.4",
      elixir: "~> 1.4",
      build_embedded: Mix.env == :prod,
      start_permanent: Mix.env == :prod,
      deps: deps(),
      dialyzer: [
        plt_add_apps: [
          :logger,
          :frank,
          :ordered_map,
          :poison,
        ],
        ignore_warnings: "dialyzer.ignore",
        flags: [
          :unmatched_returns,
          :error_handling,
          :race_conditions,
          :underspecs,
        ],
      ],
    ]
  end

  def application do
    [ applications: [
        :logger,
        :frank,
        :ordered_map,
        :poison,
      ],
    ]
  end

  defp deps do
    [ { :frank,
        git: "https://github.com/jonnystorm/frank.git"
      },
      { :ordered_map,
        git: "https://github.com/jonnystorm/ordered-map-elixir.git"
      },
      {:poison, "~> 3.1"},
    ]
  end
end
