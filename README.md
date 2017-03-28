# Firewalk

An Elixir library for firewall configuration parsing and analysis.

## Installation

1. Add `firewalk` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [{:firewalk, git: "https://github.com/jonnystorm/firewalk.git"}]
end
```

2. Ensure `firewalk` is started before your application:

```elixir
def application do
  [applications: [:firewalk]]
end
```

