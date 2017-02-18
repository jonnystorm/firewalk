# Copyright © 2017 Jonathan Storm <jds@idio.link>
# This work is free. You can redistribute it and/or modify it under the
# terms of the Do What The Fuck You Want To Public License, Version 2,
# as published by Sam Hocevar. See the COPYING.WTFPL file for more details.

defmodule Firewalk do
  defp value_to_dot(value, group_name) do
    next_node =
      case value do
        v when is_binary(v) -> v
        %NetAddr.IPv4{} = v -> to_string(v)
                          _ -> nil
      end

    next_node
      && "  #{inspect group_name} -> #{inspect next_node}"
  end

  defp values_to_dot(values, group_name) do
    values
      |> Enum.reduce([], fn(value, acc) ->
        if dependency = value_to_dot(value, group_name) do
          [dependency|acc]
        else
          acc
        end
      end)
      |> Enum.reverse
  end

  def objects_to_dot(objects) do
    dot =
      objects
        |> Enum.reduce([], fn(object, acc) ->
          case object do
            %{name: name, values: values} ->
              [values_to_dot(values, name)|acc]

            _ ->
              acc
          end
        end)
        |> Enum.reverse
        |> List.flatten
        |> Enum.join("\n")

    ["digraph G {", dot, "}"] |> Enum.join("\n")
  end
end
