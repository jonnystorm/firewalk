# Copyright © 2017 Jonathan Storm <jds@idio.link>
# This work is free. You can redistribute it and/or modify it under the
# terms of the Do What The Fuck You Want To Public License, Version 2,
# as published by Sam Hocevar. See the COPYING.WTFPL file for more details.

defmodule Firewalk do
  require Logger

  alias Firewalk.Cisco.ASA_8_3

  defp value_to_dot(value, group_name) do
    next_node =
      case value do
        {:object, v}        -> v
        {:group,  v}        -> v
        %NetAddr.IPv4{} = v -> to_string(v)
        %NetAddr.IPv6{} = v -> to_string(v)
                          _ -> nil
      end

    next_node
      && "  #{inspect group_name} -> #{inspect next_node};"
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

  defp split_egress_aces(aces, objects, routes) do
    Enum.flat_map(aces, fn ace ->
      case ace do
        %{source: {:group, name}} ->
          name
            |> ASA_8_3.split_by_interface(objects, routes)
            |> Enum.map(fn {if_, [source|_] = deps} ->
              source_ref = {:group, source.name}

              {%{ace|acl_name: "#{if_}-ingress", source: source_ref}, deps}
            end)

        %{source: source, destination: dest} when is_atom source ->
          routes
            |> Stream.map(& &1.interface)
            |> Stream.filter(& &1 != nil)
            |> Enum.uniq
            |> Enum.reduce([], fn
              # TODO: Also exclude interface to which egress ACL was applied.
              (if_, acc) when if_ in ~w(Null0 stateful failover) ->
                acc

              (if_, acc) ->
                [{%{ace|acl_name: "#{if_}-ingress", source: source}, []} | acc]
            end)

        %{source: source} ->
          if_ =
            source
              |> ASA_8_3.dereference(objects)
              |> ASA_8_3.get_interface(routes)

          [{%{ace|acl_name: "#{if_}-ingress"}, []}]

        ace ->
          [{ace, []}]
      end
    end)
  end

  defp split_tcp_udp_service_groups(objects) do
  end

  defp explode_aces_with_dm_inline_groups(aces, objects),
    do: Enum.flat_map(aces, &ASA_8_3.explode(&1, objects, "DM_INLINE_"))

  defp scrub_acl_remarks(aces) do
    Enum.map(aces, fn
      %{remark: remark} = acl_remark ->
        scrubbed = String.replace(remark, ~r/[^a-zA-Z\d\s]+/, "")

        %{acl_remark|remark: scrubbed}

      ace ->
        ace
    end)
  end

  defp merge_objects(objects, new_objects) do
    Enum.reduce(new_objects, objects, fn(new_object, acc) ->
      {_, new_acc} =
        OrderedMap.get_and_update(acc, new_object.name, fn
          nil ->
            {nil, new_object}

          ^new_object ->
            {nil, new_object}

          existing ->
            :ok = Logger.error("Unable to create new object while splitting ACE by interface:\n#{new_object}")
            :ok = Logger.error("Object #{new_object.name} already exists:\n#{existing}")

            existing
        end)

      new_acc
    end)
  end

  defp with_index_key(enum) do
    enum
      |> Stream.with_index(1)
      |> Stream.map(fn {e, i} -> {i, e} end)
  end

  defp append_ace_to_acl(%{acl_name: name} = ace, %{name: name} = acl) do
    next_seq = acl.aces.size + 1

    acl.aces
      |> OrderedMap.put(next_seq, ace)
      |> (&Map.put(acl, :aces, &1)).()
  end

  def split_egress_acl(asa, acl_name, routes) do
    acl = asa.acls[acl_name]

    {new_aces, new_objects} =
      acl.aces
        |> OrderedMap.values
        |> split_egress_aces(asa.objects, routes)
        |> Enum.map(fn {ace, deps} ->
          :ok =
            deps
              |> Enum.map(& "#{&1}")
              |> Enum.concat(["#{ace}"])
              |> Enum.join("\n")
              |> Logger.debug

          {ace, deps}
        end)
        |> Enum.unzip
        |> (fn {as, os} -> {as, List.flatten(os)} end).()

    next_objects = merge_objects(asa.objects, new_objects)

    new_aces
      |> Enum.reduce(asa, fn(ace, acc) ->
        if acc.acls[ace.acl_name] do
          ace
            |> append_ace_to_acl(acc.acls[ace.acl_name])
            |> (&OrderedMap.put(acc.acls, ace.acl_name, &1)).()
            |> (&Map.put(acc, :acls, &1)).()
        else
          acc
        end
      end)
      |> Map.put(:objects, next_objects)
  end

  def groom_acl(asa, acl_name) do
    asa.acls[acl_name].aces
      |> OrderedMap.values
      |> scrub_acl_remarks
      |> explode_aces_with_dm_inline_groups(asa.objects)
      |> with_index_key
      |> Enum.into(OrderedMap.new())
      |> (&Map.put(asa.acls[acl_name], :aces, &1)).()
      |> (&OrderedMap.put(asa.acls, acl_name, &1)).()
      |> (&Map.put(asa, :acls, &1)).()
  end

  def groom_acls(asa) do
    asa.acls
      |> OrderedMap.keys
      |> Enum.reduce(asa, &groom_acl(&2, &1))
  end

  #def groom_objects(asa) do
  #  asa.objects
  #    |> OrderedMap.keys
  #    |> Enum.reduce(asa, &groom_object(&2, &1))
  #end

  #def groom_nats(asa) do
  #  asa.nats
  #    |> Enum.reduce([], &groom_nat(&2, &1))
  #end

  def remove_acl(asa, acl_name) do
    asa.acls
      |> OrderedMap.delete(acl_name)
      |> (&Map.put(asa, :acls, &1)).()
  end
end
