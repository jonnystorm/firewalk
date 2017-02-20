# Copyright © 2017 Jonathan Storm <jds@idio.link>
# This work is free. You can redistribute it and/or modify it under the
# terms of the Do What The Fuck You Want To Public License, Version 2,
# as published by Sam Hocevar. See the COPYING.WTFPL file for more details.

defmodule Firewalk.Cisco.ASA_8_3 do
  require Logger

  alias Firewalk.Cisco.ASA_8_3.Grammar

  defmodule Interface do
    defstruct      id: nil,
                 vlan: nil,
               nameif: nil,
       security_level: nil,
           ip_address: nil,
      standby_address: nil,
          description: nil

    @type vlan_id :: 1..4094

    @type t :: %__MODULE__{
                   id: String.t,
                 vlan: nil | vlan_id,
               nameif: nil | String.t,
       security_level: 0..100,
           ip_address: NetAddr.t,
      standby_address: nil | NetAddr.t,
          description: nil | String.t

    }
  end

  defmodule NetworkObject do
    defstruct name: nil, value: nil, description: nil

    @type t :: %__MODULE__{
             name: String.t,
            value: {nil | :v4 | :v6, URI.t}
                 | NetAddr.t
                 | {NetAddr.t, NetAddr.t},
      description: nil | String.t,
    }
  end

  defmodule ServiceObject do
    defstruct name: nil,
          protocol: nil,
            source: nil,
       destination: nil,
       description: nil

    @type   port_num :: 1..65535
    @type  icmp_type :: 0..255
    @type   ip_proto :: 0..255
    @type port_match :: {:eq | :gt | :lt | :neq, port_num}
                      | {:range, port_num, port_num}
                      | icmp_type

    @type t :: %__MODULE__{
             name: nil | String.t,
         protocol: ip_proto | :tcp_udp,
           source: nil | port_match,
      destination: nil | port_match,
      description: nil | String.t,
    }
  end

  defmodule NetworkGroup do
    defstruct name: nil, values: nil, description: nil

    @type object_or_group_ref :: {:object | :group, String.t}

    @type t :: %__MODULE__{
             name: String.t,
           values: [NetAddr.t | object_or_group_ref],
      description: nil | String.t,
    }
  end

  defmodule AbsoluteTimeRange do
    defstruct name: nil, start: nil, end: nil

    @type t :: %__MODULE__{
       name: String.t,
      start: nil | NaiveDateTime.t,
        end: nil | NaiveDateTime.t,
    }
  end

  defmodule PeriodicTimeRange do
    defstruct name: nil, days: nil, from: nil, to: nil

    @type day_of_week :: 1..7

    @type t :: %__MODULE__{
      name: String.t,
      days: :daily | :weekdays | :weekend | [day_of_week],
      from: Time.t,
        to: Time.t,
    }
  end

  defmodule ICMPGroup do
    defstruct name: nil, values: nil, description: nil

    @type icmp_type :: 0..255
    @type group_ref :: {:group, String.t}

    @type t :: %__MODULE__{
             name: String.t,
           values: [icmp_type | group_ref],
      description: nil | String.t,
    }
  end

  defmodule ServiceProtocolGroup do
    defstruct name: nil, protocol: nil, values: nil, description: nil

    @type   port_num :: 1..65535
    @type port_match :: {:eq, port_num}
                      | {:range, port_num, port_num}

    @type t :: %__MODULE__{
             name: String.t,
         protocol: :tcp | :udp | :tcp_udp,
           values: [port_match],
      description: nil | String.t,
    }
  end

  defmodule ServiceGroup do
    defstruct name: nil, values: nil, description: nil

    @type      service_object :: Firewalk.Cisco.ASA.ServiceObject.t
    @type object_or_group_ref :: {:object | :group, String.t}

    @type t :: %__MODULE__{
             name: String.t,
           values: [service_object | object_or_group_ref],
      description: nil | String.t,
    }
  end

  defmodule ProtocolGroup do
    defstruct name: nil, values: nil, description: nil

    @type  ip_proto :: 0..255
    @type group_ref :: {:group, String.t}

    @type t :: %__MODULE__{
             name: String.t,
           values: [ip_proto | group_ref],
      description: nil | String.t,
    }
  end

  defmodule StaticGlobalNAT do
    defstruct    real_if: nil,
               mapped_if: nil,
              after_auto: nil,
             real_source: nil,
           mapped_source: nil,
        real_destination: nil,
      mapped_destination: nil,
                     dns: nil,
                 service: nil,
              net_to_net: nil,
          unidirectional: nil,
            no_proxy_arp: nil,
            route_lookup: nil,
                inactive: nil,
             description: nil

    @type t :: %__MODULE__{
                 real_if: nil | String.t,
               mapped_if: nil | String.t,
              after_auto: boolean,
             real_source: String.t,
           mapped_source: String.t | {:interface, nil | :ipv6},
        real_destination: nil | String.t,
      mapped_destination: nil | String.t | {:interface, nil | :ipv6},
                     dns: boolean,
                 service: nil | {String.t, String.t},
              net_to_net: boolean,
          unidirectional: boolean,
            no_proxy_arp: boolean,
            route_lookup: boolean,
                inactive: boolean,
             description: nil | String.t,
    }
  end

  defmodule StaticObjectNAT do
    defstruct    real_if: nil,
               mapped_if: nil,
             real_source: nil,
           mapped_source: nil,
              net_to_net: nil,
                     dns: nil,
            no_proxy_arp: nil,
            route_lookup: nil,
                protocol: nil,
               real_port: nil,
             mapped_port: nil

    @type port_num :: 1..65535

    @type t :: %__MODULE__{
                 real_if: nil | String.t,
               mapped_if: nil | String.t,
             real_source: String.t,
           mapped_source: NetAddr.t | String.t | {:interface, nil | :ipv6},
              net_to_net: boolean,
                     dns: boolean,
            no_proxy_arp: boolean,
            route_lookup: boolean,
                protocol: :tcp | :udp,
               real_port: port_num,
             mapped_port: port_num,
    }
  end

  defmodule DynamicGlobalNAT do
    defstruct    real_if: nil,
               mapped_if: nil,
              after_auto: nil,
             real_source: nil,
           mapped_source: nil,
                pat_pool: nil,
                extended: nil,
               interface: nil,
                    ipv6: nil,
                    flat: nil,
         include_reserve: nil,
             round_robin: nil,
        real_destination: nil,
      mapped_destination: nil,
                     dns: nil,
                 service: nil,
              net_to_net: nil,
                inactive: nil,
             description: nil

    @type t :: %__MODULE__{
                 real_if: nil | String.t,
               mapped_if: nil | String.t,
              after_auto: boolean,
             real_source: String.t | :any,
           mapped_source: nil | String.t,
                pat_pool: boolean,
                extended: boolean,
               interface: boolean,
                    ipv6: boolean,
                    flat: boolean,
         include_reserve: boolean,
             round_robin: boolean,
        real_destination: nil | String.t,
      mapped_destination: nil | String.t | {:interface, nil | :ipv6},
                     dns: boolean,
                 service: nil | {String.t, String.t},
              net_to_net: boolean,
                inactive: boolean,
             description: nil | String.t,
    }
  end

  defmodule DynamicObjectNAT do
    defstruct    real_if: nil,
               mapped_if: nil,
             real_source: nil,
           mapped_source: nil,
                pat_pool: nil,
                extended: nil,
                    flat: nil,
         include_reserve: nil,
             round_robin: nil,
               interface: nil,
                    ipv6: nil,
                     dns: nil

    @type t :: %__MODULE__{
                 real_if: nil | String.t,
               mapped_if: nil | String.t,
             real_source: String.t,
           mapped_source: nil | NetAddr.t | String.t,
                pat_pool: boolean,
                extended: boolean,
                    flat: boolean,
         include_reserve: boolean,
             round_robin: boolean,
               interface: boolean,
                    ipv6: boolean,
                     dns: boolean,
    }
  end

  defmodule StandardACE do
    defstruct acl_name: nil, action: nil, criterion: nil

    @type t :: %__MODULE__{
       acl_name: String.t,
         action: :permit | :deny,
      criterion: NetAddr.t | :any4,
    }
  end

  defmodule ExtendedACE do
    defstruct acl_name: nil,
                action: nil,
              protocol: nil,
                source: nil,
           source_port: nil,
           destination: nil,
      destination_port: nil,
                   log: nil,
             log_level: nil,
          log_interval: nil,
           log_disable: nil,
            time_range: nil,
              inactive: nil

    @type   ip_proto :: 0..255
    @type   port_num :: 1..65535
    @type  icmp_type :: 0..255
    @type port_match :: {:eq | :gt | :lt | :neq, port_num}
                      | {:range, port_num, port_num}

    @type src_or_dst_port :: port_match
                           | icmp_type
                           | {:object, String.t}
                           | {:group,  String.t}

    @type src_or_dst :: NetAddr.t
                      | {:object, String.t}
                      | {:group,  String.t}
                      | :any4
                      | :any6
                      | :any
                      | {:interface, String.t}

    @type t :: %__MODULE__{
              acl_name: String.t,
                action: :permit | :deny,
              protocol: ip_proto | String.t,
                source: src_or_dst,
           source_port: nil | src_or_dst_port,
           destination: src_or_dst,
      destination_port: nil | src_or_dst_port,
                   log: boolean,
             log_level: nil | 0..7,
          log_interval: nil | 1..600,
           log_disable: boolean,
            time_range: nil | String.t,
              inactive: boolean,
    }
  end

  defmodule ACLRemark do
    defstruct acl_name: nil, remark: nil

    @type t :: %__MODULE__{
      acl_name: String.t,
        remark: String.t,
    }
  end

  defmodule ACL do
    defstruct name: nil, aces: nil

    @type ace :: Firewalk.Cisco.ASA.StandardACE.t
               | Firewalk.Cisco.ASA.ExtendedACE.t

    @type remark :: Firewalk.Cisco.ASA.ACLRemark.t

    @type t :: %__MODULE__{
      name: String.t,
      aces: [ace | remark],
    }
  end

  defmodule Route do
    defstruct      type: nil,
      candidate_default: nil,
             replicated: nil,
            destination: nil,
         admin_distance: nil,
                 metric: nil,
               next_hop: nil,
            last_update: nil,
              interface: nil

    @type route_type :: :local
                      | :connected
                      | :static
                      | :rip
                      | :mobile
                      | :bgp
                      | :eigrp
                      | :eigrp_external
                      | :ospf
                      | :ospf_inter_area
                      | :ospf_nssa_external_type_1
                      | :ospf_nssa_external_type_2
                      | :ospf_external_type_1
                      | :ospf_external_type_2
                      | :is_is
                      | :is_is_summary
                      | :is_is_level_1
                      | :is_is_level_2
                      | :is_is_inter_area
                      | :per_user_static_route
                      | :odr
                      | :periodic_downloaded_static_route

    @type t :: %__MODULE__{
                   type: route_type,
      candidate_default: boolean,
             replicated: boolean,
            destination: NetAddr.t,
         admin_distance: 0..255,
                 metric: non_neg_integer,
               next_hop: NetAddr.t,
            last_update: nil | String.t,
              interface: nil | String.t,
    }
  end

  def icmp_types do
    [ {"alternate-address",      6},
      {"conversion-error",      31},
      {"echo",                   8},
      {"echo-reply",             0},
      {"information-reply",     16},
      {"information-request",   15},
      {"mask-reply",            18},
      {"mask-request",          17},
      {"mobile-redirect",       32},
      {"parameter-problem",     12},
      {"redirect",               5},
      {"router-advertisement",   9},
      {"router-solicitation",   10},
      {"source-quench",          4},
      {"time-exceeded",         11},
      {"timestamp-reply",       14},
      {"timestamp-request",     13},
      {"traceroute",            30},
      {"unreachable",            3},
    ]
  end

  def ip_protocols do
    [ {"ah",     51},
      {"eigrp",  88},
      {"esp",    50},
      {"gre",    47},
      {"icmp",    1},
      {"icmp6",  58},
      {"igmp",    2},
      {"igrp",    9},
      {"ip",      0},
      {"ipinip",  4},
      {"ipsec",  50},
      {"nos",    94},
      {"ospf",   89},
      {"pcp",   108},
      {"pim",   103},
      {"pptp",   45},
      {"snp",   109},
      {"tcp",     6},
      {"udp",    17},
    ]
  end

  def log_levels do
    [ {"alerts",        1},
      {"critical",      2},
      {"debugging",     7},
      {"emergencies",   0},
      {"errors",        3},
      {"informational", 6},
      {"notifications", 5},
      {"warnings",      4},
    ]
  end

  defp extract(term)
      when is_list(term), do: List.first term
  defp extract(term),     do: term

  defp copy(struct, atom, from: ast) when is_atom(atom),
    do: Map.put(struct, atom, extract(ast[atom]))

  defp copy(struct, atom, ast) when is_atom(atom),
    do: copy(struct, atom, from: ast)

  def address_mask_to_cidr(address, mask) do
    address = NetAddr.address address
       mask = NetAddr.address mask

    NetAddr.ip(address, mask)
  end

  def interface(ast) do
    ip_address =
      case ast[:ip_address][:ip_address] do
        [addr, mask] -> address_mask_to_cidr(addr, mask)
              [ipv6] -> ipv6
                 nil -> nil
      end

    %Interface{
                   id: extract(ast[:interface]),
                 vlan: extract(ast[:vlan]),
               nameif: extract(ast[:nameif]),
       security_level: extract(ast[:security_level]),
           ip_address: ip_address,
      standby_address: extract(ast[:address_line]),
    }
  end

  def network_object([{_, decl}|defs]) do
    def_ = extract defs[:net_obj_def]
    name = extract decl[:name]
    value =
      case extract(def_) do
                            nil -> nil
        {:fqdn,         [fqdn]} -> {nil, fqdn}
        {:fqdn,    [ver, fqdn]} -> {ver, fqdn}
        {:host,         [host]} -> host
        {:range, [first, last]} -> {first, last}
        {:subnet, [addr, mask]} -> address_mask_to_cidr(addr, mask)
        {:subnet,       [ipv6]} -> ipv6
      end

    %NetworkObject{}
      |> Map.put(:name, name)
      |> Map.put(:value, value)
      |> set_description(defs)
  end

  defp port_match_ast_to_model(nil),                   do: nil
  defp port_match_ast_to_model([{op,        [port]}]), do: {op, port}
  defp port_match_ast_to_model([{op, [first, last]}]), do: {op, first, last}

  def service_object([{_, decl}|defs]) do
    def_ = defs[:svc_obj_def]

    %ServiceObject{}
      |> Map.put(:name,     extract(decl[:name]))
      |> Map.put(:protocol, extract(def_[:protocol]))
      |> Map.put(:source,      port_match_ast_to_model(def_[:source]))
      |> Map.put(:destination, port_match_ast_to_model(def_[:destination]))
      |> set_description(defs)
  end

  defp _time_range(name, [{:type, :absolute}|_] = ast) do
    [stime, sday, smonth, syear] = ast[:start]
    [etime, eday, emonth, eyear] = ast[:end]

    [shr, smin] = String.split(stime, ":")
    [ehr, emin] = String.split(etime, ":")

    {:ok, start} = NaiveDateTime.new(syear, smonth, sday, shr, smin, 0)
    {:ok,  end_} = NaiveDateTime.new(eyear, emonth, eday, ehr, emin, 0)

     %AbsoluteTimeRange{
        name: name,
       start: start,
         end: end_,
     }
  end

  defp _time_range(name, [{:type, :periodic}|_] = ast) do
    days =
      case ast[:days] do
        [t] -> t
         t  -> Enum.sort(t)
      end

    [fhr_str, fmin_str] = String.split extract(ast[:from]), ":"
    [thr_str, tmin_str] = String.split extract(ast[:to]), ":"
    [fhr, fmin, thr, tmin] =
      [fhr_str, fmin_str, thr_str, tmin_str]
        |> Enum.map(&String.to_integer/1)

    {:ok, from} = Time.new(fhr, fmin, 0)
    {:ok,   to} = Time.new(thr, tmin, 0)

    %PeriodicTimeRange{
      name: name,
      days: days,
      from: from,
        to: to,
    }
  end

  def time_range([{_, decl}|[{_, def_}]]) do
    name = extract decl[:name]

    _time_range(name, def_)
  end

  def icmp_group([{_, decl}|defs]) do
    {description, defs} = Keyword.pop defs, :description

    values = Enum.map(defs, fn
      {:group_ref, [term] } -> {:group,  term}
      {_, [object: [term]]} -> {:object, term}
      {_,          [term] } -> term
    end)

    %ICMPGroup{}
      |> Map.put(:name, extract(decl[:name]))
      |> Map.put(:values, values)
      |> set_description([description: description])
  end

  def network_group([{_, decl}|defs]) do
    {description, defs} = Keyword.pop defs, :description

    values =
      Enum.map(defs, fn
        {:group_ref, [group]} ->
          {:group, group}

        {_, v} ->
        case v do
          [object: [term]] -> {:object, term}
             [addr, mask]  -> address_mask_to_cidr(addr, mask)
                   [term]  -> term
        end
      end)

    %NetworkGroup{}
      |> Map.put(:name, extract(decl[:name]))
      |> Map.put(:values, values)
      |> set_description([description: description])
  end

  def service_protocol_group([{_, decl}|defs]) do
    {description, defs} = Keyword.pop defs, :description

    values = Enum.map(defs, fn
      {:group_ref, [group]} -> {:group, group}
      {         _,     ast} -> port_match_ast_to_model(ast)
    end)

    %ServiceProtocolGroup{}
      |> Map.put(:name, extract(decl[:name]))
      |> Map.put(:protocol, extract(decl[:protocol]))
      |> Map.put(:values, values)
      |> set_description([description: description])
  end

  def service_group([{_, decl}|defs]) do
    {description, defs} = Keyword.pop defs, :description

    values =
      Enum.map(defs, fn
        {:group_ref, [group]} ->
          {:group, group}

        {_, ast} ->
          %ServiceObject{
               protocol: extract(ast[:protocol]),
                 source: port_match_ast_to_model(ast[:source]),
            destination: port_match_ast_to_model(ast[:destination]),
          }
      end)

    %ServiceGroup{}
      |> Map.put(:name, extract(decl[:name]))
      |> Map.put(:values, values)
      |> set_description([description: description])
  end

  def protocol_group([{_, decl}|defs]) do
    {description, defs} = Keyword.pop defs, :description

    values = Enum.map(defs, fn
      {:group_ref, [group]} -> {:group, group}
      {         _,     ast} -> extract(ast)
    end)

    %ProtocolGroup{}
      |> Map.put(:name, extract(decl[:name]))
      |> Map.put(:values, values)
      |> set_description([description: description])
  end

  defp sort_by_string_length_desc(strings) when is_list(strings),
    do: Enum.sort_by(strings, &String.length/1, &>=/2)

  defp strings_to_regex_choice(strings) when is_list(strings) do
    strings
      |> sort_by_string_length_desc
      |> Enum.map(&Regex.escape/1)
      |> Enum.join("|")
      |> Regex.compile!
  end

  defp extract_nameifs(nil, _),         do: {nil, nil}
  defp extract_nameifs(ifpair, nameifs) do
    pattern = strings_to_regex_choice ["any"|nameifs]

    ifpair = String.replace(ifpair, ~r/\(|\)/, "")

    case Regex.split(pattern, ifpair, include_captures: true) do
      ["", real_if, ",", mapped_if, ""] ->
        {real_if, mapped_if}

      _ ->
        raise "Unable to match interface pair #{inspect ifpair} with interfaces #{inspect nameifs}."
    end
  end

  defp extract_mapped(ast) do
    case ast[:mapped] do
                         nil -> nil
               [pat_pool: _] -> nil
      [   object:  [object]] -> object
      [interface:        []] -> {:interface, nil}
      [interface: [ipv6: _]] -> {:interface, :ipv6}
                        [ip] -> [ip]
    end
  end

  defp extract_static_nat(nil), do: {nil, nil}
  defp extract_static_nat(ast) do
    real = extract(ast[:real][:object])

    mapped = extract_mapped ast

    {real, mapped}
  end

  defp set_nat_interfaces(struct, ast, nameifs) do
    {real, mapped} =
      ast[:interfaces]
        |> extract
        |> extract_nameifs(nameifs)

    %{struct|real_if: real, mapped_if: mapped}
  end

  defp set_global_nat_destination(struct, ast) do
    {real, mapped} = extract_static_nat ast[:destination]

    %{struct|real_destination: real, mapped_destination: mapped}
  end

  defp set_global_nat_service(struct, ast) do
    service =
      case ast[:service] || ast[:destination][:service] do
        [{:object, [real]}, {:object, [mapped]}] ->
          {real, mapped}

        _ ->
          nil
      end

    %{struct|service: service}
  end

  defp set_description(struct, ast) do
    value = ast[:description]
    description = value && Enum.join(value, " ") || nil

    %{struct|description: description}
  end

  defp set_flag(struct, ast, atom) when is_atom(atom) do
    current = Map.get(struct, atom)
     target = ast[atom] != nil

    %{struct|atom => current || target || false}
  end

  def static_global_nat([{_, ast}], nameifs) do
    {real_source, mapped_source} = extract_static_nat ast[:source]

    %StaticGlobalNAT{}
      |> set_nat_interfaces(ast, nameifs)
      |> set_flag(ast, :after_auto)
      |> Map.put(:real_source, real_source)
      |> Map.put(:mapped_source, mapped_source)
      |> set_global_nat_destination(ast)
      |> set_flag(ast, :dns)
      |> set_global_nat_service(ast)
      |> set_flag(ast[:destination], :net_to_net)
      |> set_flag(ast, :unidirectional)
      |> set_flag(ast, :no_proxy_arp)
      |> set_flag(ast, :route_lookup)
      |> set_flag(ast, :inactive)
      |> set_description(ast)
  end

  defp set_object_nat_service(struct, ast) do
    case ast[:service] do
      [protocol, real: real, mapped: mapped] ->
        %{struct |
          protocol: protocol,
          real_port: real,
          mapped_port: mapped
        }

      _ ->
        struct
    end
  end

  def static_object_nat([{_, decl}, {_, def_}], nameifs) do
    mapped_source = extract_mapped def_

    %StaticObjectNAT{}
      |> set_nat_interfaces(def_, nameifs)
      |> Map.put(:real_source, extract(decl[:name]))
      |> Map.put(:mapped_source, mapped_source)
      |> set_flag(def_, :net_to_net)
      |> set_flag(def_, :dns)
      |> set_flag(def_, :no_proxy_arp)
      |> set_flag(def_, :route_lookup)
      |> set_object_nat_service(def_)
  end

  defp set_interface_nat(struct, ast) do
    struct
      |> set_flag(ast, :interface)
      |> set_flag(ast[:interface], :ipv6)
  end

  defp set_pat_pool(struct, ast) do
    pat_pool = ast[:pat_pool]

    mapped_source = struct.mapped_source
                 || pat_pool[:object]

    struct
      |> Map.put(:mapped_source, mapped_source)
      |> set_flag(ast, :pat_pool)
      |> set_flag(pat_pool, :extended)
      |> set_flag(pat_pool, :flat)
      |> set_flag(pat_pool, :include_reserve)
      |> set_flag(pat_pool, :round_robin)
      |> set_interface_nat(pat_pool)
  end

  def dynamic_global_nat([{_, ast}], nameifs) do
    real_source =
      case ast[:source][:real] do
        [object: [object]] -> object
                    [:any] -> :any
      end

    mapped_source = extract_mapped ast[:source]

    %DynamicGlobalNAT{}
      |> set_nat_interfaces(ast, nameifs)
      |> set_flag(ast, :after_auto)
      |> Map.put(:real_source, real_source)
      |> Map.put(:mapped_source, mapped_source)
      |> set_pat_pool(ast[:source][:mapped])
      |> set_global_nat_destination(ast)
      |> set_flag(ast, :dns)
      |> set_global_nat_service(ast)
      |> set_flag(ast[:destination], :net_to_net)
      |> set_flag(ast, :inactive)
      |> set_description(ast)
  end

  defp set_dynamic_object_nat_mapped(struct, ast) do
    mapped = ast[:mapped]

    mapped_source =
      case mapped do
        [pat_pool: _]           -> nil
        [{:object, [object]}|_] -> object
                         [ip|_] -> ip
      end

    struct
      |> Map.put(:mapped_source, mapped_source)
      |> set_interface_nat(mapped)
      |> set_flag(mapped, :dns)
  end

  def dynamic_object_nat([{_, decl}, {_, def_}], nameifs) do
    %DynamicObjectNAT{}
      |> Map.put(:real_source, extract(decl[:name]))
      |> set_nat_interfaces(def_, nameifs)
      |> set_dynamic_object_nat_mapped(def_)
  end

  def standard_ace(ast) do
    criterion =
      case ast[:criterion] do
        [ addr, mask] -> address_mask_to_cidr(addr, mask)
        [:host, ipv4] -> ipv4
                :any4 -> :any4
      end

    %StandardACE{}
      |> Map.put(:criterion, criterion)
      |> copy(:acl_name, from: ast)
      |> copy(:action, from: ast)
  end

  defp disambiguate_ace_criteria(criteria, objects) do
    case criteria do
      [protocol, source, {_, str} = u1, u2] when is_binary u1 ->
        case objects[str] do
          %NetworkObject{} ->
            [         protocol: protocol,
                        source: source,
                   source_port: nil,
                   destination: u1,
              destination_port: u2,
            ]

          %NetworkGroup{} ->
            [         protocol: protocol,
                        source: source,
                   source_port: nil,
                   destination: u1,
              destination_port: u2,
            ]

          _               ->
            [         protocol: protocol,
                        source: source,
                   source_port: u1,
                   destination: u2,
              destination_port: nil,
            ]
        end

      [protocol, source, {k, _} = u1, u2]
          when k in [:eq, :gt, :lt, :neq] ->
        [         protocol: protocol,
                    source: source,
               source_port: u1,
               destination: u2,
          destination_port: nil,
        ]

      [protocol, source, {:range, _, _} = u1, u2] ->
        [         protocol: protocol,
                    source: source,
               source_port: u1,
               destination: u2,
          destination_port: nil,
        ]

      [protocol, source, u1, u2] ->
        [         protocol: protocol,
                    source: source,
               source_port: nil,
               destination: u1,
          destination_port: u2,
        ]

      [protocol, source, sport, destination, dport] ->
        [         protocol: protocol,
                    source: source,
               source_port: sport,
               destination: destination,
          destination_port: dport,
        ]

      [protocol, source, destination] ->
        [         protocol: protocol,
                    source: source,
               source_port: nil,
               destination: destination,
          destination_port: nil,
        ]
    end
  end

  defp groom_ace_criteria(criteria) do
    Enum.map(criteria, fn criterion ->
      case criterion do
        [object:     [object]]   -> {:object, object}
        [group:      [object]]   -> {:group,  object}
        [eq:           [port]]   -> { :eq, port}
        [gt:           [port]]   -> { :gt, port}
        [lt:           [port]]   -> { :lt, port}
        [neq:          [port]]   -> {:neq, port}
        [range: [first, last]]   -> {:range, first, last}
        [icmp_type:    [type]]   -> {:icmp_type, type}
        [host:           [ip]]   -> ip
        [interface:  [nameif]]   -> {:interface, nameif}
                  [addr, mask]   -> address_mask_to_cidr(addr, mask)
                       [:any4]   -> :any4
                       [:any6]   -> :any6
                       [:any ]   -> :any
        [%NetAddr.IPv6{} = ipv6] -> ipv6
        [octet]
            when octet in 0..255 -> octet
      end
    end)
  end

  defp set_ace_criteria(struct, criteria) do
    Enum.reduce(criteria, struct, fn ({atom, value}, acc) ->
      %{acc | atom => value}
    end)
  end

  defp set_ace_log(struct, ast) do
    %{struct |
               log: ast[:log] != nil,
         log_level: extract(ast[:log][:level]),
      log_interval: extract(ast[:log][:interval]),
       log_disable: ast[:log][:disable] != nil
    }
  end

  defp set_ace_time_range(struct, ast),
    do: %{struct|time_range: extract(ast[:time_range])}

  def extended_ace(ast, objects) do
    criteria =
      ast
        |> Keyword.get_values(:ace_spec)
        |> groom_ace_criteria
        |> disambiguate_ace_criteria(objects)

    %ExtendedACE{}
      |> copy(:acl_name, from: ast)
      |> copy(:action, from: ast)
      |> set_ace_criteria(criteria)
      |> set_ace_log(ast)
      |> set_ace_time_range(ast)
      |> set_flag(ast, :inactive)
  end

  def acl_remark(ast) do
    %ACLRemark{}
      |> copy(:acl_name, from: ast)
      |> Map.put(:remark, Enum.join(ast[:remark], " "))
  end

  def acl([{_, head}|_] = aces, objects) do
    aces = Enum.map(aces, fn {type, ast} ->
        case type do
          :std_ace -> standard_ace(ast)
          :ext_ace -> extended_ace(ast, objects)
          :acl_rem -> acl_remark(ast)
        end
      end)

    %ACL{name: extract(head[:acl_name]), aces: aces}
  end

  defp set_route_type_and_flags(struct, ast) do
    pattern = ~r/^[LCSRMBDOiUoP]|EX|IA|N[12]|E[12]|su|L[12]|ia|\*|\+$/

    codes = Regex.split(pattern, Enum.join(ast[:code]), include_captures: true)

    candidate_default = "*" in codes
           replicated = "+" in codes

    type =
      case Enum.filter(codes, & &1 =~ ~r/^[^\*\+]+$/) do
        ~w(L)    -> :local
        ~w(C)    -> :connected
        ~w(S)    -> :static
        ~w(R)    -> :rip
        ~w(M)    -> :mobile
        ~w(B)    -> :bgp
        ~w(D)    -> :eigrp
        ~w(D EX) -> :eigrp_external
        ~w(O)    -> :ospf
        ~w(O IA) -> :ospf_inter_area
        ~w(O N1) -> :ospf_nssa_external_type_1
        ~w(O N2) -> :ospf_nssa_external_type_2
        ~w(O E1) -> :ospf_external_type_1
        ~w(O E2) -> :ospf_external_type_2
        ~w(i)    -> :is_is
        ~w(i su) -> :is_is_summary
        ~w(i L1) -> :is_is_level_1
        ~w(i L2) -> :is_is_level_2
        ~w(i ia) -> :is_is_inter_area
        ~w(U)    -> :per_user_static_route
        ~w(o)    -> :odr
        ~w(P)    -> :periodic_downloaded_static_route
      end

    %{struct |
      type: type,
      candidate_default: candidate_default,
      replicated: replicated,
    }
  end

  def route(ast) do
    network = extract ast[:network]
       mask = extract ast[:mask]

    destination = address_mask_to_cidr(network, mask)

    [ad, metric] =
      if metric_str = ast[:metric] do
        metric_str
          |> extract
          |> String.replace(~r{\[|\]}, "")
          |> String.split("/")
          |> Enum.map(&String.to_integer/1)
      else
        [0, 0]  # Assume connected route
      end

    %Route{}
      |> set_route_type_and_flags(ast)
      |> Map.put(:destination, destination)
      |> Map.put(:admin_distance, ad)
      |> Map.put(:metric, metric)
      |> copy(:next_hop, from: ast)
      |> copy(:last_update, from: ast)
      |> copy(:interface, from: ast)
  end

  defp aggregate_type({type1, _} = ast1, ast2) do
    type2 =
      case ast2 do
        {t, _} -> t
            _  -> nil
      end

    case {type1, type2} do
      {           :dyn_gbl_nat,             nil} -> :dynamic_global_nat
      {        :static_gbl_nat,             nil} -> :static_global_nat
      {          :net_obj_decl,    :dyn_obj_nat} -> :dynamic_object_nat
      {:dynamic_object_nat = t,             nil} -> t
      {          :net_obj_decl, :static_obj_nat} -> :static_object_nat
      { :static_object_nat = t,             nil} -> t
      {           :trange_decl,     :trange_def} -> :time_range
      {        :time_range = t,             nil} -> t
      {t1, t2} when (t1 in [:interface])
                and (t2 in [ :nameif,
                             :vlan,
                             :security_level,
                             :ip_address,
                             :description,
                             nil,
                           ])                    -> :interface
      {t1, t2} when (t1 in [:net_obj_decl, :network_object])
                and (t2 in [ :net_obj_def,
                             :description,
                             nil
                           ])                    -> :network_object
      {t1, t2} when (t1 in [:svc_obj_decl, :service_object])
                and (t2 in [ :svc_obj_def,
                             :description,
                             nil,
                           ])                    -> :service_object
      {t1, t2} when (t1 in [:icmp_grp_decl, :icmp_group])
                and (t2 in [ :icmp_grp_def,
                             :group_ref,
                             :description,
                             nil,
                           ])                    -> :icmp_group
      {t1, t2} when (t1 in [:net_grp_decl, :network_group])
                and (t2 in [ :net_grp_def,
                             :group_ref,
                             :description,
                             nil,
                           ])                    -> :network_group
      {t1, t2} when (t1 in [:svc_proto_grp_decl, :service_protocol_group])
                and (t2 in [ :svc_proto_grp_def,
                             :group_ref,
                             :description,
                             nil,
                           ])                    -> :service_protocol_group
      {t1, t2} when (t1 in [:svc_grp_decl, :service_group])
                and (t2 in [ :svc_grp_def,
                             :group_ref,
                             :description,
                             nil,
                           ])                    -> :service_group
      {t1, t2} when (t1 in [:proto_grp_decl, :protocol_group])
                and (t2 in [ :proto_grp_def,
                             :group_ref,
                             :description,
                             nil,
                           ])                    -> :protocol_group

      {t1, t2} when (t1 in [:std_ace, :ext_ace, :acl_rem, :acl])
                and (t2 in [:std_ace, :ext_ace, :acl_rem, nil]) ->
        case {ast1, ast2} do
          {{       _,            _},                      nil} -> :acl
          {{       t, [name_ast|_]}, {       t, [name_ast|_]}} -> :acl
          {{       _, [name_ast|_]}, {:acl_rem, [name_ast|_]}} -> :acl
          {{:acl_rem, [name_ast|_]}, {       _, [name_ast|_]}} -> :acl
          {{    :acl, [{_, ace}|_]}, {       _, [name_ast|_]}} ->
            if {:acl_name, ace[:acl_name]} == name_ast do
              :acl
            else
              nil
            end

          _ -> nil
        end

      _ -> nil
    end
  end

  defp accrete_model(       model, nil), do: model
  defp accrete_model({type, asts}, ast), do: {type, [ast|asts]}

  defp lines_into_models({type, sub_asts} = ast1, ast2) do
    case aggregate_type(ast1, ast2) do
      nil      ->
        case aggregate_type(ast1, nil) do
          nil   ->
            :ok = Logger.warn("Unable to aggregate line: #{inspect sub_asts}")

            {nil, ast2}

          ^type ->
            {{type, Enum.reverse(sub_asts)}, ast2}

          agg_type ->
            {{agg_type, [ast1]}, ast2}
        end

      ^type    ->
        if ast2 != nil do
          {nil, accrete_model(ast1, ast2)}
        else
          {{type, Enum.reverse(sub_asts)}, nil}
        end

      agg_type ->
        {nil, accrete_model({agg_type, [ast1]}, ast2)}
    end
  end

  def _aggregate([one], acc, fun) do
    case fun.(one, nil) do
      {nil, nil} ->
        Enum.reverse(acc)

      {agg, nil} ->
        Enum.reverse [agg|acc]

      {nil, agg} ->
        {last, nil} = fun.(agg, nil)

        Enum.reverse [last|acc]
    end
  end

  def _aggregate([one, two|rest], acc, fun) do
    case fun.(one, two) do
      {nil, agg} ->
        _aggregate([agg|rest], acc, fun)

      {agg, new} ->
        _aggregate([new|rest], [agg|acc], fun)
    end
  end

  def aggregate(list, fun) when is_list(list) and is_function(fun),
    do: _aggregate(list, [], fun)

  def parse_line(line, grammar) when is_binary line do
    case Frank.parse(line, grammar) do
      {:ok, [root: [ast]]} ->
        ast

      {:error, :nomatch, _} ->
        :ok = Logger.warn("Unmatched line: #{inspect line}")

        nil
    end
  end

  defp parse_lines(stream, grammar) do
    stream
      |> Stream.map(&parse_line(&1, grammar))
      |> Stream.filter(fn nil -> false; x -> x end)
  end

  defp interface_model_to_struct({:interface, ast}),
    do: interface ast

  defp object_model_to_struct({name, ast}) do
    %{        network_object: &network_object/1,
                net_obj_decl: &network_object/1,
              service_object: &service_object/1,
                svc_obj_decl: &service_object/1,
                  time_range: &time_range/1,
                  icmp_group: &icmp_group/1,
               network_group: &network_group/1,
      service_protocol_group: &service_protocol_group/1,
               service_group: &service_group/1,
              protocol_group: &protocol_group/1,
    }[name].(ast)
  end

  defp nat_model_to_struct({name, ast}, nameifs) do
    %{     static_global_nat:  &static_global_nat(&1, nameifs),
           static_object_nat:  &static_object_nat(&1, nameifs),
          dynamic_global_nat: &dynamic_global_nat(&1, nameifs),
          dynamic_object_nat: &dynamic_object_nat(&1, nameifs),
    }[name].(ast)
  end

  defp acl_model_to_struct({:acl, ast}, objects),
    do: acl(ast, objects)

  defp model_type({name, _}) do
    case name do
      :acl                -> :acl
      :interface          -> :interface
      :static_global_nat  -> :nat
      :static_object_nat  -> :nat
      :dynamic_global_nat -> :nat
      :dynamic_object_nat -> :nat
                        _ -> :object
    end
  end

  def parse(lines) do
    models =
      lines
        |> Stream.map(&String.trim/1)
        |> parse_lines(Grammar.asa_command)
        |> Enum.to_list
        |> aggregate(&lines_into_models/2)
        |> Enum.group_by(&model_type/1)

       acl_models = models[:acl]       || []
       nat_models = models[:nat]       || []
    object_models = models[:object]    || []
        if_models = models[:interface] || []

    interfaces = Enum.map(if_models, &interface_model_to_struct/1)

    nameifs =
      interfaces
        |> Enum.map(& &1.nameif)
        |> Enum.filter(& &1 != nil)

    nats = Enum.map(nat_models, &nat_model_to_struct(&1, nameifs))

    objects =
      object_models
        |> Stream.map(&object_model_to_struct/1)
        |> Stream.map(& {&1.name, &1})
        |> Enum.into(OrderedMap.new)

    acls =
      acl_models
        |> Stream.map(&acl_model_to_struct(&1, objects))
        |> Stream.map(& {&1.name, &1})
        |> Enum.into(OrderedMap.new)

    %{      acls: acls,
            nats: nats,
         objects: objects,
      interfaces: interfaces,
    }
  end

  defp _join_split_routes([], [], acc),
    do: Enum.reverse acc

  defp _join_split_routes([], [line], acc),
    do: Enum.reverse [line|acc]

  defp _join_split_routes([line|rest], tmp, acc) do
    cond do
      line =~ ~r|^\[| ->
        case tmp do
          [start] ->
            joined = Enum.join([start, line], " ")

            _join_split_routes(rest, [], [joined|acc])

          [] ->
            :ok = Logger.error("Detected split route but found no mate: #{inspect line}")

            _join_split_routes(rest, [], acc)
        end

      line =~ ~r/ via | directly connected / ->
        _join_split_routes(rest, [], [line|acc])

      true ->
        _join_split_routes(rest, [line], acc)
    end
  end

  def join_split_routes(lines),
    do: _join_split_routes(lines, [], [])

  def parse_routes(lines) do
    lines
      |> Stream.map(&String.trim/1)
      |> Enum.map(&String.replace(&1, ",", ""))
      |> join_split_routes
      |> parse_lines(Grammar.route)
      |> Enum.map(fn {:route, ast} -> route(ast) end)
  end
end

defimpl String.Chars, for: Firewalk.Cisco.ASA_8_3.NetworkObject do
  import Kernel, except: [to_string: 1]

  defp value_to_string(value) do
    case value do
      {nil, fqdn}        -> "fqdn #{fqdn}"
      {:v4, fqdn}        -> "fqdn v4 #{fqdn}"
      {:v6, fqdn}        -> "fqdn v6 #{fqdn}"
      {ip1,  ip2}        ->
        "range #{NetAddr.address(ip1)} #{NetAddr.address(ip2)}"

      %NetAddr.IPv4{length:  32} = ip -> "host #{ip}"
      %NetAddr.IPv6{length: 128} = ip -> "host #{ip}"
      %NetAddr.IPv4{length:   _} = ip ->
        "subnet #{NetAddr.network(ip)} #{NetAddr.subnet_mask(ip)}"

      %NetAddr.IPv6{length:   _} = ip -> "#{ip}"
    end
  end

  def to_string(object) do
    description = object.description && "#{object.description}\n " || ""

    value = value_to_string object.value

    [ "object network #{object.name}",
      " #{description}#{value}",
    ] |> Enum.join("\n")
  end
end

defimpl String.Chars, for: Firewalk.Cisco.ASA_8_3.StandardACE do
  import Kernel, except: [to_string: 1]

  defp criterion_to_string(criterion) do
    case criterion do
      :any4              -> "any4"
      %{length: 32} = ip -> "host #{ip}"
      %{length:  _} = ip ->
        "#{NetAddr.network(ip)} #{NetAddr.subnet_mask(ip)}"
    end
  end

  def to_string(ace) do
    criterion = criterion_to_string ace.criterion

    "access-list #{ace.acl_name} standard #{ace.action} #{criterion}"
  end
end

defimpl String.Chars, for: Firewalk.Cisco.ASA_8_3.ExtendedACE do
  import Kernel, except: [to_string: 1]

  alias Firewalk.Cisco.ASA_8_3

  defp port_match_to_string(port_match) do
    case port_match do
              nil        -> ""
      {:group, group}    -> " object-group #{group}"
      {    op, p}        -> " #{op} #{p}"
      {:range, p1, p2}   -> " range #{p1} #{p2}"

      t when t in 0..255 ->
        string =
          Enum.find_value(ASA_8_3.icmp_types, fn {str, ^t} -> str; _ -> nil end)

        " #{string}"
    end
  end

  defp ip_match_to_string(ip_match) do
    case ip_match do
                     :any  -> "any"
                     :any4 -> "any4"
                     :any6 -> "any6"
      {:interface, nameif} -> "interface #{nameif}"
      {   :object, object} -> "object #{object}"
      {    :group,  group} -> "object-group #{group}"

      %NetAddr.IPv4{length:  32} = ip -> "host #{NetAddr.address(ip)}"
      %NetAddr.IPv6{length: 128} = ip -> "host #{ip}"
      %NetAddr.IPv4{length:   _} = ip ->
        "#{NetAddr.network(ip)} #{NetAddr.subnet_mask(ip)}"

      %NetAddr.IPv6{length:   _} = ip -> "#{ip}"
    end
  end

  defp lookup_protocol_by_number(number) do
    Enum.find_value(
      ASA_8_3.ip_protocols,
      number,
      fn {str, ^number} -> str
                      _ -> nil
    end)
  end

  defp protocol_to_string(proto) do
    case proto do
      {:object, object} -> "object #{object}"
      { :group,  group} -> "object-group #{group}"

      p when p in 0..255 ->
        lookup_protocol_by_number proto
    end
  end

  defp log_level_to_string(level) do
    string =
      case level do
        nil -> ""
        l   ->
          string =
            Enum.find_value(ASA_8_3.log_levels, fn {str, ^l} -> str; _ -> nil end)

          " #{string}"
      end
  end

  def to_string(%{protocol: proto} = ace) do
    protocol = protocol_to_string(proto)

         source = ip_match_to_string ace.source
    destination = ip_match_to_string ace.destination
         source_port = port_match_to_string ace.source_port
    destination_port = port_match_to_string ace.destination_port

    log_level = log_level_to_string ace.log_level

    log_interval = ace.log_interval && " interval #{ace.log_interval}" || ""
     log_disable = ace.log_disable  && " disable" || ""

    logging =
      ace.log && " log#{log_level}#{log_interval}#{log_disable}" || ""

    time_range = ace.time_range && " time-range #{ace.time_range}" || ""
      inactive = ace.inactive   && " inactive" || ""

    [ "access-list #{ace.acl_name} extended",
      "#{ace.action} #{protocol}",
      "#{source}#{source_port}",
      "#{destination}#{destination_port}#{logging}#{time_range}#{inactive}",
    ] |> Enum.join(" ")
  end
end

defimpl String.Chars, for: Firewalk.Cisco.ASA_8_3.ACLRemark do
  import Kernel, except: [to_string: 1]

  def to_string(remark) do
    "access-list #{remark.acl_name} remark #{remark.remark}"
  end
end
defimpl String.Chars, for: Firewalk.Cisco.ASA_8_3.ACL do
  import Kernel, except: [to_string: 1]

  def to_string(acl) do
    acl.aces
      |> Enum.map(&Kernel.to_string/1)
      |> Enum.join("\n")
  end
end
