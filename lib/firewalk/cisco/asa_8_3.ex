# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

defmodule Firewalk.Cisco.ASA_8_3 do
  require Logger

  alias Firewalk.Cisco.ASA_8_3.Grammar

  defmodule AccessGroup do
    defstruct [
      :acl_name,
      :direction,
      :interface,
    ]

    @type t
      :: %__MODULE__{
         acl_name: String.t,
        direction: :in | :out,
        interface: String.t,
      }
  end

  defmodule Interface do
    defstruct [
      :id,
      :vlan,
      :nameif,
      :security_level,
      :ip_address,
      :standby_address,
      :description,
    ]

    @type vlan_id :: 1..4094

    @type t
      :: %__MODULE__{
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
    defstruct [:name, :value, :description]

    @type t
      :: %__MODULE__{
               name: String.t,
              value: {nil | :v4 | :v6, URI.t}
                   | NetAddr.t
                   | {NetAddr.t, NetAddr.t},
        description: nil | String.t,
      }
  end

  defmodule ServiceObject do
    defstruct [
             :name,
         :protocol,
           :source,
      :destination,
      :description,
    ]

    @type   port_num :: 1..65535
    @type  icmp_type :: 0..255
    @type   ip_proto :: 0..255
    @type port_match
      :: {:eq | :gt | :lt | :neq, port_num}
       | {:range, port_num, port_num}
       | icmp_type

    @type t
      :: %__MODULE__{
               name: nil | String.t,
           protocol: ip_proto | :tcp_udp,
             source: nil | port_match,
        destination: nil | port_match,
        description: nil | String.t,
      }
  end

  defmodule NetworkGroup do
    defstruct [:name, :values, :description]

    @type object_or_group_ref
      :: {:object | :group, String.t}

    @type t
      :: %__MODULE__{
               name: String.t,
             values: [NetAddr.t|object_or_group_ref],
        description: nil | String.t,
      }
  end

  defmodule AbsoluteTimeRange do
    defstruct [:name, :start, :end]

    @type t
      :: %__MODULE__{
         name: String.t,
        start: nil | NaiveDateTime.t,
          end: nil | NaiveDateTime.t,
      }
  end

  defmodule PeriodicTimeRange do
    defstruct [:name, :days, :from, :to]

    @type day_of_week :: 1..7

    @type t
      :: %__MODULE__{
        name: String.t,
        days: :daily|:weekdays|:weekend|[day_of_week],
        from: Time.t,
          to: Time.t,
      }
  end

  defmodule ICMPGroup do
    defstruct [:name, :values, :description]

    @type icmp_type :: 0..255
    @type group_ref :: {:group, String.t}

    @type t
      :: %__MODULE__{
               name: String.t,
             values: [icmp_type | group_ref],
        description: nil | String.t,
      }
  end

  defmodule ServiceProtocolGroup do
    defstruct [:name, :protocol, :values, :description]

    @type port_num :: 1..65535
    @type port_match
      :: {:eq, port_num}
       | {:range, port_num, port_num}

    @type t
      :: %__MODULE__{
               name: String.t,
           protocol: :tcp | :udp | :tcp_udp,
             values: [port_match],
        description: nil | String.t,
      }
  end

  defmodule ServiceGroup do
    defstruct [:name, :values, :description]

    @type service_object
      :: Firewalk.Cisco.ASA_8_3.ServiceObject.t

    @type object_or_group_ref
      :: {:object|:group, String.t}

    @type t
      :: %__MODULE__{
               name: String.t,
             values: [service_object|object_or_group_ref],
        description: nil | String.t,
      }
  end

  defmodule ProtocolGroup do
    defstruct [:name, :values, :description]

    @type  ip_proto :: 0..255
    @type group_ref :: {:group, String.t}

    @type t
      :: %__MODULE__{
               name: String.t,
             values: [ip_proto | group_ref],
        description: nil | String.t,
      }
  end

  defmodule StaticGlobalNAT do
    defstruct [
      :real_if,
      :mapped_if,
      :after_auto,
      :real_source,
      :mapped_source,
      :real_destination,
      :mapped_destination,
      :dns,
      :service,
      :net_to_net,
      :unidirectional,
      :no_proxy_arp,
      :route_lookup,
      :inactive,
      :description,
    ]

    @type t
      :: %__MODULE__{
                   real_if: nil | String.t,
                 mapped_if: nil | String.t,
                after_auto: boolean,
               real_source: String.t,
             mapped_source: String.t
                          | {:interface, nil | :ipv6},
          real_destination: nil | String.t,
        mapped_destination: nil
                          | String.t
                          | {:interface, nil | :ipv6},
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
    defstruct [
      :real_if,
      :mapped_if,
      :real_source,
      :mapped_source,
      :net_to_net,
      :dns,
      :no_proxy_arp,
      :route_lookup,
      :protocol,
      :real_port,
      :mapped_port,
    ]

    @type port_num :: 1..65535

    @type t
      :: %__MODULE__{
                   real_if: nil | String.t,
                 mapped_if: nil | String.t,
               real_source: String.t,
             mapped_source: NetAddr.t
                          | String.t
                          | {:interface, nil | :ipv6},
                net_to_net: boolean,
                       dns: boolean,
              no_proxy_arp: boolean,
              route_lookup: boolean,
                  protocol: nil | :tcp | :udp,
                 real_port: nil | port_num,
               mapped_port: nil | port_num,
      }
  end

  defmodule DynamicGlobalNAT do
    defstruct [
      :real_if,
      :mapped_if,
      :after_auto,
      :real_source,
      :mapped_source,
      :pat_pool,
      :extended,
      :interface,
      :ipv6,
      :flat,
      :include_reserve,
      :round_robin,
      :real_destination,
      :mapped_destination,
      :dns,
      :service,
      :net_to_net,
      :inactive,
      :description,
    ]

    @type t
      :: %__MODULE__{
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
        mapped_destination: nil
                          | String.t
                          | {:interface, nil | :ipv6},
                       dns: boolean,
                   service: nil | {String.t, String.t},
                net_to_net: boolean,
                  inactive: boolean,
               description: nil | String.t,
      }
  end

  defmodule DynamicObjectNAT do
    defstruct [
      :real_if,
      :mapped_if,
      :real_source,
      :mapped_source,
      :pat_pool,
      :extended,
      :flat,
      :include_reserve,
      :round_robin,
      :interface,
      :ipv6,
      :dns,
    ]

    @type t
      :: %__MODULE__{
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
    defstruct [:acl_name, :action, :criterion]

    @type t :: %__MODULE__{
       acl_name: String.t,
         action: :permit | :deny,
      criterion: NetAddr.t | :any4,
    }
  end

  defmodule ExtendedACE do
    defstruct [
      :acl_name,
      :action,
      :protocol,
      :source,
      :source_port,
      :destination,
      :destination_port,
      :log,
      :log_level,
      :log_interval,
      :log_disable,
      :time_range,
      :inactive,
    ]

    @type   ip_proto :: 0..255
    @type   port_num :: 1..65535
    @type  icmp_type :: 0..255
    @type port_match
      :: {:eq|:gt|:lt|:neq, port_num}
       | {:range, port_num, port_num}

    @type src_or_dst_port
      :: port_match
       | icmp_type
       | {:object, String.t}
       | {:group,  String.t}

    @type src_or_dst
      :: NetAddr.t
       | {:object, String.t}
       | {:group,  String.t}
       | :any4
       | :any6
       | :any
       | {:interface, String.t}

    @type t
      :: %__MODULE__{
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
    defstruct [:acl_name, :remark]

    @type t
      :: %__MODULE__{
        acl_name: String.t,
          remark: String.t,
      }
  end

  defmodule ACL do
    defstruct [:name, :aces]

    @type ace
      :: Firewalk.Cisco.ASA_8_3.StandardACE.t
       | Firewalk.Cisco.ASA_8_3.ExtendedACE.t

    @type remark
      :: Firewalk.Cisco.ASA_8_3.ACLRemark.t

    @type t
      :: %__MODULE__{
        name: String.t,
        aces: [ace | remark],
      }
  end

  defmodule Route do
    defstruct [
      :type,
      :candidate_default,
      :replicated,
      :destination,
      :admin_distance,
      :metric,
      :next_hop,
      :last_update,
      :interface,
    ]

    @type route_type
      :: :local
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

    @type t
      :: %__MODULE__{
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
    [ {"icmp",    1},
      {"ah",     51},
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

  def access_group(ast) do
    %AccessGroup{}
    |> Map.put(:acl_name, extract(ast[:acl_name]))
    |> Map.put(:direction, extract(ast[:direction]))
    |> Map.put(:interface, extract(ast[:interface]))
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
        {:subnet, [addr, mask]} ->
          address_mask_to_cidr(addr, mask)

        {:subnet, [ipv6]} ->
          ipv6
      end

    %NetworkObject{}
    |> Map.put(:name, name)
    |> Map.put(:value, value)
    |> set_description(defs)
  end

  defp port_match_ast_to_model(nil),
    do: nil

  defp port_match_ast_to_model([{op, [port]}]),
    do: {op, port}

  defp port_match_ast_to_model([{op, [first, last]}]),
    do: {op, first, last}

  def service_object([{_, decl}|defs]) do
    def_   = defs[:svc_obj_def]
    source = def_[:source]
    dest   = def_[:destination]

    %ServiceObject{}
    |> Map.put(:name, extract(decl[:name]))
    |> Map.put(:protocol, extract(def_[:protocol]))
    |> Map.put(:source, port_match_ast_to_model(source))
    |> Map.put(:destination, port_match_ast_to_model(dest))
    |> set_description(defs)
  end

  defp _time_range(name, [{:type, :absolute}|_] = ast) do
    [stime, sday, smonth, syear] = ast[:start]
    [etime, eday, emonth, eyear] = ast[:end]

    [shr, smin] =
      stime
      |> String.split(":")
      |> Enum.map(&String.to_integer/1)

    [ehr, emin] =
      etime
      |> String.split(":")
      |> Enum.map(&String.to_integer/1)

    {:ok, start} =
      NaiveDateTime.new(syear, smonth, sday, shr, smin, 0)

    {:ok,  end_} =
      NaiveDateTime.new(eyear, emonth, eday, ehr, emin, 0)

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

    [fhr_str, fmin_str] =
      String.split(extract(ast[:from]), ":")

    [thr_str, tmin_str] =
      String.split(extract(ast[:to]), ":")

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
    {description, defs} =
      Keyword.pop(defs, :description)

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
    {description, defs} =
      Keyword.pop(defs, :description)

    values =
      Enum.map(defs, fn
        {:group_ref, [group]} ->
          {:group, group}

        {_, v} ->
          case v do
            [object: [term]] ->
              {:object, term}

            [addr, mask]  ->
              address_mask_to_cidr(addr, mask)

            [term] ->
              term
          end
      end)

    %NetworkGroup{}
    |> Map.put(:name, extract(decl[:name]))
    |> Map.put(:values, values)
    |> set_description([description: description])
  end

  def service_protocol_group([{_, decl}|defs]) do
    {description, defs} =
      Keyword.pop(defs, :description)

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

        {_, [object: [object]]} ->
          {:object, object}

        {_, ast} ->
          proto  = ast[:protocol]
          source = ast[:source]
          dest   = ast[:destination]

          %ServiceObject{
            protocol:    extract(proto),
            source:      port_match_ast_to_model(source),
            destination: port_match_ast_to_model(dest),
          }
      end)

    %ServiceGroup{}
    |> Map.put(:name, extract(decl[:name]))
    |> Map.put(:values, values)
    |> set_description([description: description])
  end

  def protocol_group([{_, decl}|defs]) do
    {description, defs} =
      Keyword.pop(defs, :description)

    values = Enum.map(defs, fn
      {:group_ref, [group]} -> {:group, group}
      {         _,     ast} -> extract(ast)
    end)

    %ProtocolGroup{}
    |> Map.put(:name, extract(decl[:name]))
    |> Map.put(:values, values)
    |> set_description([description: description])
  end

  defp sort_by_string_length_desc(strings)
      when is_list(strings),
    do: Enum.sort_by(strings, &String.length/1, &>=/2)

  defp strings_to_regex_choice(strings)
      when is_list(strings)
  do
    strings
    |> sort_by_string_length_desc
    |> Enum.map(&Regex.escape/1)
    |> Enum.join("|")
    |> Regex.compile!
  end

  defp extract_nameifs(nil, _),         do: {nil, nil}
  defp extract_nameifs(ifpair, nameifs) do
    pattern = strings_to_regex_choice ["any"|nameifs]
    ifpair  = String.replace(ifpair, ~r/\(|\)/, "")
    split   =
      pattern
      |> Regex.split(ifpair, include_captures: true)

    case split do
      ["", real_if, ",", mapped_if, ""] ->
        {real_if, mapped_if}

      _ ->
        raise "Unable to match interface pair #{inspect ifpair} with interfaces #{inspect nameifs}."
    end
  end

  defp extract_mapped(ast) do
    case ast[:mapped] do
      nil                    -> nil
      [pat_pool: _]          -> nil
      [   object:  [object]] -> object
      [interface:        []] -> {:interface, nil}
      [interface: [ipv6: _]] -> {:interface, :ipv6}
      [ip]                   -> ip
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
    {real, mapped} =
      extract_static_nat ast[:destination]

    %{struct |
      real_destination: real,
      mapped_destination: mapped
    }
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

  defp set_flag(struct, ast, atom)
      when is_atom(atom)
  do
    current = Map.get(struct, atom)
     target = ast[atom] != nil

    %{struct|atom => current || target || false}
  end

  def static_global_nat([{_, ast}], nameifs) do
    {real_source, mapped_source} =
      extract_static_nat ast[:source]

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

  def dynamic_object_nat(
    [{_, decl},
     {_, def_}],
     nameifs
  ) do
    %DynamicObjectNAT{}
    |> Map.put(:real_source, extract(decl[:name]))
    |> set_nat_interfaces(def_, nameifs)
    |> set_dynamic_object_nat_mapped(def_)
  end

  def standard_ace(ast) do
    criterion =
      case ast[:criterion] do
        [:host, ipv4] -> ipv4
        [ addr, mask] -> address_mask_to_cidr(addr, mask)
                :any4 -> :any4
      end

    %StandardACE{}
    |> Map.put(:criterion, criterion)
    |> copy(:acl_name, from: ast)
    |> copy(:action, from: ast)
  end

  defp disambiguate_ace_criteria(criteria, objects) do
    case criteria do
      [protocol, source, {_, str} = u1, u2]
          when is_binary str
      ->
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
        [object:     [object]] -> {:object, object}
        [group:      [object]] -> {:group,  object}
        [eq:           [port]] -> { :eq, port}
        [gt:           [port]] -> { :gt, port}
        [lt:           [port]] -> { :lt, port}
        [neq:          [port]] -> {:neq, port}
        [range: [first, last]] -> {:range, first, last}
        [icmp_type:    [type]] -> {:icmp_type, type}
        [host:           [ip]] -> ip
        [interface:  [nameif]] -> {:interface, nameif}

        [addr, mask] ->
          address_mask_to_cidr(addr, mask)

        [:any4] -> :any4
        [:any6] -> :any6
        [:any ] -> :any

        [%NetAddr.IPv6{} = ipv6] ->
          ipv6

        [octet] when octet in 0..255 ->
          octet
      end
    end)
  end

  defp set_ace_criteria(struct, criteria) do
    criteria
    |> Enum.reduce(struct, fn ({atom, value}, acc) ->
      %{acc | atom => value}
    end)
  end

  defp set_ace_log(struct, ast) do
    %{struct | log: ast[:log] != nil,
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

  def acl([{_, head}|_] = ace_models, objects) do
    aces =
      ace_models
      |> Stream.map(fn {type, ast} ->
        case type do
          :std_ace -> standard_ace(ast)
          :ext_ace -> extended_ace(ast, objects)
          :acl_rem -> acl_remark(ast)
        end
      end)
      |> Stream.with_index(1)
      |> Stream.map(fn {a, i} -> {i, a} end)
      |> Enum.into(OrderedMap.new())

    %ACL{name: extract(head[:acl_name]), aces: aces}
  end

  defp set_route_type_and_flags(struct, ast) do
    pattern =
      ~r/^[LCSRMBDOiUoP]|EX|IA|N[12]|E[12]|su|L[12]|ia|\*|\+$/

    codes0 = Enum.join ast[:code]
    codes  =
      pattern
      |> Regex.split(codes0, include_captures: true)

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
      {          :access_group,             nil} -> :access_group
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

  defp accrete_model(model, nil),
    do: model

  defp accrete_model({type, asts}, ast),
    do: {type, [ast|asts]}

  defp lines_into_models({type, sub_asts} = ast1, ast2) do
    case aggregate_type(ast1, ast2) do
      nil ->
        case aggregate_type(ast1, nil) do
          nil ->
            :ok = Logger.warn("Unable to aggregate line: #{inspect sub_asts}")

            {nil, ast2}

          ^type ->
            {{type, Enum.reverse(sub_asts)}, ast2}

          agg_type ->
            {{agg_type, [ast1]}, ast2}
        end

      ^type ->
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

  def aggregate(list, fun)
      when is_list(list)
       and is_function(fun),
    do: _aggregate(list, [], fun)

  def parse_line(line, grammar)
      when is_binary line
  do
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

  defp access_group_model_to_struct({:access_group, ast}),
    do: access_group ast

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
    %{ static_global_nat:  &static_global_nat(&1, nameifs),
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
      :access_group       -> :access_group
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

    access_group_models = models[:access_group] || []
             acl_models = models[:acl]          || []
             nat_models = models[:nat]          || []
          object_models = models[:object]       || []
              if_models = models[:interface]    || []

    access_groups =
      Enum.map access_group_models,
        &access_group_model_to_struct/1

    interfaces =
      Enum.map if_models,
        &interface_model_to_struct/1

    nameifs =
      interfaces
      |> Enum.map(& &1.nameif)
      |> Enum.filter(& &1 != nil)

    nats =
      Enum.map nat_models,
        &nat_model_to_struct(&1, nameifs)

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

    %{access_groups: access_groups,
               acls: acls,
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

  def dereference(value, objects) do
    case value do
      {:object, name} -> objects[name]
      {:group,  name} -> objects[name]
      _               -> value
    end
  end

  defp group_values_by_key(tuples),
    do: Enum.group_by(tuples, &elem(&1, 0), &elem(&1, 1))

  defp get_next_values(_, [], _),
    do: {[], []}

  defp get_next_values(
    {:group, parent},
    colored,
    split_fun
  ) do
    grouped_by_color =
      colored
      |> group_values_by_key
      |> Enum.to_list

    split_fun.(parent, grouped_by_color)
  end

  def split_network_group_by_color(parent, [{color, _}]),
    do: {[{color, {:group, parent}}], []}

  def split_network_group_by_color(
    parent,
    values_by_color
  ) do
    values_by_color
    |> Enum.map(fn {color, values} ->
      name = "#{parent}-#{color}"
      group =
        %NetworkGroup{
          name: name,
          values: Enum.reverse(values)
        }

      {{color, {:group, name}}, {color, group}}
    end)
    |> Enum.unzip
  end

  defp flatten_unzipped({a, b}),
    do: {List.flatten(a), List.flatten(b)}

  def split_service_protocol_group_by_color(
    parent,
    values_by_color,
    objects
  ) do
    groomed_values =
      case List.keytake(values_by_color, 0, 0) do
        nil ->
          values_by_color

        {{0, values}, rest} ->
          rest
          |> Keyword.update(:tcp, values, & values ++ &1)
          |> Keyword.update(:udp, values, & values ++ &1)
      end

    groomed_values
    |> Enum.map(fn {color, values} ->
      case objects[parent] do
        %ServiceProtocolGroup{protocol: protocol} = o
            when protocol in [color, :tcp_udp]
        ->
          name =
            case protocol do
              ^color   -> o.name
              :tcp_udp -> "#{o.name}-#{color}"
            end

          group = %ServiceProtocolGroup{
            name: name,
            protocol: color,
            values: Enum.reverse(values),
          }

          {{color, {:group, name}}, {color, group}}

        _ ->
          {[], []}
      end
    end)
    |> Enum.unzip
    |> flatten_unzipped
  end

  defp accrete_colored(object, list, fun) do
    if color = fun.(object) do
      ref =
        case object do
          %{value: _} -> {:object, object.name}
                other -> other
        end

      [{color, ref}|list]
    else
      :ok = Logger.warn("Unable to accrete colorless object: #{inspect object}")

      list
    end
  end

  defp _split_by_color([[]], [[]], _os, _cf, _sf, acc),
    do: acc

  defp _split_by_color(
    [[], [root]],
    [c1, _c2],
    os,
    cf,
    sf,
    acc
  ) do
    {_, new_groups} =
      get_next_values(root, c1, sf)

    last_acc =
      group_values_by_key(new_groups ++ acc)

    _split_by_color([[]], [[]], os, cf, sf, last_acc)
  end

  defp _split_by_color(
    [[], [parent|rest]|rt],
    [ch1, ch2|ct],
    os,
    cf,
    sf,
    acc
  ) do
    {new_ch, new_groups} =
      get_next_values(parent, ch1, sf)

    next_ch  = new_ch ++ ch2
    next_acc = new_groups ++ acc

    [rest|rt]
    |> _split_by_color([next_ch|ct], os, cf, sf, next_acc)
  end

  defp _split_by_color(
    [[ref|rest]|rt],
    [ch|ct],
    os,
    cf,
    sf,
    acc
  ) do
    case dereference(ref, os) do
      %{name: _, values: values} ->
        [values, [ref|rest]|rt]
        |> _split_by_color([[], ch|ct], os, cf, sf, acc)

      other ->
        next_ch = accrete_colored(other, ch, cf)

        [rest|rt]
        |> _split_by_color([next_ch|ct], os, cf, sf, acc)
    end
  end

  def split_by_color(name, objects, color_fun, split_fun) do
    cf = color_fun
    sf = split_fun

    case objects[name] do
      %{values: _} ->
        [[{:group, name}]]
        |> _split_by_color([[]], objects, cf, sf, [])

      other ->
        {accrete_colored(other, [], cf), []}
    end
  end

  defp _route_recursive(netaddr, routes) do
    route =
      routes
      |> Enum.sort_by(& &1.destination.length, &>=/2)
      |> Enum.find(fn r ->
        NetAddr.contains?(r.destination, netaddr)
      end)

    if route.type == :connected do
      route
    else
      route_recursive(route.next_hop, routes)
    end
  end

  def route_recursive(netaddr, routes)

  def route_recursive(%NetAddr.IPv4{} = netaddr, routes),
    do: _route_recursive(netaddr, routes)

  def route_recursive(%NetAddr.IPv6{} = netaddr, routes),
    do: _route_recursive(netaddr, routes)

  def route_recursive(_, _), do: nil

  def get_interface(term, routes) do
    address =
      case term do
        %{value: %NetAddr.IPv4{} = value} -> value
        %{value: %NetAddr.IPv6{} = value} -> value
                 %NetAddr.IPv4{} = value  -> value
                 %NetAddr.IPv6{} = value  -> value
      end

    if route = route_recursive(address, routes) do
      route.interface
    else
      nil
    end
  end

  def split_by_interface(name, objects, routes) do
    color_fun = &get_interface(&1, routes)
    split_fun = &split_network_group_by_color/2

    split_by_color(name, objects, color_fun, split_fun)
  end

  def split_tcp_udp_service_group(name, objects) do
    color_fun = fn _ -> 0 end
    split_fun =
      &split_service_protocol_group_by_color(&1, &2, objects)

    split_by_color(name, objects, color_fun, split_fun)
  end

  def reference(object) do
    case object do
      %{name: name, values: _} -> {:group, name}
      %{name: name}            -> {:object, name}
      _                        -> object
    end
  end

  def ungroup(object, objects, pattern \\ "")

  def ungroup(object, objects, pattern) do
    case dereference(object, objects) do
      %ServiceGroup{} ->
        [object]

      %{name: name, values: values} = group ->
        if name =~ pattern do
          values
        else
          [group]
        end

      other ->
        [other]
    end
  end

  defp _explode(terms, terms, _objects, _pattern),
    do: terms

  defp _explode(terms, _last_terms, objects, pattern) do
    terms
    |> Enum.flat_map(&ungroup(&1, objects, pattern))
    |> _explode(terms, objects, pattern)
  end

  # TODO: Split tcp-udp service groups and create new ACEs
  def explode(term, objects, pattern \\ "")
  def explode(%ExtendedACE{} = ace, objects, pattern) do
    fun = fn x ->
        x
        |> ungroup(objects, pattern)
        |> Enum.map(&reference/1)
      end

    for proto <- fun.(ace.protocol),
          src <- fun.(ace.source),
        sport <- fun.(ace.source_port),
          dst <- fun.(ace.destination),
        dport <- fun.(ace.destination_port),
      do: %{ace |   protocol: proto,
                      source: src,
                 source_port: sport,
                 destination: dst,
            destination_port: dport,
          }
  end

  def explode(object, objects, pattern),
    do: _explode([object], [], objects, pattern)

  defp get_value_gracefully(accessible, key, default)
  defp get_value_gracefully(map, key, default)
      when is_map(map),
    do: Map.get(map, key, default)

  defp get_value_gracefully(keywords, key, default)
      when is_list(keywords),
    do: Keyword.get(keywords, key, default)

  defp get_value_gracefully(_accessible, _key, default),
    do: default

  def atomize(object, objects)

  def atomize(%ACLRemark{}, _objects),
    do: []

  def atomize(%StandardACE{} = ace, _objects),
    do: [ace]

  def atomize(%ExtendedACE{} = ace, objects) do
    ace
    |> explode(objects)
    |> Enum.map(fn a ->
      new_kvs =
        a
        |> Map.from_struct
        |> Enum.map(fn {k, v} ->
          deref_v =
            dereference(v, objects)

          new_v =
            get_value_gracefully(deref_v, :value, deref_v)

          {k, new_v}
        end)

      struct!(ace, new_kvs)
    end)
  end

  def coalesce([%StandardACE{} = h]) do
    %{acl_name:  h.acl_name,
      action:    h.action,
      criterion: h.criterion,
    }
  end

  def coalesce([%ExtendedACE{} = h|_] = aces) do
    init =
      %{acl_name:         h.acl_name,
        action:           h.action,
        protocol:         [h.protocol],
        source:           [h.source],
        source_port:      [h.source_port],
        destination:      [h.destination],
        destination_port: [h.destination_port],
      }

    aces
    |> Stream.map(&Map.take(&1, Map.keys(init)))
    |> Enum.reduce(init, fn (a, acc) ->
      Map.merge acc, a, fn (k, v1, v2) ->
        case k do
          :acl_name -> v1
          :action   -> v1
          _         -> [v2|v1]
        end
      end
    end)
    |> Enum.map(fn {k, v} ->
      new_v =
        if is_list(v) do
          v
          |> Enum.filter(& not is_nil &1)
          |> Enum.reverse
          |> Enum.uniq
        else
          v
        end

      {k, new_v}
    end)
    |> Enum.into(%{})
  end

  def rules_to_json(acls, objects) do
    acls
    |> OrderedMap.values
    |> Enum.flat_map(fn acl ->
      acl
      |> Map.get(:aces)
      |> OrderedMap.values
      |> Stream.map(& {"#{&1}", atomize(&1, objects)})
      |> Stream.map(fn {k, vs} -> {k, coalesce(vs)} end)
      |> Enum.flat_map(fn
        {key, %{criterion: _} = ace} ->
          [ %{key: key,
              access: "#{ace.action}",
              protocols: ["0"],
              src: ["0.0.0.0/0"],
              srcPorts: [],
              dst: ["#{ace.criterion}"],
              dstPorts: [],
            },
            %{key: key,
              access: "#{ace.action}",
              protocols: ["0"],
              src: ["#{ace.criterion}"],
              srcPorts: [],
              dst: ["0.0.0.0/0"],
              dstPorts: [],
            },
          ]

        {key, ace} ->
          str_proto =
            &Enum.map(&1, fn p -> "#{p}" end)

          str_ip =
            &Enum.map(&1, fn
              :any  -> "0.0.0.0/0"
              :any4 -> "0.0.0.0/0"
              :any6 -> "::/0"
              addr  ->"#{addr}"
            end)

          str_port =
            &Enum.map(&1, fn
              {op, p} ->
                %{port: "#{p}", operator: "#{op}"}

              {:range, a, b} ->
                %{port: "#{a}-#{b}", operator: "eq"}
            end)

          [ %{key:       key,
              access:    "#{ace.action}",
              protocols: str_proto.(ace.protocol),
              src:       str_ip.(ace.source),
              srcPorts:  str_port.(ace.source_port),
              dst:       str_ip.(ace.destination),
              dstPorts:  str_port.(ace.destination_port),
            },
          ]
      end)
    end)
    |> Poison.encode!
  end

  defp strip_objects(objects) do
    Enum.map objects, fn
      %{value: value} -> value
                other -> other
    end
  end

  def congruent?(object1, object2, objects) do
    [values1, values2] =
      Enum.map [object1, object2], fn o ->
        o
        |> explode(objects)
        |> strip_objects
        |> Enum.sort
      end

    values1 == values2
  end

  #defp _generate_reference_map(object, acc) do
  #  case object do
  #    %{name: name, values: values} ->
  #      Map.
  #  end
  #end

  #def generate_reference_map(parsed_config) do
  #  parsed_config.acls
  #  |> OrderedMap.values
  #  |> Enum.flat_map(fn acl ->
  #    Enum.map(acl.aces, & {acl.name, &1})
  #  end)
  #  |> Stream.concat(OrderedMap.values(parsed_config.objects))
  #  |> Stream.concat(OrderedMap.values(parsed_config.nats))
  #  |> Enum.reduce(%{}, &_generate_reference_map/2)
  #end

  defp get_int_suffix,
    do: rem(:erlang.unique_integer([:positive]) + 100, 1000)

  defp replace_object_refs(config, name, new_name) do
    objects =
      config.objects
      |> Enum.map(fn
        {_, %{name: ^name} = object} ->
          {new_name, %{object|name: new_name}}

        {key, %{values: values} = group} ->
          {key, %{group |
            values: Enum.map(values, fn
              {:object, ^name} -> {:object, new_name}
              { :group, ^name} -> { :group, new_name}
                         value -> value
            end)
          }}

        other -> other
      end)
      |> Enum.into(OrderedMap.new)

    %{config|objects: objects}
  end

  defp replace_ref_in_map(map, key, value, new_value) do
    {_, next_map} =
      Map.get_and_update map, key, fn
        nil    -> :pop
        ^value -> {nil, new_value}
      end

    next_map
  end

  defp replace_nat_refs(config, name, new_name) do
    nats =
      Enum.map config.nats, fn nat ->
        next_nat =
          nat
          |> replace_ref_in_map(:real_source, name, new_name)
          |> replace_ref_in_map(:mapped_source, name, new_name)
          |> replace_ref_in_map(:real_destination, name, new_name)
          |> replace_ref_in_map(:mapped_destination, name, new_name)

        case next_nat do
          %{service: {^name, mapped}} = nat ->
            %{nat|service: {new_name, mapped}}

          %{service: {real, ^name}} = nat ->
            %{nat|service: {real, new_name}}

          other -> other
        end
      end

    %{config|nats: nats}
  end

  defp replace_acl_refs(config, name, new_name) do
    acls =
      Enum.map config.acls, fn {acl_name, acl} ->
        aces =
          acl.aces
          |> Enum.map(fn {seq, ace} ->
            next_ace =
              ace
              |> replace_ref_in_map(:protocol, name, new_name)
              |> replace_ref_in_map(:source, name, new_name)
              |> replace_ref_in_map(:source_port, name, new_name)
              |> replace_ref_in_map(:destination, name, new_name)
              |> replace_ref_in_map(:destination_port, name, new_name)

            {seq, next_ace}
          end)
          |> Enum.into(OrderedMap.new)

        {acl_name, %{acl|aces: aces}}
      end

    %{config|acls: acls}
  end

  defp replace_all_refs(config, name, new_name) do
    config
    |> replace_object_refs(name, new_name)
    |> replace_nat_refs(name, new_name)
    |> replace_acl_refs(name, new_name)
  end

  @type config
    :: %{
      interfaces: list,
      objects:    OrderedMap.t,
      acls:       %{},
      nats:       list
    }

  @spec merge_configs(config, config) :: config
  def merge_configs(config1, config2) do
    new_config2 =
      config2.objects
      |> OrderedMap.keys
      |> Stream.filter(& config1[&1] != nil)
      |> Stream.filter(& config1[&1] != config2[&1])
      |> Enum.reduce(config2, fn(name, acc) ->
        replace_all_refs acc, name,
          "#{name}-#{get_int_suffix()}"
      end)

    objects =
      config1.objects
      |> Enum.concat(new_config2.objects)
      |> Enum.uniq
      |> Enum.into(OrderedMap.new)

    acls1 = Enum.into(config1.acls, %{})
    acls2 = Enum.into(new_config2.acls, %{})

    acls = Map.merge(acls1, acls2, fn(_k, acl1, acl2) ->
      aces =
        acl1.aces
        |> OrderedMap.values
        |> Stream.concat(OrderedMap.values(acl2.aces))
        |> Stream.with_index(1)
        |> Stream.map(fn {a, i} -> {i, a} end)
        |> Enum.into(OrderedMap.new)

      %{acl1|aces: aces}
    end)

    %{config1 |
      objects: objects,
      acls: acls,
      nats: Enum.uniq(config1.nats ++ new_config2.nats),
    }
  end

  def lookup_protocol_by_number(number) do
    Enum.find_value ip_protocols(), number, fn
      {str, ^number} -> str
      _              -> nil
    end
  end

  defp interface_nat_to_string(nat) do
    ipv6 = nat.ipv6 && " ipv6" || ""

    if nat.interface,
    do: " interface#{ipv6}",
    else: ""
  end

  def pat_pool_to_string(nat) do
    if_nat = interface_nat_to_string nat

    mapped_source =
      if nat.mapped_source,
      do: " #{nat.mapped_source}",
      else: ""

    extended =
      if nat.extended,
      do: " extended",
      else: ""

    flat =
      if nat.flat,
      do: " flat",
      else: ""

    include_reserve =
      if nat.include_reserve,
      do: " include-reserve",
      else: ""

    round_robin =
      if nat.round_robin,
      do: " round-robin",
      else: ""

    [ "pat-pool#{mapped_source}#{extended}#{if_nat}",
      "#{flat}#{include_reserve}#{round_robin}"
    ] |> Enum.join
  end

  def static_nat_suffix_to_string(nat) do
    mapped_dest =
      case nat.mapped_destination do
        {:interface, ipv6} ->
          if_ipv6 = ipv6 && " ipv6" || ""

          " interface#{if_ipv6}"

        other ->
          other && " #{other}" || ""
      end

    service_nat =
      if nat.service do
        {real, mapped} = nat.service

        " service #{real} #{mapped}"
      else
        ""
      end

    net_to_net =
      if nat.net_to_net,
      do: " net-to-net",
      else: ""

    cond do
      nat.dns ->
        " dns"

      real_dest = nat.real_destination ->
        [ " destination static",
          "#{real_dest}#{mapped_dest}#{service_nat}"
          <> "#{net_to_net}",
        ] |> Enum.join(" ")

      true ->
        service_nat
    end
  end
end

defimpl String.Chars,
    for: Firewalk.Cisco.ASA_8_3.NetworkObject
do
  import Kernel, except: [to_string: 1]

  defp value_to_string(value) do
    case value do
      {nil, fqdn} -> "fqdn #{fqdn}"
      {:v4, fqdn} -> "fqdn v4 #{fqdn}"
      {:v6, fqdn} -> "fqdn v6 #{fqdn}"
      {ip1,  ip2} ->
        "range #{NetAddr.address(ip1)} "
        <> "#{NetAddr.address(ip2)}"

      %NetAddr.IPv4{length:  32} = ip ->
        "host #{NetAddr.address(ip)}"

      %NetAddr.IPv6{length: 128} = ip ->
        "host #{ip}"

      %NetAddr.IPv4{length:   _} = ip ->
        "subnet #{NetAddr.network(ip)} "
        <> "#{NetAddr.subnet_mask(ip)}"

      %NetAddr.IPv6{length:   _} = ip ->
        "#{ip}"
    end
  end

  def to_string(object) do
    description =
      if object.description,
      do: "description #{object.description}\n ",
      else: ""

    value = value_to_string object.value

    [ "object network #{object.name}",
      " #{description}#{value}",
    ] |> Enum.join("\n")
  end
end

defimpl String.Chars,
    for: Firewalk.Cisco.ASA_8_3.NetworkGroup
do
  import Kernel, except: [to_string: 1]

  defp value_to_string(value) do
    case value do
      { :group, name} -> "group-object #{name}"
      {:object, name} -> "network-object object #{name}"

      %NetAddr.IPv4{length: 32} ->
        "network-object host #{NetAddr.address(value)}"

      %NetAddr.IPv6{length: 128} ->
        "network-object host #{NetAddr.address(value)}"

      %NetAddr.IPv4{} = v ->
        "network-object "
        <> "#{NetAddr.address(v)} #{NetAddr.subnet_mask(v)}"

      %NetAddr.IPv6{} = v ->
        "network-object #{v}"
    end
  end

  def to_string(object) do
    description =
      if object.description,
      do: "description #{object.description}\n ",
      else: ""

    values =
      object.values
      |> Enum.map(&value_to_string/1)
      |> Enum.join("\n ")

    [ "object-group network #{object.name}",
      " #{description}#{values}",
    ] |> Enum.join("\n")
  end
end

defimpl String.Chars,
    for: Firewalk.Cisco.ASA_8_3.ServiceObject
do
  import Kernel, except: [to_string: 1]

  alias Firewalk.Cisco.ASA_8_3

  defp port_match_to_string(term) do
    case term do
      {    op, port}   -> "#{op} #{port}"
      {:range, p1, p2} -> "range #{p1} #{p2}"
    end
  end

  defp service_to_string(service) do
    proto_keyword =
      ASA_8_3.lookup_protocol_by_number service.protocol

    source =
      if s = service.source,
      do: " source #{port_match_to_string(s)}",
      else: ""

    dest =
      if d = service.destination,
      do: " destination #{port_match_to_string(d)}",
      else: ""

    "#{proto_keyword}#{source}#{dest}"
  end

  def to_string(object) do
    description =
      if object.description,
      do: "description #{object.description}\n ",
      else: ""

    value = service_to_string object

    [ "object service #{object.name}",
      " #{description}service #{value}",
    ] |> Enum.join("\n")
  end
end

defimpl String.Chars,
    for: Firewalk.Cisco.ASA_8_3.ServiceGroup
do
  import Kernel, except: [to_string: 1]

  alias Firewalk.Cisco.ASA_8_3

  defp port_match_to_string(term) do
    case term do
      {    op, port}   -> "#{op} #{port}"
      {:range, p1, p2} -> "range #{p1} #{p2}"
    end
  end

  defp value_to_string(value) do
    case value do
      {:group, name} ->
        "group-object #{name}"

      {:object, name} ->
        "service-object object #{name}"

      %ASA_8_3.ServiceObject{} = object ->
        p = object.proto

        proto_keyword =
          if p == :tcp_udp do
            "tcp-udp"
          else
            ASA_8_3.lookup_protocol_by_number p
          end

        source =
          if s = object.source,
          do: " source #{port_match_to_string(s)}",
          else: ""

        dest =
          if d = object.destination,
          do: " destination #{port_match_to_string(d)}",
          else: ""

        "service-object #{proto_keyword}#{source}#{dest}"
    end
  end

  def to_string(object) do
    description =
      if object.description,
      do: "description #{object.description}\n ",
      else: ""

    values =
      object.values
      |> Enum.map(&value_to_string/1)
      |> Enum.join("\n ")

    [ "object-group service #{object.name}",
      " #{description}#{values}",
    ] |> Enum.join("\n")
  end
end

defimpl String.Chars,
    for: Firewalk.Cisco.ASA_8_3.ProtocolGroup
do
  import Kernel, except: [to_string: 1]

  alias Firewalk.Cisco.ASA_8_3

  defp value_to_string(value) do
    case value do
      {:group, name} ->
        "group-object #{name}"

      proto ->
        name = ASA_8_3.lookup_protocol_by_number proto

        "protocol-object #{name}"
    end
  end

  def to_string(object) do
    description =
      if object.description,
      do: "description #{object.description}\n ",
      else: ""

    values =
      object.values
      |> Enum.map(&value_to_string/1)
      |> Enum.join("\n ")

    [ "object-group protocol #{object.name}",
      " #{description}#{values}",
    ] |> Enum.join("\n")
  end
end

defimpl String.Chars,
    for: Firewalk.Cisco.ASA_8_3.ServiceProtocolGroup
do
  import Kernel, except: [to_string: 1]

  alias Firewalk.Cisco.ASA_8_3

  defp port_match_to_string(term) do
    case term do
      {   :eq, port}   -> "eq #{port}"
      {:range, p1, p2} -> "range #{p1} #{p2}"
    end
  end

  defp value_to_string(value) do
    case value do
      {:group, name} ->
        "group-object #{name}"

      port_match ->
        "port-object #{port_match_to_string(port_match)}"
    end
  end

  def to_string(object) do
    description =
      if object.description,
      do: "description #{object.description}\n ",
      else: ""

    proto =
      if object.protocol == :tcp_udp do
        "tcp-udp"
      else
        "#{object.protocol}"
      end

    values =
      object.values
      |> Enum.map(&value_to_string/1)
      |> Enum.join("\n ")

    [ "object-group service #{object.name} #{proto}",
      " #{description}#{values}",
    ] |> Enum.join("\n")
  end
end

defimpl String.Chars,
    for: Firewalk.Cisco.ASA_8_3.ICMPGroup
do
  import Kernel, except: [to_string: 1]

  alias Firewalk.Cisco.ASA_8_3

  defp value_to_string(value) do
    case value do
      {:group, name} ->
        "group-object #{name}"

      type ->
        type_keyword =
          Enum.find_value(ASA_8_3.icmp_types, fn
            {str, ^type} -> str
                       _ -> nil
          end)

        "icmp-object #{type_keyword}"
    end
  end

  def to_string(object) do
    description =
      if object.description,
      do: "description #{object.description}\n ",
      else: ""

    values =
      object.values
      |> Enum.map(&value_to_string/1)
      |> Enum.join("\n ")

    [ "object-group icmp-type #{object.name}",
      " #{description}#{values}",
    ] |> Enum.join("\n")
  end
end

defimpl String.Chars,
    for: Firewalk.Cisco.ASA_8_3.PeriodicTimeRange
do
  import Kernel, except: [to_string: 1]

  alias Firewalk.Cisco.ASA_8_3

  defp days_to_string(days) do
    case days do
      d when d in [:daily, :weekdays, :weekend] ->
        "#{days}"

      _ ->
        days
        |> Enum.map(fn d ->
          %{1 => "Monday",
            2 => "Tuesday",
            3 => "Wednesday",
            4 => "Thursday",
            5 => "Friday",
            6 => "Saturday",
            7 => "Sunday",
          }[d]
        end)
        |> Enum.join(" ")
      end
  end

  defp time_to_string(time),
    do: String.replace("#{time}", ~r/:00$/, "")

  def to_string(trange) do
    days = days_to_string trange.days
    from = time_to_string trange.from
      to = time_to_string trange.to

    [ "time-range #{trange.name}",
      "periodic #{days} #{from} to #{to}",
    ] |> Enum.join("\n")
  end
end

defimpl String.Chars,
    for: Firewalk.Cisco.ASA_8_3.DynamicObjectNAT
do
  import Kernel, except: [to_string: 1]

  alias Firewalk.Cisco.ASA_8_3

  defp mapped_source_to_string(nat) do
    if nat.pat_pool do
      ASA_8_3.pat_pool_to_string nat
    else
      ipv6   = nat.ipv6 && " ipv6" || ""
      if_nat =
        if nat.interface,
        do: " interface#{ipv6}",
        else: ""

      if nat.mapped_source,
      do: " #{nat.mapped_source}#{if_nat}",
      else: ""
    end
  end

  def to_string(nat) do
    ifpair =
      if nat.real_if,
      do: " (#{nat.real_if},#{nat.mapped_if})",
      else: ""

    dns =
      if nat.dns,
      do: " dns",
      else: ""

    mapped_source =
      mapped_source_to_string nat

    [ "object network #{nat.real_source}",
      " nat#{ifpair} dynamic#{mapped_source}#{dns}",
    ] |> Enum.join("\n")
  end
end

defimpl String.Chars,
    for: Firewalk.Cisco.ASA_8_3.DynamicGlobalNAT
do
  import Kernel, except: [to_string: 1]

  alias Firewalk.Cisco.ASA_8_3

  defp mapped_source_to_string(nat) do
    if nat.pat_pool do
      ASA_8_3.pat_pool_to_string nat
    else
      ipv6   = nat.ipv6 && " ipv6" || ""
      if_nat =
        if nat.interface,
        do: " interface#{ipv6}",
        else: ""

      if nat.mapped_source,
      do: " #{nat.mapped_source}#{if_nat}",
      else: ""
    end
  end

  def to_string(nat) do
    ifpair =
      if nat.real_if,
      do: " (#{nat.real_if},#{nat.mapped_if})",
      else: ""

    after_auto =
      if nat.after_auto,
      do: " after-auto",
      else: ""

    real_source =
      case nat.real_source do
        :any -> "any"
        name -> "object #{name}"
      end

    mapped_source = mapped_source_to_string nat

    static_nat_suffix =
      ASA_8_3.static_nat_suffix_to_string nat

    inactive =
      if nat.inactive,
      do: " inactive",
      else: ""

    description =
      if nat.description,
      do: " description #{nat.description}",
      else: ""

    [ "nat#{ifpair}#{after_auto} ",
      "source dynamic #{real_source}",
      "#{mapped_source}#{static_nat_suffix}#{inactive}"
      <> "#{description}",
    ] |> Enum.join
  end
end

defimpl String.Chars,
    for: Firewalk.Cisco.ASA_8_3.StaticGlobalNAT
do
  import Kernel, except: [to_string: 1]

  alias Firewalk.Cisco.ASA_8_3

  def to_string(nat) do
    ifpair =
      if nat.real_if,
      do: " (#{nat.real_if},#{nat.mapped_if})",
      else: ""

    after_auto =
      if nat.after_auto,
      do: " after-auto",
      else: ""

    mapped_source =
      case nat.mapped_source do
        {:interface, ipv6} ->
          if_ipv6 = ipv6 && " ipv6" || ""

          " interface#{if_ipv6}"

        name ->
          " #{name}"
      end

    static_nat_suffix =
      ASA_8_3.static_nat_suffix_to_string nat

    unidirectional =
      if nat.unidirectional,
      do: " unidirectional",
      else: ""

    no_proxy_arp =
      if nat.no_proxy_arp,
      do: " no-proxy-arp",
      else: ""

    route_lookup =
      if nat.route_lookup,
      do: " route-lookup",
      else: ""

    inactive =
      if nat.inactive,
      do: " inactive",
      else: ""

    description =
      if nat.description,
      do: " description #{nat.description}",
      else: ""

    [ "nat#{ifpair}#{after_auto} ",
      "source static #{nat.real_source}#{mapped_source}"
      <> "#{static_nat_suffix}",
      "#{unidirectional}#{no_proxy_arp}#{route_lookup}"
      <> "#{inactive}#{description}",
    ] |> Enum.join
  end
end

defimpl String.Chars,
    for: Firewalk.Cisco.ASA_8_3.StaticObjectNAT
do
  import Kernel, except: [to_string: 1]

  alias Firewalk.Cisco.ASA_8_3

  def to_string(nat) do
    ifpair =
      if nat.real_if,
      do: " (#{nat.real_if},#{nat.mapped_if})",
      else: ""

    mapped_source =
      case nat.mapped_source do
        {:interface, ipv6} ->
          if_ipv6 = ipv6 && " ipv6" || ""

          "interface#{if_ipv6}"

        name when is_binary name ->
          name

        netaddr ->
          NetAddr.address netaddr
      end

    net_to_net =
      if nat.net_to_net,
      do: " net-to-net",
      else: ""

    dns =
      if nat.dns,
      do: " dns",
      else: ""

    no_proxy_arp =
      if nat.no_proxy_arp,
      do: " no-proxy-arp",
      else: ""

    route_lookup =
      if nat.route_lookup,
      do: " route-lookup",
      else: ""

    service =
      if nat.protocol do
        " service #{nat.protocol} #{nat.real_port} "
        <> "#{nat.mapped_port}"
      else
        ""
      end

    [ "object network #{nat.real_source}\n",
      " nat#{ifpair} static #{mapped_source}",
      "#{net_to_net}#{dns}#{no_proxy_arp}#{route_lookup}"
      <> "#{service}",
    ] |> Enum.join
  end
end

# TODO: defimpl String.Chars, for: Firewalk.Cisco.ASA_8_3.Interface
# TODO: defimpl String.Chars, for: Firewalk.Cisco.ASA_8_3.AbsoluteTimeRange

defimpl String.Chars,
    for: Firewalk.Cisco.ASA_8_3.StandardACE
do
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
    name      = ace.acl_name
    action    = ace.action
    criterion = criterion_to_string ace.criterion

    "access-list #{name} standard #{action} #{criterion}"
  end
end

defimpl String.Chars,
    for: Firewalk.Cisco.ASA_8_3.ExtendedACE
do
  import Kernel, except: [to_string: 1]

  alias Firewalk.Cisco.ASA_8_3

  defp port_match_to_string(port_match) do
    case port_match do
      nil              -> ""
      {:group, group}  -> " object-group #{group}"
      {    op, p}      -> " #{op} #{p}"
      {:range, p1, p2} -> " range #{p1} #{p2}"

      t when t in 0..255 ->
        string =
          Enum.find_value ASA_8_3.icmp_types, fn
            {str, ^t} -> str
            _         -> nil
          end

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

      %NetAddr.IPv4{length:  32} = ip ->
        "host #{NetAddr.address(ip)}"

      %NetAddr.IPv6{length: 128} = ip ->
        "host #{ip}"

      %NetAddr.IPv4{length:   _} = ip ->
        "#{NetAddr.network(ip)} #{NetAddr.subnet_mask(ip)}"

      %NetAddr.IPv6{length:   _} = ip ->
        "#{ip}"
    end
  end

  defp protocol_to_string(proto) do
    case proto do
      {:object, object}  -> "object #{inspect object}"
      { :group,  group}  -> "object-group #{group}"
      p when p in 0..255 ->
        ASA_8_3.lookup_protocol_by_number proto
    end
  end

  defp log_level_to_string(level) do
    case level do
      nil -> ""
      l   ->
        string =
          Enum.find_value ASA_8_3.log_levels, fn
            {str, ^l} -> str
            _         -> nil
          end

        " #{string}"
    end
  end

  def to_string(%{protocol: proto} = ace) do
    protocol = protocol_to_string proto

         source =   ip_match_to_string ace.source
    destination =   ip_match_to_string ace.destination
    source_port = port_match_to_string ace.source_port

    destination_port =
      port_match_to_string ace.destination_port

    log_level =
      log_level_to_string ace.log_level

    log_interval =
      if ace.log_interval,
      do: " interval #{ace.log_interval}",
      else: ""

    log_disable =
      if ace.log_disable,
      do: " disable",
      else: ""

    logging =
      if ace.log,
      do: " log#{log_level}#{log_interval}#{log_disable}",
      else: ""

    time_range =
      if ace.time_range,
      do: " time-range #{ace.time_range}",
      else: ""

    inactive =
      if ace.inactive,
      do: " inactive",
      else: ""

    [ "access-list #{ace.acl_name} extended",
      "#{ace.action} #{protocol}",
      "#{source}#{source_port}",
      "#{destination}#{destination_port}"
      <> "#{logging}#{time_range}#{inactive}",
    ] |> Enum.join(" ")
  end
end

defimpl String.Chars,
    for: Firewalk.Cisco.ASA_8_3.ACLRemark
do
  import Kernel, except: [to_string: 1]

  def to_string(remark) do
    "access-list #{remark.acl_name} remark #{remark.remark}"
  end
end

defimpl String.Chars,
    for: Firewalk.Cisco.ASA_8_3.ACL
do
  import Kernel, except: [to_string: 1]

  def to_string(acl) do
    acl.aces
    |> OrderedMap.values
    |> Enum.map(&Kernel.to_string/1)
    |> Enum.join("\n")
  end
end
