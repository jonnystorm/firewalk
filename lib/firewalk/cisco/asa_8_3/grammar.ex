# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

defmodule Firewalk.Cisco.ASA_8_3.Grammar do
  import Frank

  alias Firewalk.Cisco.ASA_8_3

  defmacro flag(string) when is_binary string do
    atom =
      if string =~ ~r/^[a-zA-Z][0-9a-zA-Z\-_]*/ do
        string
        |> String.downcase
        |> String.replace("-", "_")
        |> String.to_atom

      else
        raise "Flag must begin with a letter and may only contain alphanumeric characters or hyphen: #{string}"
      end

    quote do
      [{unquote(atom), [unquote(string)]}]
    end
  end

  def delimit(string, first, last),
    do: "#{first}#{string}#{last}"

  def name,
    do: "`~!@#$%^&*()\\-_=+[]{}\\|;:'\",<.>\/?"
        |> Regex.escape
        |> delimit("[", "a-zA-Z0-9]+")
        |> Regex.compile!

  def acl_name,    do: name

  def nameif_name, do: name

  def trange_name, do: name

  # Object names cannot contain '\', '/', or ','
  def object_name,
    do: "`~!@#$%^&*()\\-_=+[]{}|;:'\"<.>?"
        |> Regex.escape
        |> delimit("[", "a-zA-Z0-9]+")
        |> Regex.compile!

  def octet, do: 0..255

  def ip_proto_number, do: octet

  # http://www.cisco.com/c/en/us/td/docs/security/asa/asa91/configuration/general/asa_91_general_config/ref_ports.html
  def ip_proto_keyword,
    do: one_of ASA_8_3.ip_protocols

  def ip_proto,
    do: one_of [ip_proto_number, ip_proto_keyword]

  def interface,
    do: [interface: ["interface", ~r|^[a-z0-9/\.\-]+$|i]]

  def vlan,
    do: [vlan: ["vlan", 1..4094]]

  def nameif,
    do: [nameif: ["nameif", nameif_name]]

  def security_level,
    do: [security_level: ["security-level", 0..100]]

  def ip_address do
    ipvx = [ip_address: one_of([[ipv4, ipv4], ipv6])]
    standby = [standby: ["standby", ipvx]]

    [ip_address: [~w(ip address), ipvx, maybe(standby)]]
  end

  def object, do: [object: [object_name]]

  def action, do: [action: one_of([:permit, :deny])]

  def ace_proto,
    do: [ace_spec: one_of([ [object: ["object",       object_name]],
                            [group:  ["object-group", object_name]],
                            ip_proto,
                          ])]

  def ipv4, do: ip "0/0"

  def ipv6, do: ip "::/0"

  def ace_ip,
    do: [ace_spec: one_of([ [object: ["object",       object_name]],
                            [group:  ["object-group", object_name]],
                            [host:   ["host", one_of([ipv4, ipv6])]],
                            [interface: ["interface", nameif_name]],
                            [ipv4, ipv4],
                            ipv6,
                            :any4,
                            :any6,
                            :any,
                          ])]

  def port, do: one_of [port_number, port_keyword]

  def port_number, do: 1..65535

  # http://www.cisco.com/c/en/us/td/docs/security/asa/asa91/configuration/general/asa_91_general_config/ref_ports.html
  def port_keyword,
    do: one_of [ {"aol",                5190},
                 {"bgp",                 179},
                 {"biff",                512},
                 {"bootpc",               68},
                 {"bootps",               67},
                 {"chargen",              19},
                 {"cifs",               3020},
                 {"citrix-ica",         1494},
                 {"cmd",                 514},
                 {"ctiqbe",             2748},
                 {"daytime",              13},
                 {"discard",               9},
                 {"domain",               53},
                 {"dnsix",               195},
                 {"echo",                  7},
                 {"exec",                512},
                 {"finger",               79},
                 {"ftp",                  21},
                 {"ftp-data",             20},
                 {"gopher",               70},
                 {"h323",               1720},
                 {"hostname",            101},
                 {"http",                 80},
                 {"https",               443},
                 {"ident",               113},
                 {"imap4",               143},
                 {"irc",                 194},
                 {"isakmp",              500},
                 {"kerberos",            750},
                 {"klogin",              543},
                 {"kshell",              544},
                 {"ldap",                389},
                 {"ldaps",               636},
                 {"login",               513},
                 {"lotusnotes",         1352},
                 {"lpd",                 515},
                 {"mobile-ip",           434},
                 {"nameserver",           42},
                 {"netbios-ns",          137},
                 {"netbios-dgm",         138},
                 {"netbios-ssn",         139},
                 {"nfs",                2049},
                 {"nntp",                119},
                 {"ntp",                 123},
                 {"pcanywhere-data",    5631},
                 {"pcanywhere-status",  5632},
                 {"pim-auto-rp",         496},
                 {"pop2",                109},
                 {"pop3",                110},
                 {"pptp",               1723},
                 {"radius",             1645},
                 {"radius-acct",        1646},
                 {"rip",                 520},
                 {"rsh",                 514},
                 {"rtsp",                554},
                 {"secureid-udp",       5510},
                 {"sip",                5060},
                 {"smtp",                 25},
                 {"snmp",                161},
                 {"snmptrap",            162},
                 {"sqlnet",             1521},
                 {"ssh",                  22},
                 {"sunrpc",              111},
                 {"syslog",              514},
                 {"tacacs",               49},
                 {"talk",                517},
                 {"telnet",               23},
                 {"tftp",                 69},
                 {"time",                 37},
                 {"uucp",                540},
                 {"who",                 513},
                 {"whois",                43},
                 {"www",                  80},
                 {"xdmcp",               177},
               ]

  def icmp_type,
    do: one_of [0..255 | ASA_8_3.icmp_types()]

  def port_match,
    do: one_of [ [group: ["object-group", object_name]],
                     eq: ["eq",    port],
                     gt: ["gt",    port],
                     lt: ["lt",    port],
                    neq: ["neq",   port],
                  range: ["range", port, port],
                  icmp_type: icmp_type,
               ]

  def log_level_number, do: 0..7

  # http://www.cisco.com/c/en/us/td/docs/security/asa/asa82/configuration/guide/config/monitor_syslog.html#wp1092814
  def log_level_keyword,
    do: one_of ASA_8_3.log_levels()

  def log_level,
    do: one_of [log_level_number, log_level_keyword]

  def log_interval, do: 1..600

  def ace_log do
    disable = flag "disable"

    [log:
      [ "log",
        maybe(one_of(
          [ [level: log_level, interval: maybe(["interval", log_interval])],
            disable,
          ]))
      ]
    ]
  end

  def acl_remark do
    remark = [remark: ["remark", many_of(~r/.*/)]]

    [acl_rem: ["access-list", {:acl_name, [acl_name]}, remark]]
  end

  def standard_ace do
    [std_ace:
      [ "access-list", {:acl_name, [acl_name]}, maybe("standard"), action,
        criterion: one_of([ [ipv4, ipv4],
                            [:host, ipv4],
                            :any4,
                          ])
      ]
    ]
  end

  def extended_ace do
    inactive = flag "inactive"

    ace_port = [ace_spec: port_match]
      trange = [time_range: ["time-range", trange_name]]

    [ext_ace:
      [ "access-list", {:acl_name, [acl_name]}, maybe("extended"), action,
        ace_proto, ace_ip,
          one_of([ [ace_port, ace_ip, ace_port],
                   [ace_port, ace_ip],
                   [ace_ip, ace_port],
                   ace_ip,
                 ]),
          maybe(ace_log), maybe(trange), maybe(inactive)
      ]
    ]
  end

  def access_group do
    [access_group:
      [ acl_name: ["access-group", acl_name],
        direction: one_of([:in, :out]),
        interface: ["interface", nameif_name],
      ]
    ]
  end

  def time, do: ~r/^([0-1]?\d|2[0-3]):[0-5]\d$/

  def day_of_month, do: 1..31

  def month,
    do: one_of [ {"Jan",  1},
                 {"Feb",  2},
                 {"Mar",  3},
                 {"Apr",  4},
                 {"May",  5},
                 {"Jun",  6},
                 {"Jul",  7},
                 {"Aug",  8},
                 {"Sep",  9},
                 {"Oct", 10},
                 {"Nov", 11},
                 {"Dec", 12},
               ]

  def year, do: 1993..2035

  def abs_time, do: [time, day_of_month, month, year]

  def day_of_week,
    do: one_of [ {"Monday",    1},
                 {"Tuesday",   2},
                 {"Wednesday", 3},
                 {"Thursday",  4},
                 {"Friday",    5},
                 {"Saturday",  6},
                 {"Sunday",    7},
               ]

  def trange_decl,
    do: [trange_decl: ["time-range", name: [trange_name]]]

  def abs_trange_def do
    [ {"absolute", {:type, :absolute}},
      one_of([ [start: ["start", abs_time], end: maybe(["end", abs_time])],
                                            end:       ["end", abs_time],
             ])
    ]
  end

  def period_trange_def do
    [ {"periodic", {:type, :periodic}},
      one_of([ [ days: one_of([:daily, :weekdays, :weekend]),
                 from: [time], to: ["to", time],
               ],
               [ days: many_of(day_of_week),
                 from: [time], to: ["to", time],
               ],
             ])
    ]
  end

  def trange_def,
    do: [trange_def: one_of([abs_trange_def, period_trange_def])]

  def group_ref, do: [group_ref: ["group-object", object_name]]

  def description,
    do: [description: ["description", many_of(~r/.*/)]]

  def fqdn, do: ~r/^[0-9a-z][0-9a-z\-\.]+[0-9a-z]$/i

  def network_object_decl,
    do: [net_obj_decl: [~w(object network), name: [object_name]]]

  def network_object_def do
    ip_version = one_of [:v4, :v6]

    [net_obj_def:
      one_of([   fqdn: ["fqdn", maybe(ip_version), fqdn],
                 host: ["host", one_of([ipv4, ipv6])],
                range: ["range", one_of([[ipv4, ipv4], [ipv6, ipv6]])],
               subnet: ["subnet", one_of([[ipv4, ipv4], ipv6])],
             ])
    ]
  end

  def service_spec do
         source = [source:      [     "source", port_match]]
    destination = [destination: ["destination", port_match]]

    one_of [ [source, maybe(destination)],
             destination,
           ]
  end

  def service_object_decl,
    do: [svc_obj_decl: [~w(object service), name: [object_name]]]

  def service_object_def,
    do: [svc_obj_def: ["service", [protocol: ip_proto], maybe(service_spec)]]

  def icmp_group_decl,
    do: [icmp_grp_decl: [~w(object-group icmp-type), name: [object_name]]]

  def icmp_group_def,
    do: [icmp_grp_def: ["icmp-object", icmp_type]]

  def network_group_decl,
    do: [net_grp_decl: [~w(object-group network), name: [object_name]]]

  def network_group_def do
    host   = one_of [ipv4, ipv6]
    subnet = one_of [[ipv4, ipv4], ipv6]

    [net_grp_def:
      one_of([ [~w(network-object object), object],
               [~w(network-object   host),   host],
               [  "network-object",        subnet],
             ])
    ]
  end

  def service_proto_group_decl do
    proto = {:protocol, one_of [:tcp, :udp, {"tcp-udp", :tcp_udp}]}

    [svc_proto_grp_decl:
      [~w(object-group service), {:name, [object_name]}, proto]
    ]
  end

  def service_proto_group_def do
    [svc_proto_grp_def:
      ["port-object", one_of([ eq:    ["eq",    port],
                               range: ["range", port, port],
                             ])
      ]
    ]
  end

  def service_group_decl,
    do: [svc_grp_decl: [~w(object-group service), name: [object_name]]]

  def service_group_def do
    protocol = [protocol: one_of([ ip_proto,
                                   {"icmp6", :icmp6},
                                   {"tcp-udp", :tcp_udp},
                                 ])]

    [svc_grp_def:
      [ "service-object", one_of([ ["object", object],
                                   [protocol, icmp_type],
                                   [protocol, maybe(service_spec)],
                                 ]),
      ]
    ]
  end

  def protocol_group_decl,
    do: [proto_grp_decl: [~w(object-group protocol), name: [object_name]]]

  def protocol_group_def,
    do: [proto_grp_def: ["protocol-object", ip_proto]]

  def interface_nat,
    do: [interface: ["interface", maybe(flag("ipv6"))]]

  def ifpair, do: [interfaces: [~r/^\(.*,.*\)$/]]

  def static_object_nat do
    mapped = [mapped: one_of([ipv4, ipv6, object, interface_nat])]

      net_to_net = flag "net-to-net"
    no_proxy_arp = flag "no-proxy-arp"
    route_lookup = flag "route-lookup"
             dns = flag "dns"

    options = [maybe(no_proxy_arp), maybe(route_lookup)]

       protocol = one_of ~w(tcp udp)a
      real_port = [real:   port]
    mapped_port = [mapped: port]

    service = [service: ["service", protocol, real_port, mapped_port]]

    [static_obj_nat:
      [ "nat", maybe(ifpair), "static", mapped, maybe(net_to_net),
        one_of([ [dns, options],
                 [options, maybe(service)],
               ])
      ]
    ]
  end

  def pat_pool_spec do
           extended = flag "extended"
               flat = flag "flat"
    include_reserve = flag "include-reserve"
        round_robin = flag "round-robin"

    [pat_pool:
      [ "pat-pool",
        one_of([ [object, maybe(one_of [extended, interface_nat])],
                 interface_nat,
               ]),
        maybe([flat, maybe(include_reserve)]),
        maybe(round_robin),
      ]
    ]
  end

  def dynamic_object_nat do
    mapped = one_of([ipv4, ipv6, object])

    dns = flag "dns"

    [dyn_obj_nat:
      [ "nat", maybe(ifpair), "dynamic",
        mapped: one_of([ pat_pool_spec,
                         [mapped, maybe(interface_nat), maybe(dns)],
                       ])
      ]
    ]
  end

  def static_nat_spec,
    do: [real: object, mapped: one_of([interface_nat, object])]

  def static_nat_suffix do
           dns = flag "dns"
    net_to_net = flag "net-to-net"

    service_nat = [service: ["service", object, object]]

    one_of [ dns,
             service_nat,
             destination: [ ~w(destination static), static_nat_spec,
                            maybe(service_nat),
                            maybe(net_to_net),
                          ],
           ]
  end

  def static_global_nat do
        after_auto = flag "after-auto"
    unidirectional = flag "unidirectional"
      no_proxy_arp = flag "no-proxy-arp"
      route_lookup = flag "route-lookup"
          inactive = flag "inactive"

    [static_gbl_nat:
      [ "nat", maybe(ifpair), maybe(after_auto),
        [source: [~w(source static), static_nat_spec]],
        maybe(static_nat_suffix),
        maybe(unidirectional),
        maybe(no_proxy_arp),
        maybe(route_lookup),
        maybe(inactive),
        maybe(description),
      ]
    ]
  end

  def dynamic_global_nat do
    after_auto = flag "after-auto"
      inactive = flag "inactive"

    [dyn_gbl_nat:
      [ "nat", maybe(ifpair), maybe(after_auto),
        [source: [ ~w(source dynamic),
                   real: one_of([object, :any]),
                   mapped: one_of([ pat_pool_spec,
                                    [object, maybe(interface_nat)],
                                  ]),
                 ]
        ],
        maybe(static_nat_suffix),
        maybe(inactive),
        maybe(description),
      ]
    ]
  end

  def asa_command do
    one_of [ acl_remark,
             extended_ace,
             standard_ace,
             access_group,
             interface,
             vlan,
             nameif,
             security_level,
             ip_address,
             description,
             group_ref,
             network_object_decl,
             network_object_def,
             service_object_decl,
             service_object_def,
             trange_decl,
             trange_def,
             icmp_group_decl,
             icmp_group_def,
             network_group_decl,
             network_group_def,
             service_proto_group_decl,
             service_proto_group_def,
             service_group_decl,
             service_group_def,
             protocol_group_decl,
             protocol_group_def,
             static_global_nat,
             static_object_nat,
             dynamic_global_nat,
             dynamic_object_nat,
           ]
  end

  # Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP
  #        D - EIGRP, EX - EIGRP external, O - OSPF, IA - OSPF inter area
  #        N1 - OSPF NSSA external type 1, N2 - OSPF NSSA external type 2
  #        E1 - OSPF external type 1, E2 - OSPF external type 2
  #        i - IS-IS, su - IS-IS summary, L1 - IS-IS level-1, L2 - IS-IS level-2
  #        ia - IS-IS inter area, * - candidate default, U - per-user static route
  #        o - ODR, P - periodic downloaded static route, + - replicated route
  defp route_code do
    [code:
      one_of([ [ ~r/^[LCSRMBDOiUoP]\*?$/,
                 ~r/^(EX|IA|N[12]|E[12]|su|L[12]|ia)?\+?$/
               ],
               ~r/^[LCSRMBDOiUoP]\*(EX|IA|N[12]|E[12]|su|L[12]|ia)\+?$/,
               ~r/^[LCSRMBDOiUoP]\*?$/,
             ])
    ]
  end

  def route do
    metric = [metric: [~r|^\[\d+/\d+\]$|]]
    next_hop =
      [next_hop: one_of([ [~w(is directly), {"connected", NetAddr.ip("0")}],
                          ["via", ipv4],
                        ])
      ]

    last_update = [last_update: [~r/^[0-9:mwdh]+$/]]

    [route:
      [ route_code,
        [network: [ipv4]], [mask: [ipv4]],
        maybe(metric),
        next_hop,
        maybe(last_update),
        [interface: maybe(nameif_name)],
      ]
    ]
  end
end
