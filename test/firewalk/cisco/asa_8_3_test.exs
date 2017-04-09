defmodule Firewalk.Cisco.ASA_8_3Test do
  use ExUnit.Case

  alias Firewalk.Cisco.ASA_8_3.{
    ExtendedACE,
    NetworkObject,
    NetworkGroup,
    ProtocolGroup,
    ServiceProtocolGroup,
  }

  import Firewalk.Cisco.ASA_8_3

  test "Correctly aggregates several aces from the same ACL" do
    lines = """
      access-list outside-egress extended permit udp object customer-tunnel-endpoint eq isakmp object cci-tunnel-endpoint eq isakmp log
      access-list outside-egress extended permit esp object customer-tunnel-endpoint object cci-tunnel-endpoint log
      access-list outside-egress extended permit ip any any log
    """ |> String.split("\n")

    aces = Enum.to_list parse(lines).acls["outside-egress"].aces

    assert length(aces) == 3
  end

  test "Handles orphaned network object declarations" do
    lines = """
      object network obj-192.0.2.1
    """ |> String.split("\n")

    assert parse(lines).objects != nil
  end

  test "Dynamic object NAT is not split" do
    lines = """
      object network obj_any
       nat (any,any) dynamic pat-pool pool extended flat
    """ |> String.split("\n")

    assert parse(lines).nats != nil
  end

  test "Object NAT does not clobber object definitions" do
    lines = """
      object network test
       host 192.0.2.1
      object network test
       nat (any,any) static 198.51.100.1
      """ |> String.split("\n")

    assert parse(lines).objects ==
      %OrderedMap{
        keys: ~w(test),
         map: %{
           "test" =>
              %NetworkObject{name: "test", value: NetAddr.ip("192.0.2.1")},
        },
        size: 1,
      }
  end

  test "Splits object tree by arbitrary coloring condition" do
    lines = """
      object network one
       host 192.0.2.1
      !
      object network two
       host 192.0.2.2
      !
      object-group network child
       network-object host 192.0.2.3
       network-object host 192.0.2.4
      !
      object-group network parent
       network-object 198.18.0.0 255.254.0.0
       network-object object two
       group-object child
      !
      object-group network grandparent
       network-object object one
       group-object parent
       network-object host 198.51.100.1
       network-object 203.0.113.0 255.255.255.0
    """ |> String.split("\n")

    objects = parse(lines).objects

    cf = fn term ->
      address =
        case term do
          %{value: %NetAddr.IPv4{} = value} -> value
          %{value: %NetAddr.IPv6{} = value} -> value
                   %NetAddr.IPv4{} = value  -> value
                   %NetAddr.IPv6{} = value  -> value
        end

      cond do
        NetAddr.contains?(NetAddr.ip("192.0.0.0/8"), address) -> "192"
        NetAddr.contains?(NetAddr.ip("198.0.0.0/8"), address) -> "198"
        NetAddr.contains?(NetAddr.ip("203.0.0.0/8"), address) -> "203"
        true -> nil
      end
    end

    sf = &Firewalk.Cisco.ASA_8_3.split_network_group_by_color/2

    assert Firewalk.Cisco.ASA_8_3.split_by_color("grandparent", objects, cf, sf) ==
      %{"192" =>
          [ %NetworkGroup{
              name: "grandparent-192",
              values: [{:object, "one"}, {:group, "parent-192"}],
            },
            %NetworkGroup{
              name: "parent-192",
              values: [object: "two", group: "child"],
            },
          ],
        "198" =>
          [ %NetworkGroup{
              name: "grandparent-198",
              values: [
                {:group, "parent-198"},
                %NetAddr.IPv4{address: <<198,51,100,1>>, length: 32},
              ],
            },
            %NetworkGroup{
              name: "parent-198",
              values: [%NetAddr.IPv4{address: <<198,18,0,0>>, length: 15}],
            },
          ],
        "203" =>
          [ %NetworkGroup{
              name: "grandparent-203",
              values: [%NetAddr.IPv4{address: <<203,0,113,0>>, length: 24}],
            },
          ],
      }
  end

  test "Explodes an ACE" do
    objects =
      [ {"one", %NetworkGroup{name: "one", values: [{:object, "a"}, {:object, "b"}]}},
      ] |> Enum.into(OrderedMap.new)

    ace = %ExtendedACE{acl_name: "test",
      action: :permit, protocol: 0, source: {:group, "one"}, destination: {:group, "one"}
    }

    assert explode(ace, objects, ~r/^o/) ==
      [ %ExtendedACE{acl_name: "test",
          action: :permit, protocol: 0, source: {:object, "a"}, destination: {:object, "a"}
        },
        %ExtendedACE{acl_name: "test",
          action: :permit, protocol: 0, source: {:object, "a"}, destination: {:object, "b"}
        },
        %ExtendedACE{acl_name: "test",
          action: :permit, protocol: 0, source: {:object, "b"}, destination: {:object, "a"}
        },
        %ExtendedACE{acl_name: "test",
          action: :permit, protocol: 0, source: {:object, "b"}, destination: {:object, "b"}
        },
      ]
  end

  test "Parses a protocol group" do
    lines = """
      object-group protocol DM_INLINE_PROTOCOL_5
       protocol-object ip
       protocol-object esp
       protocol-object ah
    """ |> String.split("\n")

    assert OrderedMap.values(parse(lines).objects)
      == [%ProtocolGroup{name: "DM_INLINE_PROTOCOL_5", values: [0, 50, 51]}]
  end

  test "Splits tcp-udp service protocol groups in object tree" do
    lines =
      """
      object-group service mixed-group tcp-udp
       port-object eq 53
      !
      object-group service root tcp-udp
       group-object mixed-group
       port-object eq 443
      """ |> String.split("\n")

    objects = parse(lines).objects

    assert Firewalk.Cisco.ASA_8_3.split_tcp_udp_service_group("root", objects) ==
      %{:tcp =>
          [ %ServiceProtocolGroup{
              name: "root-tcp",
              protocol: :tcp,
              values: [group: "mixed-group-tcp", eq: 443],
            },
            %ServiceProtocolGroup{
              name: "mixed-group-tcp",
              protocol: :tcp,
              values: [eq: 53]
            },
          ],
        :udp =>
          [ %ServiceProtocolGroup{
              name: "root-udp",
              protocol: :udp,
              values: [group: "mixed-group-udp", eq: 443],
            },
            %ServiceProtocolGroup{
              name: "mixed-group-udp",
              protocol: :udp,
              values: [eq: 53]
            },
          ],
      }
  end

  test "Splits different tcp-udp service protocol groups in object tree" do
    lines =
      """
      object-group service mixed-group tcp-udp
       port-object eq 53
      !
      object-group service root udp
       group-object mixed-group
       port-object eq 443
      """ |> String.split("\n")

    objects = parse(lines).objects

    assert Firewalk.Cisco.ASA_8_3.split_tcp_udp_service_group("root", objects) ==
      %{:udp =>
          [ %ServiceProtocolGroup{
              name: "root",
              protocol: :udp,
              values: [group: "mixed-group-udp", eq: 443],
            },
            %ServiceProtocolGroup{
              name: "mixed-group-udp",
              protocol: :udp,
              values: [eq: 53],
            },
          ],
        :tcp =>
          [ %ServiceProtocolGroup{
              name: "mixed-group-tcp",
              protocol: :tcp,
              values: [eq: 53],
            },
          ],
      }
  end

  test "Explodes a network object-group" do
    lines =
      """
      object-group network child
       network-object 198.51.100.0 255.255.255.0
      !
      object-group network parent
       group-object child
       network-object host 192.0.2.1
      """ |> String.split("\n")

    objects = parse(lines).objects

    assert Firewalk.Cisco.ASA_8_3.explode(objects["parent"], objects) ==
      [NetAddr.ip("198.51.100.0/24"), NetAddr.ip("192.0.2.1")]
  end
end
