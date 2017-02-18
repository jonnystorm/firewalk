defmodule Firewalk.Cisco.ASA_8_3Test do
  use ExUnit.Case

  alias Firewalk.Cisco.ASA_8_3.NetworkObject

  import Firewalk.Cisco.ASA_8_3

  test "Correctly aggregates several aces from the same ACL" do
    test = """
      access-list outside-egress extended permit udp object customer-tunnel-endpoint eq isakmp object cci-tunnel-endpoint eq isakmp log
      access-list outside-egress extended permit esp object customer-tunnel-endpoint object cci-tunnel-endpoint log
      access-list outside-egress extended permit ip any any log
    """ |> String.split("\n")

    assert length(parse(test).acls["outside-egress"].aces) == 3
  end

  test "Handles orphaned network object declarations" do
    test = """
      object network obj-192.0.2.1
    """ |> String.split("\n")

    assert parse(test).objects != nil
  end

  test "Dynamic object NAT is not split" do
    test = """
      object network obj_any
       nat (any,any) dynamic pat-pool pool extended flat
    """ |> String.split("\n")

    assert parse(test).nats != nil
  end

  test "Object NAT does not clobber object definitions" do
    test = """
      object network test
       host 192.0.2.1
      object network test
       nat (any,any) static 198.51.100.1
      """ |> String.split("\n")

    assert parse(test).objects ==
      %OrderedMap{
        keys: ~w(test),
         map: %{
           "test" =>
              %NetworkObject{name: "test", value: NetAddr.ip("192.0.2.1")},
        },
        size: 1,
      }
  end
end
