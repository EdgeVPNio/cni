package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ipam"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/utils"
	"github.com/digitalocean/go-openvswitch/ovs"
	"github.com/j-keck/arping"
	"github.com/vishvananda/netlink"
)

type NetConf struct {
	types.NetConf
	BrName      string `json:"bridge"`
	BrType      string `json:"bridgeType"`
	BrIP        string `json:"bridgeIPv4"`
	IsGW        bool   `json:"isGateway"`
	IsDefaultGW bool   `json:"isDefaultGateway"`
	IPMasq      bool   `json:"isIPMasq"`
	subnetPath  string `json:"subnetPath"`
}

type gwInfo struct {
	gws               []net.IPNet
	family            int
	defaultRouteFound bool
}

func loadNetConf(bytes []byte) (*NetConf, string, error) {
	n := &NetConf{}
	if err := json.Unmarshal(bytes, n); err != nil {
		return nil, "", fmt.Errorf("failed to load network configuration: %v", err)
	}
	log.Printf("%+v", *n)
	return n, n.CNIVersion, nil
}

func configureBridgeInterface(bridgeName string, gatewayAddress string) error {

	i, err := net.InterfaceByName(bridgeName)
	if err != nil {
		log.Println("Bridge interface not found.")
		return err
	}
	ipv4set := false
	var ip net.IP
	ipv4 := ""

	addrs, err := i.Addrs()
	if err != nil {
		log.Println("Could not get addresses associated with the bridge.")
		return err
	}
	for _, addr := range addrs {
		switch v := addr.(type) {
		case *net.IPAddr:
			ip = v.IP
		case *net.IPNet:
			ip = v.IP
		}
		log.Printf("Bridge address %s\n", addr.String())
		if ip.To4() != nil {
			if strings.Compare(gatewayAddress, addr.String()) == 0 {
				log.Printf("Interface %s already configured with address %s\n", bridgeName, addr.String())
				ipv4set = true
			} else {
				ipv4 = addr.String()
			}
		}
	}
	if ipv4set == true {
		return nil
	}
	// need to assign gateway address to switch and bring it up.
	ipExecutable, err := exec.LookPath("ip")
	if err != nil {
		log.Println("failed to locate executable ip")
		return err
	}
	if ipv4 != "" {
		log.Println(" some other ipv4 address %s is assigned in place of %s ", ipv4, gatewayAddress)
	}
	cmdDelIP := &exec.Cmd{
		Path: ipExecutable,
		Args: []string{ipExecutable, "addr", "del", ipv4, "dev", bridgeName},
	}
	if ipv4 != "" {
		if output, err := cmdDelIP.Output(); err != nil {
			log.Println(err.Error())
			return err
		} else {
			log.Println(output)
		}
	}
	cmdSetIP := &exec.Cmd{
		Path: ipExecutable,
		Args: []string{ipExecutable, "addr", "add", gatewayAddress, "dev", bridgeName},
	}
	if output, err := cmdSetIP.Output(); err != nil {
		log.Println(err.Error())
		return err
	} else {
		log.Println(output)
	}

	cmdBringUP := &exec.Cmd{
		Path: ipExecutable,
		Args: []string{ipExecutable, "link", "set", bridgeName, "up"},
	}
	if output, err := cmdBringUP.Output(); err != nil {
		log.Println(err.Error())
		return err
	} else {
		log.Println(output)
	}
	return nil
}

func setupBridge(netconf *NetConf) (*netlink.Bridge, *current.Interface, error) {
	br := &netlink.Bridge{
		LinkAttrs: netlink.LinkAttrs{
			Name:   netconf.BrName,
			MTU:    1500,
			TxQLen: -1,
		},
	}
	// this section adds and sets up a linux bridge
	if netconf.BrType == "LXBR" {
		err := netlink.LinkAdd(br)
		if err != nil && err != syscall.EEXIST {
			return nil, nil, err
		}

		if err := netlink.LinkSetUp(br); err != nil {
			return nil, nil, err
		}
	} else if netconf.BrType == "OVS" {
		// setting up an ovs bridge
		ovsClient := ovs.New(ovs.Sudo())
		if err := ovsClient.VSwitch.AddBridge(br.Attrs().Name); err != nil {
			log.Fatalf("failed to add OVS bridge: %v", err)
		}
	}
	return br, &current.Interface{
		Name: br.Attrs().Name,
		Mac:  br.Attrs().HardwareAddr.String(),
	}, nil
}

func setupVeth(br *netlink.Bridge, netconf *NetConf, args *skel.CmdArgs) (*current.Interface, *current.Interface, error) {
	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		log.Fatalf("Could not find network namespace %v", err)
		return nil, nil, fmt.Errorf("Could not find network namespace %v", err)
	}
	contIface := &current.Interface{}
	hostIface := &current.Interface{}
	var handler = func(hostNS ns.NetNS) error {
		hostVeth, containerVeth, err := ip.SetupVeth(args.IfName, 1500, hostNS)
		if err != nil {
			return err
		}
		contIface.Name = containerVeth.Name
		contIface.Mac = containerVeth.HardwareAddr.String()
		contIface.Sandbox = netns.Path()
		hostIface.Name = hostVeth.Name
		log.Printf("Created pod veth interface: %v\n", containerVeth.Name)
		return nil
	}
	if err := netns.Do(handler); err != nil {
		return nil, nil, err
	}
	hostVeth, err := netlink.LinkByName(hostIface.Name)
	if err != nil {
		return nil, nil, err
	}
	log.Printf("Located host veth interface: %v\n", hostVeth.Attrs().Name)
	hostIface.Mac = hostVeth.Attrs().HardwareAddr.String()
	if netconf.BrType == "LXBR" {
		// below attaches veth interface to the bridge.
		if err := netlink.LinkSetMaster(hostVeth, br); err != nil {
			return nil, nil, err
		}
	} else if netconf.BrType == "OVS" {
		// below attaches veth interface to ovs bridge
		ovsClient := ovs.New(ovs.Sudo())
		if err := ovsClient.VSwitch.AddPort(br.Attrs().Name, hostIface.Name); err != nil {
			log.Printf("failed to add %v to bridge %v error %v", hostIface.Name, br.Attrs().Name, err)
		}
		log.Printf("Attached %v to %v\n", hostVeth.Attrs().Name, br.Name)
	}
	return hostIface, contIface, nil

}

func cmdAdd(args *skel.CmdArgs) error {
	n, cniVersion, err := loadNetConf(args.StdinData)
	if err != nil {
		return err
	}

	log.Printf("%v\t %v\t %v", args.ContainerID, args.IfName, args.Netns)
	log.Println("parsed configuration successfully !")
	br, brInterface, err := setupBridge(n)
	if err != nil {
		return err
	}
	log.Printf("set up bridge %v successfully !\n", br.Name)
	// set up IP address on the bridge and bring it up.
	err = configureBridgeInterface(n.BrName, n.BrIP)
	if err != nil {
		log.Println("Failure in configuring bridge.")
		return err
	}
	hostInterface, containerInterface, err := setupVeth(br, n, args)
	if err != nil {
		log.Println("Failure in setting up Veth interfaces.")
		return err
	}
	log.Println("set up veth interfaces successfully !")

	result := &current.Result{CNIVersion: cniVersion, Interfaces: []*current.Interface{brInterface, hostInterface, containerInterface}}
	r, err := ipam.ExecAdd(n.IPAM.Type, args.StdinData)
	if err != nil {
		return err
	}
	var success bool = false
	// release IP in case of failure
	defer func() {
		if !success {
			os.Setenv("CNI_COMMAND", "DEL")
			ipam.ExecDel(n.IPAM.Type, args.StdinData)
			os.Setenv("CNI_COMMAND", "ADD")
		}
	}()

	// Convert whatever the IPAM result was into the current Result type
	ipamResult, err := current.NewResultFromResult(r)
	if err != nil {
		log.Printf("could not convert IPAM result %+v \n", ipamResult)
		return err
	}
	log.Printf("result from IPAM : %+v\n", ipamResult)
	result.IPs = ipamResult.IPs
	result.Routes = ipamResult.Routes

	if len(result.IPs) == 0 {
		log.Printf("IPAM plugin provided no IP config\n")
		return errors.New("IPAM plugin returned missing IP config")
	}
	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		log.Printf("could not find namespace %v", args.Netns)
		return err
	}
	for _, ipc := range result.IPs {
		ipc.Interface = current.Int(2)
	}

	gwsV4, gwsV6, err := calcGateways(result, n)
	if err != nil {
		return err
	}
	// Configure the container hardware address and IP address(es)
	if err := netns.Do(func(_ ns.NetNS) error {
		contVeth, err := net.InterfaceByName(args.IfName)
		if err != nil {
			log.Printf("could not find interface %v", contVeth.Name)
			return err
		}
		// Add the IP to the interface
		if err := ipam.ConfigureIface(args.IfName, result); err != nil {
			log.Printf("could not configure IP address on the interface %v", args.IfName)
			return err
		}

		// Send a gratuitous arp
		for _, ipc := range result.IPs {
			if ipc.Version == "4" {
				_ = arping.GratuitousArpOverIface(ipc.Address.IP, *contVeth)
			}
		}
		return nil
	}); err != nil {
		log.Printf("something went wrong while trying to configure IP address on the interface !")
		return err
	}
	if n.IsGW {
		// Set the IP address(es) on the bridge and enable forwarding
		for _, gws := range []*gwInfo{gwsV4, gwsV6} {
			if gws.gws != nil {
				if err = enableIPForward(gws.family); err != nil {
					return fmt.Errorf("failed to enable forwarding: %v", err)
				}
			}
		}
	}

	if n.IPMasq {
		chain := utils.FormatChainName(n.Name, args.ContainerID)
		comment := utils.FormatComment(n.Name, args.ContainerID)
		for _, ipc := range result.IPs {
			if err = ip.SetupIPMasq(ip.Network(&ipc.Address), chain, comment); err != nil {
				log.Printf("something went wrong while to set up IPMasq %v!", err)
				return err
			}
			log.Printf("IPMasq set up successfully !!")
		}
	}
	if n.BrType == "LXBR" {
		// commented out because accesses variables set when setting linux bridges
		l, err := netlink.LinkByName(br.Name)
		if err != nil {
			log.Printf("could not lookup %q: %v", br.Name, err)
		}
		br, ok := l.(*netlink.Bridge)
		if !ok {
			log.Printf("%q already exists but is not a bridge", br.Name)
		}
	}
	log.Printf("result %v\n", result)
	return types.PrintResult(result, cniVersion)
}

func clearDeadPortsOnBridge(brName string) {
	ovsClient := ovs.New(ovs.Sudo())
	listOfPorts, err := ovsClient.VSwitch.ListPorts(brName)
	// dead interfaces are cleared and interfaces deleted outside cni plugin, just check and remove from
	// the bridge, happens for previously deleted namespaces not the current one being deleted.
	if err != nil {
		log.Printf("Could not list ports on bridge %s, error is %v", brName, err.Error())
	} else {
		for _, portName := range listOfPorts {
			_, err := netlink.LinkByName(portName)
			if err != nil {
				if err = ovsClient.VSwitch.DeletePort(brName, portName); err != nil {
					log.Printf("failed to remove %v from bridge %v error %v", brName, portName, err)
				}
			}
		}
	}
}
func cmdDel(args *skel.CmdArgs) error {
	n, _, err := loadNetConf(args.StdinData)
	if err != nil {
		return err
	}

	log.Printf("%v\t %v\t %v", args.ContainerID, args.IfName, args.Netns)
	log.Println("Delete: parsed configuration successfully !")
	if args.Netns == "" {
		return nil
	}
	var ipnets []*net.IPNet
	err = ns.WithNetNSPath(args.Netns, func(_ ns.NetNS) error {
		var err error
		ipnets, err = ip.DelLinkByNameAddr(args.IfName)
		if err != nil && err == ip.ErrLinkNotFound {
			log.Printf("could not delete NS interface %v", err.Error())
			return nil
		}
		return err
	})
	if n.IPMasq {
		chain := utils.FormatChainName(n.Name, args.ContainerID)
		comment := utils.FormatComment(n.Name, args.ContainerID)
		for _, ipn := range ipnets {
			if err := ip.TeardownIPMasq(ipn, chain, comment); err != nil {
				log.Printf("could not reset IPMasq %v", err.Error())
				return err
			}
		}
	}
	if n.BrType == "OVS" {
		clearDeadPortsOnBridge(n.BrName)
	}
	if n.IPAM.Type != "" {
		if err := ipam.ExecDel(n.IPAM.Type, args.StdinData); err != nil {
			log.Printf("could not clear out IPAM %v", err.Error())
			return err
		}
	}

	return nil
}


func main() {
	skel.PluginMain(cmdAdd,  cmdDel, version.All)
}

func enableIPForward(family int) error {
	if family == netlink.FAMILY_V4 {
		return ip.EnableIP4Forward()
	}
	return ip.EnableIP6Forward()
}

func calcGateways(result *current.Result, n *NetConf) (*gwInfo, *gwInfo, error) {

	gwsV4 := &gwInfo{}
	gwsV6 := &gwInfo{}

	for _, ipc := range result.IPs {

		// Determine if this config is IPv4 or IPv6
		var gws *gwInfo
		defaultNet := &net.IPNet{}
		switch {
		case ipc.Address.IP.To4() != nil:
			gws = gwsV4
			gws.family = netlink.FAMILY_V4
			defaultNet.IP = net.IPv4zero
		case len(ipc.Address.IP) == net.IPv6len:
			gws = gwsV6
			gws.family = netlink.FAMILY_V6
			defaultNet.IP = net.IPv6zero
		default:
			return nil, nil, fmt.Errorf("Unknown IP object: %v", ipc)
		}
		defaultNet.Mask = net.IPMask(defaultNet.IP)

		// All IPs currently refer to the container interface
		ipc.Interface = current.Int(2)

		if n.IsGW {
			ipc.Gateway = getGatewayIP(n)
		}

		// Add a default route for this family using the current
		// gateway address if necessary.
		if n.IsDefaultGW && !gws.defaultRouteFound {
			for _, route := range result.Routes {
				if route.GW != nil && defaultNet.String() == route.Dst.String() {
					gws.defaultRouteFound = true
					break
				}
			}
			if !gws.defaultRouteFound {
				result.Routes = append(
					result.Routes,
					&types.Route{Dst: *defaultNet, GW: ipc.Gateway},
				)
				gws.defaultRouteFound = true
			}
		}

		// Append this gateway address to the list of gateways
		if n.IsGW {
			gw := net.IPNet{
				IP:   ipc.Gateway,
				Mask: ipc.Address.Mask,
			}
			gws.gws = append(gws.gws, gw)
		}
	}
	return gwsV4, gwsV6, nil
}

func calcGatewayIP(ipn *net.IPNet) net.IP {
	nid := ipn.IP.Mask(ipn.Mask)
	return ip.NextIP(nid)
}

func getGatewayIP(n *NetConf) net.IP {
	gwIP := net.ParseIP(strings.Split(n.BrIP, "/")[0])
	log.Printf("Gateway IPv4 address for bridge is %v !!", gwIP.String())
	return gwIP
}

func init() {
	// this ensures that main runs only on main thread (thread group leader).
	// since namespace ops (unshare, setns) are done for a single thread, we
	// must ensure that the goroutine does not jump from OS thread to thread
	runtime.LockOSThread()
	file, err := os.OpenFile("/var/log/evioPlugin.log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		log.Fatal(err)
	}
	log.SetOutput(file)
}
