package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"go.etcd.io/etcd/clientv3"
	"go.etcd.io/etcd/clientv3/clientv3util"
	"go.etcd.io/etcd/clientv3/concurrency"
)

var cli *clientv3.Client

type ipamInfo struct {
	IpamType   string `json:"type"`
	Subnet     string `json:"subnet"`
	RangeStart string `json:"rangeStart"`
	RangeEnd   string `json:"rangeEnd"`
}

type InitNetConf struct {
	CniVersion  string   `json:"cniVersion"`
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	BrName      string   `json:"bridge"`
	BrType      string   `json:"bridgeType"`
	BrIP        string   `json:"bridgeIPv4"`
	IsGW        bool     `json:"isGateway"`
	IsDefaultGW bool     `json:"isDefaultGateway"`
	IPMasq      bool     `json:"isIPMasq"`
	Network     ipamInfo `json:"ipam"`
	PodCIDR     string   `json:"podCIDR"`
	NodeBits    string   `json:"nodeBits"`
	DataStore   string   `json:"dataStore"`
	AuthEnabled bool     `json:"auth"`
}

func connectToEtcd(storeAddress string, user string, passkey string) {
	var err error
	user = strings.TrimSpace(user)
	passkey = strings.TrimSpace(passkey)
	if user != "" {
		cli, err = clientv3.New(clientv3.Config{
			Endpoints:   []string{storeAddress},
			DialTimeout: 5 * time.Second,
			Username:    user,
			Password:    passkey,
		})
	} else {
		cli, err = clientv3.New(clientv3.Config{
			Endpoints:   []string{storeAddress},
			DialTimeout: 5 * time.Second,
		})
	}
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(2)
	}
}
func genRangesForHosts(podCIDR string, nodePrefix int) []string {
	ip, podNet, _ := net.ParseCIDR(podCIDR)
	cidrPrefix, _ := strconv.Atoi(strings.Split(podCIDR, "/")[1])
	baseAddress := ip.Mask(net.CIDRMask(cidrPrefix, 32))
	log.Println("baseAddress", baseAddress, "podNet", podNet, "cidrPrefix", cidrPrefix)
	_, ipnet, _ := net.ParseCIDR(baseAddress.String() + "/" + strconv.Itoa(nodePrefix))
	baseMask := ipnet.Mask
	maxMask := net.CIDRMask(32, 32)
	mm := binary.BigEndian.Uint32(maxMask)
	bm := binary.BigEndian.Uint32(baseMask)
	addRange := mm - bm
	log.Println("Range is ", addRange)
	aR := make([]byte, 4)
	binary.BigEndian.PutUint32(aR, addRange)
	fmt.Println(aR)
	ba := binary.BigEndian.Uint32(baseAddress)
	log.Println("baseAddress", baseAddress, "ba", ba)
	firstNet := ba + addRange
	log.Println("firstNet in BigEndian format", firstNet)
	numRanges := math.Pow(2, float64(nodePrefix-cidrPrefix))
	hostRanges := make([]string, 0, int(numRanges))
	for addressBound, i := firstNet, 0; i < int(numRanges); i++ {
		bS := make([]byte, 4)
		binary.BigEndian.PutUint32(bS, addressBound)
		bridgeAddress := net.IP(bS).Mask(baseMask)
		bridgeAddress[3]++
		firstAddress := net.IP(bS).Mask(baseMask) // do not want to copy bridgeAddress
		firstAddress[3] += 2
		lastAddress := net.IP(bS).To4()
		lastAddress[3]--
		addressBound = addressBound + addRange + 1
		hostRanges = append(hostRanges, firstAddress.String()+","+lastAddress.String()+","+bridgeAddress.String()+"/"+strconv.Itoa(cidrPrefix))
	}
	return hostRanges
}

func getNodeSubnet(podCIDR string, nodePrefix int) string {
	var selectedRange string
	candidates := genRangesForHosts(podCIDR, nodePrefix)
	s, _ := concurrency.NewSession(cli)
	defer s.Close()
	lock := concurrency.NewMutex(s, "/evpn/evio-lock/")
	ctx := context.TODO()
	if err := lock.Lock(ctx); err != nil {
		log.Println("Could not get Lock on store")
	}
	kv := clientv3.NewKV(cli)
	keyPrefix := "/evpn/"
	for _, hostRange := range candidates {
		resp, err := kv.Txn(context.TODO()).
			If(clientv3util.KeyMissing(keyPrefix + hostRange)).
			Then(clientv3.OpPut(keyPrefix+hostRange, "ok")).
			Commit()
		if resp.Succeeded {
			log.Printf("Successfully reserved hostRange %v on Store", hostRange)
			selectedRange = hostRange
			break
		}
		if err != nil {
			log.Printf("%v", err)
		}
	}
	if err := lock.Unlock(ctx); err != nil {
		log.Println("Failed to release lock on store")
	}
	if len(selectedRange) == 0 {
		log.Println("Could not reserve any range on the Store.")
	}
	return selectedRange
}

func loadBasicConf(bytes []byte) (*InitNetConf, error) {
	initialNetConf := &InitNetConf{}
	if err := json.Unmarshal(bytes, initialNetConf); err != nil {
		log.Printf("ERROR")
		return nil, fmt.Errorf("failed to inital load network configuration: %v", err)
	}
	log.Printf("%+v", *initialNetConf)
	initialNetConf.Network.Subnet = initialNetConf.PodCIDR
	initialNetConf.Network.IpamType = "host-local"
	initialNetConf.Network.RangeStart = ""
	initialNetConf.Network.RangeEnd = ""
	if initialNetConf.AuthEnabled {
		var username, password string
		log.Printf("Auth enabled\n")
		b, err := ioutil.ReadFile("/etc/credentials/username")
		if err != nil {
			log.Println(err.Error())
		}
		username = string(b)
		b, err = ioutil.ReadFile("/etc/credentials/password")
		if err != nil {
			log.Println(err.Error())
		}
		password = string(b)
		connectToEtcd(initialNetConf.DataStore, username, password)
	} else {
		connectToEtcd(initialNetConf.DataStore, "", "")
	}
	log.Printf("%+v", *initialNetConf)
	return initialNetConf, nil
}

func SetUpNodeAddressRange() {
	cniFile := "/etc/cni/net.d/10-evio.conf"
	//check if prefix file already exists.
	_, err := os.Stat(cniFile)
	if os.IsNotExist(err) {
		jsonFile, err := os.Open("/etc/evioCNI/net-conf.json")
		if err != nil {
			fmt.Println(err)
		}
		log.Println("Successfully Opened file")
		// defer the closing of our jsonFile so that we can parse it later on
		defer jsonFile.Close()
		byteValue, _ := ioutil.ReadAll(jsonFile)
		icf, _ := loadBasicConf(byteValue)
		podCIDR := icf.Network.Subnet
		podPrefix, _ := strconv.Atoi(strings.Split(podCIDR, "/")[1])
		nodeBits, _ := strconv.Atoi(icf.NodeBits)
		nodePrefix := podPrefix + nodeBits
		if 32-nodePrefix < 2 {
			log.Println("Not sufficient addresses for pods on host, allocate fewer bits for nodes")
			return
		}
		hostRange := strings.Split(getNodeSubnet(podCIDR, nodePrefix), ",")
		// manipulate RangeStart, first address in range reserved for gateway switch.
		icf.Network.RangeStart = hostRange[0]
		icf.Network.RangeEnd = hostRange[1]
		icf.BrIP = hostRange[2]
		log.Printf("startAddress %s, endAddress %s", icf.Network.RangeStart, icf.Network.RangeEnd)
		log.Printf("%+v", *icf)
		file, err := json.MarshalIndent(icf, "", " ")
		if err != nil {
			fmt.Println(err)
			return
		}
		_ = ioutil.WriteFile(cniFile, file, 0644)
	} else {
		log.Printf("CNI file %s already exists", cniFile)
		return
	}
}

func main() {
	SetUpNodeAddressRange()
}
