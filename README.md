# evioPlugin
CNI plugin for EdgeVPN - Enhanced version of bridge plugin to work with OVS and utility to allocate IP address range 
to nodes and generate config file for the plugin.
Dependency on github.com/containernetworking tag v0.7.5  
``` 
mkdir -p $GOPATH/src/github.com/containernetworking
cd $GOPATH/src/github.com/containernetworking
git clone https://github.com/containernetworking/plugins.git
cd plugins
git checkout tags/v0.7.5
cd plugins/main/
git clone https://github.com/EdgeVPNio/evioPlugin.git
```  
  
 Now need to download a few dependencies.  
 ```
 go get github.com/j-keck/arping
 go get github.com/vishvananda/netlink
 go get github.com/digitalocean/go-openvswitch/ovs
 go get go.etcd.io/etcd/clientv3
 ```  
   
 We will need three executables, for the plugin, config-gen evioUtililty and for
 host-local IPAM plugin.  
 ```
 # assuming you are in $GOPATH/src/github.com/containernetworking/plugins/plugins/main/evioPlugin/src
 go build evioPlugin.go  
 go build evioUtilities.go
 cd $GOPATH/src/github.com/containernetworking/plugins/plugins/ipam/host-local
 go build
 ```  
   
 Now we need to copy all three executables to the deployment folder.  
 ```
 cd $GOPATH/src/github.com/containernetworking/plugins/plugins/main/evioPlugin/deployment
 cp $GOPATH/src/github.com/containernetworking/plugins/plugins/ipam/host-local/host-local .
 cp $GOPATH/src/github.com/containernetworking/plugins/plugins/main/evioPlugin/src/evioPlugin .
 cp $GOPATH/src/github.com/containernetworking/plugins/plugins/main/evioPlugin/src/evioUtilities .
 ```   
   
 Build the docker image.  
   
```
docker build -t evio_plugin:0.0 -f evioCNI.dockerfile .
```
