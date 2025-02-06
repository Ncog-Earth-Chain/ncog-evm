**Go Ethereum over forest**
Note

Repo is the github.com/ethereum/go-ethereum fork. It should be in the same local path as original: $GOPATH/src/github.com/ethereum/.
Aims

Ethereum over forest network and consensus. Full ethereum stack and forest performance.
Demo

    start forest test net first: cd $GOPATH/src/github.com/Ncog-Earth-Chain/go-ncogearthchain/demo && make start;
    change dir: cd forest/demo;
    make geth docker image and run 2 containers: make && make start;
    try to send tx: ./20.txn.sh;
    try to get balanses: ./10.balances.sh;
    stop docker containers: make stop;
    stop forest test net;

Changes

    Rename p2p.Server to p2p.p2pServer;
    Create p2p/interface.go (p2p.ServerInterface, p2p.Server struct, p2p.p2pServer's additionals methods, p2p.forestAdapter interface);
    Create eth/forest.go (p2p.ForestAdapter implementation);
    Add p2p.Config.ForestAdapter ForestAdapter;
    Create ForestAddrFlag in cmd/utils/flags.go:

        ForestAddrFlag = cli.StringFlag{
    	Name:  "forest",
    	Usage: "forest-node address",
    }
    . . .
    func setListenAddress(ctx *cli.Context, cfg *p2p.Config) {
    	. . .
    	if ctx.GlobalIsSet(ForestAddrFlag.Name) {
    		cfg.ForestAdapter = eth.NewForestAdapter(ctx.GlobalString(ForestAddrFlag.Name), cfg.Logger)
    	}
    }

    Append utils.ForestAddrFlag to:
        nodeFlags in cmd/geth/main.go;
        AppHelpFlagGroups in cmd/geth/usage.go;
        app.Flags in cmd/swarm/main.go;
    Make node.Node create .server according to .serverConfig.ForestAdapter and use p2p.Server.AddProtocols() at .Start():

    var running *p2p.Server
    if n.serverConfig.ForestAdapter == nil {
    	running = p2p.NewServer(n.serverConfig)
    	n.log.Info("Starting peer-to-peer node", "instance", n.serverConfig.Name)
    } else {
    	running = forest.NewServer(n.serverConfig)
    	n.log.Info("Using forest node", "address", n.serverConfig.ForestAdapter.Address())
    }
    . . .
    for _, service := range services {
    	running.AddProtocols(service.Protocols()...)
    }

    Create forest/ package;

TODO:

    make ethereum blocks from forest commits at eth.forestAdapter without mining;
    switch forest/demo/docker/Dockerfile.geth* from local to origin "github.com/Ncog-Earth-Chain/go-ncogearthchain" when stable;
