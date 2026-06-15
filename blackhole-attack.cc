#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/mobility-module.h"
#include "ns3/wifi-module.h"
#include "ns3/internet-module.h"
#include "ns3/aodv-module.h"
#include "ns3/netanim-module.h"
#include "ns3/applications-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/aodv-packet.h"

using namespace ns3;
NS_LOG_COMPONENT_DEFINE("ProtocolLevelBlackhole");

AnimationInterface *g_anim = 0;
uint32_t g_dropCount = 0;

// ============================================================================
// MALICIOUS BLACKHOLE INTERCEPTION LOGIC
// ============================================================================
class MaliciousAodvProtocol : public aodv::RoutingProtocol
{
public:
    static TypeId GetTypeId (void)
    {
        static TypeId tid = TypeId ("ns3::aodv::MaliciousAodvProtocol")
            .SetParent<aodv::RoutingProtocol> ()
            .SetGroupName ("Aodv")
            .AddConstructor<MaliciousAodvProtocol> ();
        return tid;
    }

    MaliciousAodvProtocol () : aodv::RoutingProtocol () {}
    virtual ~MaliciousAodvProtocol () {}

    virtual bool RouteInput (Ptr<const Packet> p, const Ipv4Header &header, 
                             Ptr<const NetDevice> idev, const UnicastForwardCallback &ucb, 
                             const MulticastForwardCallback &mcb, const LocalDeliverCallback &lcb, 
                             const ErrorCallback &ecb) override
    {
        if (header.GetProtocol () == 17) // 17 = UDP
        {
            g_dropCount++;
            if (g_anim)
            {
                Ptr<Node> node = this->GetObject<Node>();
                g_anim->UpdateNodeDescription (node, "BLACKHOLE DROP #" + std::to_string(g_dropCount));
                g_anim->UpdateNodeColor (node, 255, 0, 0); 
            }
            NS_LOG_UNCOND("[ATTACK SUCCESS] -> Intercepted and dropped packet from " 
                          << header.GetSource() << " to " << header.GetDestination());
            return true; 
        }

        Ptr<Packet> pCopy = p->Copy();
        uint8_t packetType;
        pCopy->CopyData(&packetType, 1);

        if (packetType == 1) // Type 1 = RREQ
        {
            pCopy->RemoveAtStart(1);
            aodv::RreqHeader rreqHeader;
            pCopy->RemoveHeader(rreqHeader);

            NS_LOG_UNCOND("[RREQ INTERCEPTED] Forging reply for destination: " << rreqHeader.GetDst());
            
            aodv::RrepHeader fakeRrep;
            fakeRrep.SetHopCount (1);
            fakeRrep.SetDstSeqno (rreqHeader.GetDstSeqno () + 99999); 
            fakeRrep.SetDst (rreqHeader.GetDst ());
            fakeRrep.SetOrigin (rreqHeader.GetOrigin ());
            fakeRrep.SetLifeTime (Seconds (30.0));

            Ptr<Packet> replyPacket = Create<Packet> ();
            replyPacket->AddHeader (fakeRrep);
            
            aodv::TypeHeader typeHeader (aodv::AODVTYPE_RREP);
            replyPacket->AddHeader (typeHeader);

            Ptr<Node> node = this->GetObject<Node>();
            Ptr<UdpL4Protocol> udp = node->GetObject<UdpL4Protocol>();
            if (udp)
            {
                Ptr<Socket> socket = udp->CreateSocket();
                if (socket)
                {
                    socket->BindToNetDevice(node->GetDevice(0));
                    socket->Connect(InetSocketAddress(header.GetSource(), 654)); 
                    socket->Send(replyPacket);
                    socket->Close();
                }
            }
            return true;
        }

        return aodv::RoutingProtocol::RouteInput (p, header, idev, ucb, mcb, lcb, ecb);
    }
};

class MaliciousAodvHelper : public Ipv4RoutingHelper
{
public:
    MaliciousAodvHelper () {}
    virtual ~MaliciousAodvHelper () {}
    virtual Ptr<Ipv4RoutingProtocol> Create (Ptr<Node> node) const override
    {
        Ptr<MaliciousAodvProtocol> routing = CreateObject<MaliciousAodvProtocol> ();
        node->AggregateObject (routing);
        return routing;
    }
    virtual MaliciousAodvHelper* Copy (void) const override { return new MaliciousAodvHelper (*this); }
};

// ============================================================================
// MAIN SIMULATION LOOP
// ============================================================================
int main (int argc, char *argv[])
{
    uint32_t numNodes = 15;
    double simTime = 16.0;
    uint32_t attackerNode = 5;

    NodeContainer nodes;
    nodes.Create (numNodes);

    WifiHelper wifi;
    wifi.SetStandard (WIFI_STANDARD_80211b);
    wifi.SetRemoteStationManager ("ns3::ConstantRateWifiManager",
                                  "DataMode",    StringValue ("DsssRate11Mbps"),
                                  "ControlMode", StringValue ("DsssRate1Mbps"));

    YansWifiPhyHelper phy;
    YansWifiChannelHelper channel = YansWifiChannelHelper::Default ();
    
    phy.Set ("TxPowerStart", DoubleValue (20.0));
    phy.Set ("TxPowerEnd", DoubleValue (20.0));
    phy.SetChannel (channel.Create ());

    WifiMacHelper mac;
    mac.SetType ("ns3::AdhocWifiMac");
    NetDeviceContainer devices = wifi.Install (phy, mac, nodes);

    AnimationInterface anim ("/home/vboxuser/ns-allinone-3.40/ns-3.40/animations/blackhole-attack.xml");
    g_anim = &anim;
    anim.SetStartTime (Seconds (0.0));
    anim.SetStopTime (Seconds (simTime));
    anim.EnablePacketMetadata (true);

    for (uint32_t i = 0; i < numNodes; i++)
    {
        anim.UpdateNodeColor (nodes.Get (i), 200, 200, 200);
        anim.UpdateNodeSize (nodes.Get (i), 5.0, 5.0);
        anim.UpdateNodeDescription (nodes.Get (i), "Node_" + std::to_string (i));
    }

    anim.UpdateNodeColor (nodes.Get (0), 0, 0, 255);  
    anim.UpdateNodeDescription (nodes.Get (0), "SOURCE (N0)");
    anim.UpdateNodeColor (nodes.Get (attackerNode), 120, 0, 0); 
    anim.UpdateNodeDescription (nodes.Get (attackerNode), "MALICIOUS (N5)");
    anim.UpdateNodeColor (nodes.Get (14), 0, 255, 0); 
    anim.UpdateNodeDescription (nodes.Get (14), "DEST (N14)");

    // ============================================================================
    // VISUALLY APPEALING GRID LAYOUT
    // ============================================================================
    MobilityHelper mobility;
    Ptr<ListPositionAllocator> posAlloc = CreateObject<ListPositionAllocator> ();
    
    // Seed random variables for node placement scatter
    Ptr<UniformRandomVariable> randX = CreateObject<UniformRandomVariable> ();
    randX->SetAttribute ("Min", DoubleValue (20.0));
    randX->SetAttribute ("Max", DoubleValue (140.0));
    
    Ptr<UniformRandomVariable> randY = CreateObject<UniformRandomVariable> ();
    randY->SetAttribute ("Min", DoubleValue (10.0));
    randY->SetAttribute ("Max", DoubleValue (90.0));

    for (uint32_t i = 0; i < numNodes; i++)
    {
        if (i == 0)       posAlloc->Add (Vector (10.0, 50.0, 0.0));  // Far Left
        else if (i == 14) posAlloc->Add (Vector (150.0, 50.0, 0.0)); // Far Right
        else if (i == 5)  posAlloc->Add (Vector (80.0, 50.0, 0.0));  // Center Deadblock
        else 
        {
            // Scatter background nodes across a natural grid space
            posAlloc->Add (Vector (randX->GetValue (), randY->GetValue (), 0.0));
        }
    }
    mobility.SetPositionAllocator (posAlloc);
    mobility.SetMobilityModel ("ns3::ConstantVelocityMobilityModel");
    mobility.Install (nodes);

    // ============================================================================
    // RANDOM VELOCITY SCATTER
    // ============================================================================
    Ptr<UniformRandomVariable> randSpeed = CreateObject<UniformRandomVariable> ();
    randSpeed->SetAttribute ("Min", DoubleValue (-1.5));
    randSpeed->SetAttribute ("Max", DoubleValue (1.5));

    for (uint32_t i = 0; i < nodes.GetN(); i++)
    {
        Ptr<Node> currentNode = nodes.Get(i);
        Ptr<ConstantVelocityMobilityModel> cvmm = currentNode->GetObject<ConstantVelocityMobilityModel>();
        if (cvmm)
        {
            if (i == 0)       cvmm->SetVelocity (Vector (4.0, 0.0, 0.0));   // Direct clean path rightward
            else if (i == 14) cvmm->SetVelocity (Vector (-4.0, 0.0, 0.0));  // Direct clean path leftward
            else if (i == 5)  cvmm->SetVelocity (Vector (0.0, 0.0, 0.0));   // Malicious roadblock is fixed
            else 
            {
                // Background nodes drift naturally in custom directions
                cvmm->SetVelocity (Vector (randSpeed->GetValue (), randSpeed->GetValue (), 0.0));
            }
        }
    }

    InternetStackHelper internet;
    AodvHelper honestAodv;
    internet.SetRoutingHelper (honestAodv);
    
    for (uint32_t i = 0; i < numNodes; i++)
    {
        if (i != attackerNode)
        {
            NodeContainer singleNodeContainer (nodes.Get (i));
            internet.Install (singleNodeContainer);
        }
    }

    MaliciousAodvHelper maliciousAodv;
    internet.SetRoutingHelper (maliciousAodv);
    NodeContainer attackerContainer (nodes.Get (attackerNode));
    internet.Install (attackerContainer);

    Ipv4AddressHelper ipv4;
    ipv4.SetBase ("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer interfaces = ipv4.Assign (devices);

    uint16_t port = 9;
    UdpEchoClientHelper echoClient (interfaces.GetAddress (14), port);
    echoClient.SetAttribute ("MaxPackets", UintegerValue (15));
    echoClient.SetAttribute ("Interval", TimeValue (Seconds (0.8))); 
    echoClient.SetAttribute ("PacketSize", UintegerValue (512));
    
    ApplicationContainer clientApp = echoClient.Install (nodes.Get (0));
    clientApp.Start (Seconds (2.0));
    clientApp.Stop (Seconds (simTime));

    UdpEchoServerHelper echoServer (port);
    ApplicationContainer serverApp = echoServer.Install (nodes.Get (14));
    serverApp.Start (Seconds (1.0));
    serverApp.Stop (Seconds (simTime));

    FlowMonitorHelper flowmon;
    Ptr<FlowMonitor> monitor = flowmon.InstallAll ();

    NS_LOG_UNCOND ("==================================================");
    NS_LOG_UNCOND ("    RUNNING SIMULATION WITH INJECTED BLACKHOLE     ");
    NS_LOG_UNCOND ("==================================================");

    Simulator::Stop (Seconds (simTime));
    Simulator::Run ();

    monitor->CheckForLostPackets ();
    std::map<FlowId, FlowMonitor::FlowStats> stats = monitor->GetFlowStats ();
    
    uint32_t txPackets = 0;
    uint32_t rxPackets = 0;
    uint64_t rxBytes = 0;
    Time delaySum = Seconds (0.0);

    double totalThroughputKbps = 0.0;
    double averageLatencyMs = 0.0;
    double pdr = 0.0;

    for (auto i = stats.begin (); i != stats.end (); ++i)
    {
        txPackets += i->second.txPackets;
        rxPackets += i->second.rxPackets;
        rxBytes += i->second.rxBytes;
        delaySum += i->second.delaySum;
    }

    if (txPackets > 0) pdr = ((double)rxPackets / txPackets) * 100.0;
    if (rxPackets > 0) averageLatencyMs = (delaySum.GetMilliSeconds () / (double)rxPackets);
    
    double activeDurationSec = simTime - 2.0; 
    if (rxPackets > 0 && activeDurationSec > 0)
    {
        totalThroughputKbps = (rxBytes * 8.0) / (activeDurationSec * 1000.0);
    }

    NS_LOG_UNCOND ("\n==================================================");
    NS_LOG_UNCOND ("             NETWORK PERFORMANCE MATRIX           ");
    NS_LOG_UNCOND ("==================================================");
    NS_LOG_UNCOND (" Total Packets Transmitted   : " << txPackets);
    NS_LOG_UNCOND (" Total Packets Received      : " << rxPackets);
    NS_LOG_UNCOND (" Packets Intercepted & Dropped: " << g_dropCount);
    NS_LOG_UNCOND ("--------------------------------------------------");
    NS_LOG_UNCOND (" Packet Drop Ratio (PDR) : " << pdr << " %");
    NS_LOG_UNCOND (" Average E2E Latency         : " << averageLatencyMs << " ms");
    NS_LOG_UNCOND (" Network Throughput          : " << totalThroughputKbps << " Kbps");
    NS_LOG_UNCOND ("==================================================\n");

    Simulator::Destroy ();
    return 0;
}
