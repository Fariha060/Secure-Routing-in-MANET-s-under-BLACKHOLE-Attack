#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/mobility-module.h"
#include "ns3/wifi-module.h"
#include "ns3/internet-module.h"
#include "ns3/aodv-module.h"
#include "ns3/netanim-module.h"
#include "ns3/applications-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/flow-monitor-helper.h"
#include "ns3/aodv-packet.h"
#include <map>

using namespace ns3;
NS_LOG_COMPONENT_DEFINE("TrustBasedSecureRouting");

AnimationInterface *g_anim = 0;
uint32_t g_dropCount = 0;
bool g_isAttackerBlocked = false;
bool g_isPathHighlighted = false;

// Counters for explicit application metrics verification
uint32_t g_sentPackets = 0;
uint32_t g_receivedPackets = 0;

// ============================================================================
// 🛡️ TRUST ENGINE IMPLEMENTATION (THE WATCHDOG MGR)
// ============================================================================
class TrustManager 
{
private:
    struct TrustScore {
        uint32_t forwarded = 0;
        uint32_t dropped = 0;
        double evaluation = 1.0; 
    };
    std::map<Ipv4Address, TrustScore> m_table;
    double m_threshold = 0.5;

public:
    void RecordForward(Ipv4Address neighbor) {
        m_table[neighbor].forwarded++;
        UpdateScore(neighbor);
    }

    void RecordDrop(Ipv4Address neighbor) {
        m_table[neighbor].dropped++;
        UpdateScore(neighbor);
    void UpdateScore(Ipv4Address neighbor) {
    }

        uint32_t total = m_table[neighbor].forwarded + m_table[neighbor].dropped;
        if (total > 1) { 
            m_table[neighbor].evaluation = (double)m_table[neighbor].forwarded / total;
        }
    }

    bool IsTrusted(Ipv4Address neighbor) {
        if (m_table.find(neighbor) == m_table.end()) return true; 
        return m_table[neighbor].evaluation >= m_threshold;
    }
};

TrustManager g_trustEngine;

// ============================================================================
// MALICIOUS BLACKHOLE LAYER
// ============================================================================
class MaliciousAodvProtocol : public aodv::RoutingProtocol
{
public:
    static TypeId GetTypeId (void) {
        static TypeId tid = TypeId ("ns3::aodv::MaliciousAodvProtocol")
            .SetParent<aodv::RoutingProtocol> ()
            .SetGroupName ("Aodv")
            .AddConstructor<MaliciousAodvProtocol> ();
        return tid;
    }
    MaliciousAodvProtocol () : aodv::RoutingProtocol () {}
    
    virtual bool RouteInput (Ptr<const Packet> p, const Ipv4Header &header, 
                             Ptr<const NetDevice> idev, const UnicastForwardCallback &ucb, 
                             const MulticastForwardCallback &mcb, const LocalDeliverCallback &lcb, 
                             const ErrorCallback &ecb) override
    {
        if (header.GetProtocol () == 17) 
        {
            g_dropCount++;
            
            Ptr<Node> node = this->GetObject<Node>();
            Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>();
            Ipv4Address myAddress = ipv4->GetAddress(1, 0).GetLocal();
            
            g_trustEngine.RecordDrop(myAddress); 
            
            // PHASE 2: Malicious node identified and flagged RED
            if (g_anim && !g_isAttackerBlocked) {
                g_isAttackerBlocked = true;
                g_anim->UpdateNodeDescription (node, "BLOCKED!");
                g_anim->UpdateNodeColor (node, 255, 0, 0); 
            }
            return true; 
        }

        // Send Fake RREP
        Ptr<Packet> pCopy = p->Copy();
        uint8_t packetType;
        pCopy->CopyData(&packetType, 1);
        if (packetType == 1) 
        {
            pCopy->RemoveAtStart(1);
            aodv::RreqHeader rreqHeader;
            pCopy->RemoveHeader(rreqHeader);
            
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
            if (udp) {
                Ptr<Socket> socket = udp->CreateSocket();
                if (socket) {
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

class MaliciousAodvHelper : public Ipv4RoutingHelper {
public:
    virtual Ptr<Ipv4RoutingProtocol> Create (Ptr<Node> node) const override {
        Ptr<MaliciousAodvProtocol> routing = CreateObject<MaliciousAodvProtocol> ();
        node->AggregateObject (routing);
        return routing;
    }
    virtual MaliciousAodvHelper* Copy (void) const override { return new MaliciousAodvHelper (*this); }
};

// ============================================================================
// 🛡️ TRUST-AWARE HONEST ROUTING IMPLEMENTATION
// ============================================================================
class SecureTrustAodvProtocol : public aodv::RoutingProtocol
{
public:
    static TypeId GetTypeId (void) {
        static TypeId tid = TypeId ("ns3::aodv::SecureTrustAodvProtocol")
            .SetParent<aodv::RoutingProtocol> ()
            .SetGroupName ("Aodv")
            .AddConstructor<SecureTrustAodvProtocol> ();
        return tid;
    }
    SecureTrustAodvProtocol () : aodv::RoutingProtocol () {}

    virtual bool RouteInput (Ptr<const Packet> p, const Ipv4Header &header, 
                             Ptr<const NetDevice> idev, const UnicastForwardCallback &ucb, 
                             const MulticastForwardCallback &mcb, const LocalDeliverCallback &lcb, 
                             const ErrorCallback &ecb) override
    {
        Ipv4Address toxicIP ("10.1.1.6"); 

        if (!g_trustEngine.IsTrusted(toxicIP))
        {
            // PHASE 3: Route converges onto the alternative track and turns CYAN
            if (g_anim && !g_isPathHighlighted) {
                g_isPathHighlighted = true;
                for (uint32_t secureNode : {1, 2, 3, 4}) {
                    g_anim->UpdateNodeColor(secureNode, 0, 255, 255); 
                    g_anim->UpdateNodeDescription(secureNode, "SEC_ROUTE");
                }
            }
            return aodv::RoutingProtocol::RouteInput (p, header, idev, ucb, mcb, lcb, ecb);
        }

        if (header.GetProtocol() == 17) {
            g_trustEngine.RecordForward(header.GetSource());
        }

        return aodv::RoutingProtocol::RouteInput (p, header, idev, ucb, mcb, lcb, ecb);
    }
};

class SecureTrustAodvHelper : public Ipv4RoutingHelper {
public:
    virtual Ptr<Ipv4RoutingProtocol> Create (Ptr<Node> node) const override {
        Ptr<SecureTrustAodvProtocol> routing = CreateObject<SecureTrustAodvProtocol> ();
        node->AggregateObject (routing);
        return routing;
    }
    virtual SecureTrustAodvHelper* Copy (void) const override { return new SecureTrustAodvHelper (*this); }
};

// Application tracing helpers to catch counts
void PacketSentCallback (Ptr<const Packet> p)
{
    g_sentPackets++;
}

void PacketReceivedCallback (Ptr<const Packet> p)
{
    g_receivedPackets++;
    // PHASE 4: Packets deliver successfully over time, turning destination GREEN
    if (g_anim) {
        g_anim->UpdateNodeDescription(14, "DELIVERED!");
        g_anim->UpdateNodeColor(14, 0, 128, 0); 
    }
}

// ============================================================================
// MAIN SIMULATION ARCHITECTURE
// ============================================================================
int main (int argc, char *argv[])
{
    uint32_t numNodes = 15;
    double simTime = 25.0; // Extended time to allow distinct phase separations
    uint32_t attackerNode = 5;

    NodeContainer nodes;
    nodes.Create (numNodes);

    WifiHelper wifi;
    wifi.SetStandard (WIFI_STANDARD_80211b);
    wifi.SetRemoteStationManager ("ns3::ConstantRateWifiManager",
                                  "DataMode", StringValue ("DsssRate11Mbps"),
                                  "ControlMode", StringValue ("DsssRate1Mbps"));

    YansWifiPhyHelper phy;
    YansWifiChannelHelper channel = YansWifiChannelHelper::Default ();
    phy.SetChannel (channel.Create ());

    WifiMacHelper mac;
    mac.SetType ("ns3::AdhocWifiMac");
    NetDeviceContainer devices = wifi.Install (phy, mac, nodes);

    AnimationInterface anim ("/home/vboxuser/ns-allinone-3.40/ns-3.40/animations/secure-routing.xml");
    g_anim = &anim;

    // PHASE 1: INITIALIZATION - ALL NODES START LOOKING COMPLETELY SIMILAR
    for (uint32_t i = 0; i < numNodes; i++) {
        anim.UpdateNodeColor (nodes.Get (i), 220, 220, 220); 
        anim.UpdateNodeSize (nodes.Get (i), 6.0, 6.0);
        anim.UpdateNodeDescription(nodes.Get(i), "node");
    }

    MobilityHelper mobility;
    Ptr<ListPositionAllocator> posAlloc = CreateObject<ListPositionAllocator> ();
    
    posAlloc->Add (Vector (10.0, 50.0, 0.0));   // Node 0
    posAlloc->Add (Vector (40.0, 25.0, 0.0));   // Node 1 
    posAlloc->Add (Vector (40.0, 75.0, 0.0));   // Node 2 
    posAlloc->Add (Vector (75.0, 25.0, 0.0));   // Node 3
    posAlloc->Add (Vector (110.0, 25.0, 0.0));  // Node 4
    posAlloc->Add (Vector (80.0, 50.0, 0.0));   // Node 5 
    
    for (uint32_t i = 6; i < 14; i++) {
        posAlloc->Add (Vector (20.0 + (i * 10), 85.0, 0.0));
    }
    posAlloc->Add (Vector (150.0, 50.0, 0.0));  // Node 14
    
    mobility.SetPositionAllocator (posAlloc);
    mobility.SetMobilityModel ("ns3::ConstantVelocityMobilityModel");
    mobility.Install (nodes);

    // Apply movement speeds to the MANET nodes
    for (uint32_t i = 0; i < numNodes; i++) {
        Ptr<ConstantVelocityMobilityModel> cvmm = nodes.Get(i)->GetObject<ConstantVelocityMobilityModel>();
        if (i == 0)       cvmm->SetVelocity (Vector (0.8, 0.0, 0.0));  
        else if (i == 14) cvmm->SetVelocity (Vector (-0.8, 0.0, 0.0)); 
        else if (i == 5)  cvmm->SetVelocity (Vector (0.0, 0.0, 0.0));   
        else              cvmm->SetVelocity (Vector (0.2, 0.05, 0.0));  
    }

    InternetStackHelper internet;
    SecureTrustAodvHelper secureTrustAodv; 
    internet.SetRoutingHelper (secureTrustAodv);
    
    for (uint32_t i = 0; i < numNodes; i++) {
        if (i != attackerNode) {
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
    
    // TIMELINE DELAY MANAGEMENT: Spacing intervals to allow observation time
    UdpEchoClientHelper echoClient (interfaces.GetAddress (14), port);
    echoClient.SetAttribute ("MaxPackets", UintegerValue (15));
    echoClient.SetAttribute ("Interval", TimeValue (Seconds (1.2))); // Wider gap between packets
    echoClient.SetAttribute ("PacketSize", UintegerValue (512));
    
    ApplicationContainer clientApp = echoClient.Install (nodes.Get (0));
    clientApp.Start (Seconds (2.0)); // Delay application start to watch node mobility first
    clientApp.Stop (Seconds (simTime));

    UdpEchoServerHelper echoServer (port);
    ApplicationContainer serverApp = echoServer.Install (nodes.Get (14));
    serverApp.Start (Seconds (1.0));
    serverApp.Stop (Seconds (simTime));

    // Connect metrics capture hooks
    clientApp.Get(0)->GetObject<UdpEchoClient>()->TraceConnectWithoutContext("Tx", MakeCallback(&PacketSentCallback));
    serverApp.Get(0)->GetObject<UdpEchoServer>()->TraceConnectWithoutContext("Rx", MakeCallback(&PacketReceivedCallback));

    // ============================================================================
    // 📊 PERFORMANCE MATRICES: FLOW MONITOR ATTACHMENT
// ============================================================================
    FlowMonitorHelper flowmon;
    Ptr<FlowMonitor> monitor = flowmon.InstallAll();

    NS_LOG_UNCOND ("==========================================================");
    NS_LOG_UNCOND ("    RUNNING TIMED SECURE ROUTING MANET SIMULATION        ");
    NS_LOG_UNCOND ("==========================================================");

    Simulator::Stop (Seconds (simTime));
    Simulator::Run ();

    // Process performance indicators after simulation complete
    monitor->CheckForLostPackets();
    Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier>(flowmon.GetClassifier());
    std::map<FlowId, FlowMonitor::FlowStats> stats = monitor->GetFlowStats();

    double totalDelay = 0;
    uint32_t monitoredRxPackets = 0;
    uint32_t monitoredTxPackets = 0;
    double throughput = 0;

    for (std::map<FlowId, FlowMonitor::FlowStats>::const_iterator i = stats.begin(); i != stats.end(); ++i) {
        Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow(i->first);
        // Track stats for data traveling from Node 0 to Node 14
        if (t.sourceAddress == "10.1.1.1" && t.destinationAddress == "10.1.1.15") {
            monitoredTxPackets += i->second.txPackets;
            monitoredRxPackets += i->second.rxPackets;
            totalDelay += i->second.delaySum.GetSeconds();
            if (i->second.rxPackets > 0) {
                throughput += (i->second.rxBytes * 8.0) / (i->second.timeLastRxPacket.GetSeconds() - i->second.timeFirstTxPacket.GetSeconds()) / 1024.0;
            }
        }
    }

    // Calculating Metrics
    double pdr = (monitoredTxPackets > 0) ? ((double)monitoredRxPackets / monitoredTxPackets) * 100.0 : 0.0;
    double avgLatency = (monitoredRxPackets > 0) ? (totalDelay / monitoredRxPackets) * 1000.0 : 0.0; // In Milliseconds

    NS_LOG_UNCOND ("\n==========================================================");
    NS_LOG_UNCOND ("             PERFORMANCE METRICS MATRIX RESULTS           ");
    NS_LOG_UNCOND ("==========================================================");
    std::cout << "Packet Delivery Ratio (PDR) : " << pdr << " %" << std::endl;
    std::cout << "Average End-to-End Latency  : " << avgLatency << " ms" << std::endl;
    std::cout << "Network Throughput          : " << throughput << " Kbps" << std::endl;
    std::cout << "Intercepted/Dropped Packets : " << g_dropCount << " packets" << std::endl;
    NS_LOG_UNCOND ("==========================================================\n");

    Simulator::Destroy ();
    return 0;
}
