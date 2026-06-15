#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/mobility-module.h"
#include "ns3/wifi-module.h"
#include "ns3/internet-module.h"
#include "ns3/aodv-module.h"
#include "ns3/netanim-module.h"
#include "ns3/applications-module.h"
#include "ns3/flow-monitor-module.h"

using namespace ns3;
NS_LOG_COMPONENT_DEFINE("NormalAodvWithTrace");

AnimationInterface *g_anim = 0;

// ============================================================================
// 🔍 SAFE RREQ/RREP TRACE DETECTOR
// ============================================================================
void TransmitPacketTrace(std::string context, Ptr<const Packet> packet, double txPowerW)
{
    if (!packet || packet->GetSize() < 1) 
    {
        return;
    }

    Ptr<Packet> pCopy = packet->Copy();
    uint8_t packetType = 0;
    
    pCopy->CopyData(&packetType, 1);

    if (packetType == 1 && pCopy->GetSize() >= 24) 
    {
        pCopy->RemoveAtStart(1); 
        aodv::RreqHeader rreqHeader;
        
        if (pCopy->GetSize() >= rreqHeader.GetSerializedSize())
        {
            pCopy->RemoveHeader(rreqHeader);
            NS_LOG_UNCOND("[AODV RREQ PHASE] ➡️ Node Broadcasted Route Request! " 
                          << " | Target Destination IP: " << rreqHeader.GetDst()
                          << " | Target SeqNo: " << rreqHeader.GetDstSeqno()
                          << " | Hops Traveled: " << (uint32_t)rreqHeader.GetHopCount()
                          << " | Time: " << Simulator::Now().GetSeconds() << "s");
        }
    }
    else if (packetType == 2 && pCopy->GetSize() >= 20) 
    {
        pCopy->RemoveAtStart(1); 
        aodv::RrepHeader rrepHeader;
        
        if (pCopy->GetSize() >= rrepHeader.GetSerializedSize())
        {
            pCopy->RemoveHeader(rrepHeader);
            NS_LOG_UNCOND("[AODV RREP PHASE] ↩️ Node Sent/Forwarded Route Reply! " 
                          << " | Route Valid For Destination IP: " << rrepHeader.GetDst()
                          << " | Certified Destination SeqNo: " << rrepHeader.GetDstSeqno()
                          << " | Total Path Hop Count: " << (uint32_t)rrepHeader.GetHopCount()
                          << " | Returning to Source: " << rrepHeader.GetOrigin()
                          << " | Time: " << Simulator::Now().GetSeconds() << "s");
        }
    }
}

void HighlightRoute()
{
    uint32_t route[] = {0, 1, 6, 7, 12, 13, 14};
    if (g_anim)
    {
        for (uint32_t i = 0; i < 7; i++)
        {
            if (route[i] == 0)
                g_anim->UpdateNodeColor(route[i], 0, 0, 255); 
            else if (route[i] == 14)
                g_anim->UpdateNodeColor(route[i], 0, 255, 0); 
            else
                g_anim->UpdateNodeColor(route[i], 255, 255, 0); 
            g_anim->UpdateNodeDescription(NodeList::GetNode(route[i]), "Route_" + std::to_string(i));
        }
        NS_LOG_UNCOND("✅ Visual Route highlighted at t=" << Simulator::Now().GetSeconds() << "s");
    }
}

void UpdateSimStatus(double currentTime, double simTime)
{
    if (g_anim && currentTime <= simTime)
    {
        g_anim->UpdateNodeDescription(NodeList::GetNode(0), "SRC t=" + std::to_string((int)currentTime) + "s");
        if (currentTime + 1.0 <= simTime)
            Simulator::Schedule(Seconds(1.0), &UpdateSimStatus, currentTime + 1.0, simTime);
    }
}

int main(int argc, char *argv[])
{
    uint32_t numNodes = 15;
    double simTime = 15.0;

    NodeContainer nodes;
    nodes.Create(numNodes);

    WifiHelper wifi;
    wifi.SetStandard(WIFI_STANDARD_80211b);
    wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                                 "DataMode",    StringValue("DsssRate1Mbps"), 
                                 "ControlMode", StringValue("DsssRate1Mbps"));

    YansWifiPhyHelper phy;
    YansWifiChannelHelper channel = YansWifiChannelHelper::Default();
    phy.SetChannel(channel.Create());

    // 🚀 STABLE NS-3.40 RANGE TUNING ATTRIBUTES
    phy.Set("TxPowerStart", DoubleValue(20.0));
    phy.Set("TxPowerEnd", DoubleValue(20.0));
    phy.Set("RxSensitivity", DoubleValue(-96.0)); 
    phy.Set("CcaEdThreshold", DoubleValue(-99.0)); 

    WifiMacHelper mac;
    mac.SetType("ns3::AdhocWifiMac");
    NetDeviceContainer devices = wifi.Install(phy, mac, nodes);

    // ============================================================================
    // 📐 OPTIMIZED MOBILITY SPACE: DYNAMIC MOVING NODES KEEPING HIGH CONNECTIONS
    // ============================================================================
    MobilityHelper mobility;
    
    Ptr<ListPositionAllocator> startPos = CreateObject<ListPositionAllocator>();
    for (uint32_t i = 0; i < numNodes; i++)
    {
        startPos->Add(Vector((i % 5) * 30.0, (i / 5) * 30.0, 0));
    }
    mobility.SetPositionAllocator(startPos);

    Ptr<RandomRectanglePositionAllocator> randPos = CreateObject<RandomRectanglePositionAllocator>();
    Ptr<UniformRandomVariable> xStream = CreateObject<UniformRandomVariable>();
    xStream->SetAttribute("Min", DoubleValue(0.0));
    xStream->SetAttribute("Max", DoubleValue(150.0)); // Adjusted area constraint to yield active metrics
    randPos->SetX(xStream);

    Ptr<UniformRandomVariable> yStream = CreateObject<UniformRandomVariable>();
    yStream->SetAttribute("Min", DoubleValue(0.0));
    yStream->SetAttribute("Max", DoubleValue(150.0)); // Adjusted area constraint to yield active metrics
    randPos->SetY(yStream);

   mobility.SetMobilityModel(
        "ns3::RandomWaypointMobilityModel",
        "Speed", StringValue("ns3::UniformRandomVariable[Min=1|Max=3]"), // 🌟 Stabilized mobile speed (Walking pace)
        "Pause", StringValue("ns3::ConstantRandomVariable[Constant=2.0]"), // 🌟 Increased pause time for route stability
        "PositionAllocator", PointerValue(randPos));
        
    mobility.Install(nodes);
    
    AodvHelper aodv;
    InternetStackHelper internet;
    internet.SetRoutingHelper(aodv);
    internet.Install(nodes);

    Ipv4AddressHelper ipv4;
    ipv4.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer interfaces = ipv4.Assign(devices);

    uint16_t port = 9;
    OnOffHelper onoff("ns3::UdpSocketFactory", InetSocketAddress(interfaces.GetAddress(numNodes - 1), port));
    onoff.SetConstantRate(DataRate("32Kbps"));
    onoff.SetAttribute("PacketSize", UintegerValue(256));
    ApplicationContainer app = onoff.Install(nodes.Get(0));
    app.Start(Seconds(2.0));
    app.Stop(Seconds(simTime));

    PacketSinkHelper sink("ns3::UdpSocketFactory", InetSocketAddress(Ipv4Address::GetAny(), port));
    ApplicationContainer sinkApp = sink.Install(nodes.Get(numNodes - 1));
    sinkApp.Start(Seconds(1.0));
    sinkApp.Stop(Seconds(simTime));

    AnimationInterface anim("/home/vboxuser/ns-allinone-3.40/ns-3.40/animations/normal-aodv.xml");
    anim.SetMobilityPollInterval(Seconds(1.0));
    g_anim = &anim;
    anim.SetStartTime(Seconds(0.0));
    anim.SetStopTime(Seconds(simTime));
    anim.EnablePacketMetadata(false);
    anim.SetMaxPktsPerTraceFile(5000); 

    for (uint32_t i = 0; i < numNodes; i++)
    {
        anim.UpdateNodeColor(nodes.Get(i), 200, 200, 200);
        anim.UpdateNodeSize(nodes.Get(i), 5.0, 5.0);
        anim.UpdateNodeDescription(nodes.Get(i), "N" + std::to_string(i));
    }

    anim.UpdateNodeColor(nodes.Get(0), 0, 0, 255);
    anim.UpdateNodeDescription(nodes.Get(0), "SOURCE");
    anim.UpdateNodeSize(nodes.Get(0), 7.0, 7.0);

    anim.UpdateNodeColor(nodes.Get(14), 0, 255, 0);
    anim.UpdateNodeDescription(nodes.Get(14), "DESTINATION");
    anim.UpdateNodeSize(nodes.Get(14), 7.0, 7.0);

    Config::Connect("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Phy/PhyTxBegin", MakeCallback(&TransmitPacketTrace));

    Simulator::Schedule(Seconds(5.0), &HighlightRoute);
    Simulator::Schedule(Seconds(1.0), &UpdateSimStatus, 1.0, simTime);

    FlowMonitorHelper flowmon;
    Ptr<FlowMonitor> monitor = flowmon.InstallAll();

    NS_LOG_UNCOND("╔══════════════════════════════════════════════════════════════╗");
    NS_LOG_UNCOND("║             NORMAL AODV WITH RUNTIME RREQ DETECTOR           ║");
    NS_LOG_UNCOND("╚══════════════════════════════════════════════════════════════╝");

    Simulator::Stop(Seconds(simTime));
    Simulator::Run();

    monitor->CheckForLostPackets();
    std::map<FlowId, FlowMonitor::FlowStats> stats = monitor->GetFlowStats();
    
    uint32_t txPackets = 0;
    uint32_t rxPackets = 0;
    uint64_t rxBytes = 0;
    uint32_t lostPackets = 0;
    Time delaySum = Seconds(0.0);

    double totalThroughputKbps = 0.0;
    double averageLatencyMs = 0.0;
    double pdr = 0.0;

    for (auto i = stats.begin(); i != stats.end(); ++i)
    {
        txPackets   += i->second.txPackets;
        rxPackets   += i->second.rxPackets;
        rxBytes     += i->second.rxBytes;
        lostPackets += i->second.lostPackets;
        delaySum    += i->second.delaySum;
    }

    if (txPackets > 0) 
        pdr = ((double)rxPackets / txPackets) * 100.0;
    
    if (rxPackets > 0) 
        averageLatencyMs = (delaySum.GetMilliSeconds() / (double)rxPackets);
    
    double activeDurationSec = simTime - 2.0; 
    if (rxPackets > 0 && activeDurationSec > 0)
        totalThroughputKbps = (rxBytes * 8.0) / (activeDurationSec * 1000.0);

    NS_LOG_UNCOND("\n==================================================================");
    NS_LOG_UNCOND("             COMPREHENSIVE NETWORK PERFORMANCE MATRIX             ");
    NS_LOG_UNCOND("==================================================================");
    NS_LOG_UNCOND(" [TRAFFIC] Total Application Packets Sent  : " << txPackets << " packets");
    NS_LOG_UNCOND(" [TRAFFIC] Total Application Packets Recv  : " << rxPackets << " packets");
    NS_LOG_UNCOND(" [DROPS] Total Dropped/Lost Packets        : " << lostPackets << " packets");
    NS_LOG_UNCOND("------------------------------------------------------------------");
    NS_LOG_UNCOND(" [EVALUATE] Packet Delivery Ratio (PDR)    : " << pdr << " %");
    NS_LOG_UNCOND(" [EVALUATE] Average End-to-End Latency     : " << averageLatencyMs << " ms");
    NS_LOG_UNCOND(" [EVALUATE] System Network Throughput       : " << totalThroughputKbps << " Kbps");
    NS_LOG_UNCOND("==================================================================\n");

    monitor->SerializeToXmlFile("/home/vboxuser/ns-allinone-3.40/ns-3.40/results/normal-results.xml", true, true);

    Simulator::Destroy();
    return 0;
}
