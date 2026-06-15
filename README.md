# Linux based project
 Tools: NS3 and NETAnim (for simulations)
Make a scratch folder to save all files 
# Step 1: Build
cd ~/ns-allinone-3.40/ns-3.40/build && ninja
# Step 2: Run Simulations
# Normal AODV
~/ns-allinone-3.40/ns-3.40/build/scratch/ns3.40-normal-aodv-debug
# Blackhole Attack
~/ns-allinone-3.40/ns-3.40/build/scratch/ns3.40-blackhole-attack-debug

# Secure Routing
~/ns-allinone-3.40/ns-3.40/build/scratch/ns3.40-secure-routing-debug

# Step 3: Open in NetAnim
# Normal AODV
~/ns-allinone-3.40/netanim-3.109/NetAnim ~/ns-allinone-3.40/ns-3.40/animations/normal-aodv.xml &

# Blackhole Attack
~/ns-allinone-3.40/netanim-3.109/NetAnim ~/ns-allinone-3.40/ns-3.40/animations/blackhole-attack.xml &

# Secure Routing
~/ns-allinone-3.40/netanim-3.109/NetAnim ~/ns-allinone-3.40/ns-3.40/animations/secure-routing.xml &
