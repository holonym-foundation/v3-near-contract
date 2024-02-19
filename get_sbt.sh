if [ "$1" = "V3KYCSybilResistance" ]
then
    circuitid="[114,157,102,14,28,2,228,228,25,116,94,97,125,100,63,137,122,83,134,115,204,241,5,30,9,59,191,165,139,10,18,11]"
elif [ "$1" = "V3PhoneSybilResistance" ]
then
    circuitid="[188,224,82,207,114,61,202,6,162,27,211,207,131,139,197,24,147,23,48,251,61,183,133,159,201,204,134,240,213,72,52,149]"
else
    echo "Invalid circuit id"
    exit 1
fi
near view verifier.holonym_id.testnet get_sbt --args '{"owner": "'"$2"'", "circuit_id": '$circuitid' }'
