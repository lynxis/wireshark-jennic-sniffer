-- jsniffer - 15 bytes lang. Timestamp(5b), id(2b), channel(1b), lqi(1b), len(1b len(payload) + len(fcs)), payload() fcs(2b), 

jsniff = Proto("jennicsniffer","Jennic sniffer protocol")

function jsniff.dissector(buffer,pinfo,tree)
    -- dissector
    pinfo.cols.protocol = "JSNIFF"
    local subtree = tree:add(jsniff, buffer(),"TGGGial Protocol Data")
    subtree:add(buffer( 0,5),"Timestamp: " .. buffer(0,5):uint64())
    -- subtree = subtree:add(buffer(2,2),"The next two bytes")
    subtree:add(buffer( 5,2),"id: " .. buffer(5,2):uint())
    subtree:add(buffer( 7,1),"channel: " .. buffer(7,1):uint())
    subtree:add(buffer( 8,1),"lqi: " .. buffer(8,1):uint())
    subtree:add(buffer( 9,1),"length: " .. buffer(9,1):uint())
    --subtree:add(buffer(10,$len-),"payload" .. buffer(3,1):uint())
    --subtree:add(buffer(11,$len),"fcs" .. buffer(3,1):uint())
    --
    local wpan_dis = Dissector.get("wpan")
    wpan_dis:call(buffer(10):tvb(), pinfo, tree)
end
udp_table = DissectorTable.get("udp.port")
udp_table:add(49999, jsniff)

