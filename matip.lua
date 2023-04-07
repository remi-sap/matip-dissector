
matip_p = Proto("matip","MATIP / Mapping of Airline Reservation, Ticketing and Messaging Traffic over IP")             
B2_SESSION_OPEN     = -2
B2_OPEN_CONF        = -3
B2_SESSION_CLOSE    = -4

CHAR_SLASH = 47

OC_ENCODING = {[20]="ascii", [22]="EBCDIC"}
OC_STYP = {[16]="Conversational", [32]="TYPE A IATA Host to Host", [128]="SITA Host to Host"}

H_T_H_B1_PROG       = 86

H_T_H_GFI = { ["V"] = "Program-to-Program Exchange", ["P"] = "Layer-to-Layer Control Message"}
--QRI1
H_T_H_QRI1 = { [72] = "QUERY", [68] = "REPLY" , [69] = "REPLY (possible dup.)", [69] = "REPLY (rejected.)"}

H_T_H_QRI2 = { ["L"] = "Reject partial, minimum HTH protocol. No protection requested, no confirmation present", ["Q"] = "Hold for future delivery, protection requested, no confirmation present"}
H_T_H_QRI3 = { ["F"] = "Medium user priority, first data unit", ["G"] = "Medium user priority, only data unit", ["D"] = "Medium user priority, intermediate data unit" , ["E"] = "Medium user priority, last data unit"}
H_T_H_QRI5 = { ["W"] = "The series references the first TPR of the data unit, only data unit in series", ["S"] = "No TPR , only data unit in series"}

H_T_H_ADDR_TYPE_SRC = "E"
H_T_H_ADDR_TYPE_DST = "I"
H_T_H_ADDR_TYPE = { [H_T_H_ADDR_TYPE_SRC] = "Source", [H_T_H_ADDR_TYPE_DST] = "Destination"}

CTRL_ID = { ["E"]= "Transaction series control"}

CTRL_CTRL = { 
    ["E"]= {["Q"] = "terminate series by TPR", ["R"] = "terminate all series"}
}

pkt_type = ProtoField.string("matip.pkt_type","Packet Type")
pkt_stype = ProtoField.string("matip.pkt_stype","Packet Subtype")
data_length = ProtoField.uint16("matip.data_length","Message Length")
origin = ProtoField.string("matip.origin","Message Origin")
destination = ProtoField.string("matip.destination","Message destination")
--tpr1= ProtoField.string("matip.tpr1","TPR")
tpr= ProtoField.string("matip.tpr","TPR")
matip_p.fields={packet_type, pkt_stype, data_length, origin, destination, tpr}

function read_until(buffer, offset, delimiter, max_length)
    local result = ""
    local c
    for i=offset,offset+max_length do
        c=string.char(buffer(i,1):int())
        if c ==delimiter then
            break
        else
            result = result .. c
        end
    end
    return result
end

function get(map, val, def)
    if map[val]~= nil then
        return map[val]
    end
    
    return def or val
end
function getc(map, val, def)
    local c = string.char(val:int())
    if map[c]~= nil then
        return map[c]
    end
    return def or c
end

function matip_p.dissector(buffer, pinfo, tree)
    local bl = buffer:len()
    if bl <= 4 then return end
    pinfo.cols.protocol = "?matip"
    local subtree = tree:add(matip_p,buffer(),"MATIP Protocol Data")
    subtree:add("buffer length:" ..bl)
    local b1 = buffer(0,1)
    local b2 = buffer(1,1)
    subtree:add(buffer(2,2), "declared length:" ..buffer(2,2):uint())
    if b1:uint()==1 then
        pinfo.cols.protocol = "matip"
        local b3 = buffer(2,1)
        if b2:uint() == 0 then 
            subtree:add(pkt_type, "Packet type: Data")
            subtree:add(data_length, buffer(2,2))
            local b4=buffer(4,1):uint()
            
            if b4==H_T_H_B1_PROG then
                local l4tree = subtree:add(matip_p,buffer(4,2),"H. to H.")
                local GFI_val = string.char(buffer(4,1):int())
                if GFI_val == 'V' then 
                    GFI_val="Program to Program"
                end
                l4tree:add(buffer(4,1),"GFI: " .. GFI_val)
                l4tree:add(buffer(5,1), "version: ".. string.char(buffer(5,1):int()))
                GFI_val = string.char(buffer(7,1):int())
                if H_T_H_GFI[GFI_val] ~= nil then
                    GFI_val=H_T_H_GFI[GFI_val]
                end
                l4tree:add(buffer(7,1),"GFI:" .. GFI_val )
                if string.char(buffer(7,1):int())   =="P" then
                    local cid = string.char(buffer(8,1):int())
                    if CTRL_ID[cid] ~= nil then
                        cid = CTRL_ID[cid]
                    end
                    l4tree:add(buffer(8,1), "ID: ".. cid)
                    return
                end
                local qri1 = buffer(8,1):int()
                local qri1_val = tostring(buffer(8,1))
                if H_T_H_QRI1[qri1] ~= nil then 
                    qri1_val = H_T_H_QRI1[qri1]
                end
                l4tree:add(buffer(8,1),"QRI1: " .. qri1_val)
                l4tree:add(buffer(9,1),"QRI2: ".. getc(H_T_H_QRI2,buffer(9,1)))
                l4tree:add(buffer(10,1),"QRI3: " .. getc(H_T_H_QRI3, buffer(10,1)))
                local qri4=string.char(buffer(11,1):int())
                if qri4 == "." then
                    l4tree:add(buffer(11,1),"QRI4: No sequencing" )
                else
                    l4tree:add(buffer(11,1),"QRI4: Sequence element #"..qri4 )
                end
                l4tree:add(buffer(12,1),"QRI5: " .. getc(H_T_H_QRI5, buffer(12,1)))
                l4tree:add(buffer(13,1),"QRI6: " .. string.char(buffer(13,1):int()) )

                local offset = 0
                if buffer(14,1):int() ~= CHAR_SLASH and buffer(15,1):int() == CHAR_SLASH then
                    offset = 1
                end
                l4tree:add(buffer(14,1),"QRI7: " .. buffer(14,1):int().." =  ".. string.char(buffer(14,1):int()) .. "  offset:" .. offset )

                local adr1_type = string.char(buffer(15+offset, 1):int())
                --skip the 1 (field ADR2)
                offset=offset+1
                local adr1=read_until(buffer,16+offset, "/", 12)
                l4tree:add(buffer(16+offset,string.len(adr1)), "ADR1: "..H_T_H_ADDR_TYPE[adr1_type].."="..adr1)
                
                
                offset = 16+offset+string.len(adr1)+1
                local adr2_type = string.char(buffer(offset, 1):int())
                --skip the 1 (field ADR2)
                offset=offset+1
                local adr2 = read_until(buffer, offset+1, "/", 12)
                l4tree:add(buffer(offset+1,string.len(adr2)), "ADR2: "..H_T_H_ADDR_TYPE[adr2_type].."="..adr2)
                
                local adr ={ [adr1_type] = adr1, [adr2_type] = adr2} 
                if adr[H_T_H_ADDR_TYPE_SRC] ~= nil then 
                    l4tree:add(origin, adr[H_T_H_ADDR_TYPE_SRC])
                end
                if adr[H_T_H_ADDR_TYPE_DST] ~= nil then 
                    l4tree:add(destination, adr[H_T_H_ADDR_TYPE_DST])
                end
                offset=offset+string.len(adr2)+2
                l4tree:add(buffer(offset,1), "TPR1:"..string.char(buffer(offset, 1):int()))
                --stop at \r
                local tpr2 = read_until(buffer, offset+1, "\r", 12)
                --l4tree:add(buffer(offset+1, string.len(tpr2)), 'TPR:'..tpr2)
                l4tree:add(tpr, tpr2)


            else 
                print(b4)
            end

            if buffer:len()>=64 then
                subtree:add(buffer(44,20), "Offset at 44")
            end
        elseif b2:int() == B2_SESSION_OPEN then
            subtree:add(pkt_type, "Packet type: Session Open")
            subtree:add(buffer(4,1), "encoding: " .. get(OC_ENCODING, buffer(4,1):int()))
            --subtype
            subtree:add(buffer(5,1), "subtype: " .. get(OC_STYP, buffer(5,1):int()))
            subtree:add(buffer(7,1), "HDR: " .. buffer(7,1):int() )


        elseif b2:int() == B2_OPEN_CONF then
            subtree:add(pkt_type, "Packet type: Open Confirm")
            local cause =buffer(4,1):int()
            if cause == 0 then
                subtree:add(pkt_stype, "Accept")
            else
                subtree:add(pkt_stype, "Reject")
                subtree:add(cause, "Reject Cause" .. cause)
            end
        elseif b2:int() == B2_SESSION_CLOSE then
            subtree:add(pkt_stype, "Session close")
        else
            subtree:add(pkt_stype, "unknown b2: ".. b2:uint())
        end
    else
        subtree:add(b2,"Packet type:" .. b2:int())
    end

    --subtree = subtree:add(buffer(2,2),"The next two bytes")
    --subtree:add(buffer(2,1),"The 3rd byte: " .. buffer(2,1):uint())
    --subtree:add(buffer(3,1),"The 4th byte: " .. buffer(3,1):uint())
end

-- load the tcp.port table
local tcp_port = DissectorTable.get("tcp.port")
-- register our protocol to handle tcp port 350
tcp_port:add(350, matip_p)
tcp_port:add(352, matip_p)
tcp_port:add(5352, matip_p)

-- Step 6 - register the new protocol as a postdissector
--register_postdissector(matip_p)

