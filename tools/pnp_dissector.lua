----------------------------------------
-- Unfortunately, the older Wireshark/Tshark versions have bugs, and part of the point
-- of this script is to test those bugs are now fixed.  So we need to check the version
-- end error out if it's too old.
local major, minor, micro = get_version():match("(%d+)%.(%d+)%.(%d+)")
if major and tonumber(major) <= 1 and ((tonumber(minor) <= 10) or (tonumber(minor) == 11 and tonumber(micro) < 3)) then
        error(  "Sorry, but your Wireshark/Tshark version ("..get_version()..") is too old for this script!\n"..
                "This script needs Wireshark/Tshark version 1.11.3 or higher.\n" )
end

-- more sanity checking
-- verify we have the ProtoExpert class in wireshark, as that's the newest thing this file uses
assert(ProtoExpert.new, "Wireshark does not have the ProtoExpert class, so it's too old - get the latest 1.11.3 or higher")

local pnp2 = Proto("pnp2","EEConnect PNP")
local cmd_types = {
    [0] = "Ping",
    [1] = "Data",
    [10] = "Open channel",
    [11] = "Close channel",
    [12] = "Hello",
    [13] = "Redirect",
}

local pf_cmd_type = ProtoField.uint8("pnp2.cmd", "Command", base.DEC, cmd_types)
local pf_chan_num = ProtoField.uint8("pnp2.ch", "Channel", base.DEC)
local pf_data_len = ProtoField.uint16("pnp2.data_len", "Data length", base.DEC)
local pf_cmd_len = ProtoField.uint8("pnp2.cmd_len", "Command data length", base.DEC)
local pf_open_addr = ProtoField.string("pnp2.open_address", "Address")
local pf_open_port = ProtoField.uint16("pnp2.open_port", "Port", base.DEC)

pnp2.fields = { pf_cmd_type, pf_chan_num, pf_data_len, pf_cmd_len, pf_open_addr, pf_open_port }

local ch_field = Field.new("pnp2.ch")
local data_dissector = Dissector.get("data")

assert(data_dissector, "No data dissector found")

local MAX_CHANNELS = 50

local pnp2_ch_dissectors = {}

function pnp2.prefs_changed()
    for i = 0, MAX_CHANNELS, 1 do
	if pnp2_ch_dissectors[i] ~= nil then
            local new_diss = Dissector.get(pnp2.prefs['ch'..tostring(i)..'_diss'])
	    if new_diss then
		pnp2_ch_dissectors[i] = new_diss
	    end
	end
    end
end

function pnp2.dissector(tvbuf, pktinfo, root)

    -- set the protocol column to show our protocol name
    pktinfo.cols.protocol:set("PNP")

    local pktlen = tvbuf:reported_length_remaining()
    local ate = 0
    local cmd_type = tvbuf:range(0,1):uint()
    if cmd_types[cmd_type] == nil then
	return 0
    end

    if cmd_type == 1 then
	if pktlen < 4 then
	    pktinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
	    return
	end
	local data_len = tvbuf:range(2,2):uint()
	if data_len + 4 > pktlen then
	    pktinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
	    return
	end

	local tree = root:add(pnp2, tvbuf:range(0, 4 + data_len), "PNP "..cmd_types[cmd_type])

	tree:add(pf_cmd_type, tvbuf:range(0,1))
        tree:add(pf_chan_num, tvbuf:range(1,1))
        tree:add(pf_data_len, tvbuf:range(2,2))

	local ch = ch_field()()
	pktinfo.cols.info = "Data CH"..ch.." "
        if ch < MAX_CHANNELS and pnp2_ch_dissectors[ch] == nil then
	    pnp2_ch_dissectors[ch] = data_dissector
	    pnp2.prefs['ch'..tostring(ch)..'_diss'] = Pref.string("Ch"..tostring(ch).." dissector", "data", "Dissector for Channel "..tostring(ch))
        end

	local diss = pnp2_ch_dissectors[ch]
	if diss ~= nil then
	    diss:call(tvbuf:range(4, data_len):tvb(), pktinfo, tree)
	else
	    data_dissector:call(tvbuf(4):tvb(), pktinfo, tree)
	end
	ate = data_len + 4
    elseif cmd_type ~= 0 then
	if pktlen < 2 then
	    pktinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
	    return
	end
	local data_len = tvbuf:range(1,1):uint()
        if pktlen < data_len + 2 then
	   pktinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
	   return
	end
	local tree = root:add(pnp2, tvbuf:range(0, 2 + data_len), "PNP "..cmd_types[cmd_type])
	tree:add(pf_cmd_type, tvbuf:range(0,1))
        tree:add(pf_cmd_len, tvbuf:range(1,1))
	ate = data_len + 2
	if cmd_type == 10 then
	    tree:add(pf_chan_num, tvbuf:range(3,1))
	    local addr_len = tvbuf:range(5,1):uint()
	    tree:add(pf_open_addr, tvbuf:range(6, addr_len))

	    local ch = ch_field()()
	    pktinfo.cols.info = "Open CH"..ch
	    if ch < MAX_CHANNELS and pnp2_ch_dissectors[ch] == nil then
		pnp2_ch_dissectors[ch] = data_dissector
		pnp2.prefs['ch'..tostring(ch)..'_diss'] = Pref.string("Ch"..tostring(ch).." dissector", "data", "Dissector for Channel "..tostring(ch))
	    end
	elseif cmd_type == 11 then
	    tree:add(pf_chan_num, tvbuf:range(3,1))
	    pktinfo.cols.info = "Close CH"..ch_field()()
	else
	    pktinfo.cols.info = cmd_types[cmd_type]
	end
    else
	local tree = root:add(pnp2, tvbuf:range(0, 1))
	tree:add(pf_cmd_type, tvbuf:range(0,1))
        pktinfo.cols.info = cmd_types[cmd_type]
	ate =  1
    end
    if pktlen - ate > 0 then
	Dissector.get("pnp2"):call(tvbuf(ate):tvb(), pktinfo, root)
    end
end
DissectorTable.get("tcp.port"):add(8081, pnp2)
DissectorTable.get("tcp.port"):add(18080, pnp2)
