--[[

    This is a Wireshark dissector for the B&K OpenAPI streaming protocol supported by
    LAN-XI.

    To use, copy the openapi.lua file to the Wireshark plugins folder. The location of
    the plugins folder might be:
        
        - Windows: C:\Users\<user>\AppData\Roaming\Wireshark\plugins

        - Linux: /home/<user>/.local/lib/wireshark/plugins

        (alternatively, open Wireshark and look up the folder that it uses:
         Help -> About Wireshark, Folders tab, Global/Personal Lua Plugins)

    It's a heuristic dissector, which means it is not associated with any TCP or UDP
    port number. Instead, Wireshark will call its dissector function for every packet
    and the dissector function will return a value that indicates whether the packet
    was recognized as OpenAPI.

    The dissector is implemented in the Lua scripting language.    

    To modify or extend the dissector, make modifications to this file and then press
    Ctrl+Shift+L in Wireshark to reload the script.

    For documentation see

        - fpm.lua sample that this dissector was based on:
            https://wiki.wireshark.org/Lua/Examples#A_dissector_tutorial_with_TCP-reassembly

        - Wireshark Lua API:
            https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm_modules.html

]]--

openapi_protocol = Proto("OpenAPI", "OpenAPI Streaming Protocol")

-- Define the protocol fields, which specify how values are named and displayed in wireshark

-- OpenAPI header
f_hd_magic = ProtoField.uint16("openapi.header.magic", "Magic", base.HEX)
f_hd_header_length = ProtoField.uint16("openapi.header.header_length", "Header Length", base.DEC)
f_hd_message_type = ProtoField.uint16("openapi.header.message_type", "Message Type", base.DEC)
f_hd_reserved1 = ProtoField.uint16("openapi.header.reserved1", "Reserved 1", base.HEX)
f_hd_reserved2 = ProtoField.uint32("openapi.header.reserved2", "Reserved 2", base.HEX)
f_hd_timestamp = ProtoField.absolute_time("openapi.header.timestamp", "Timestamp", base.UTC)
f_hd_message_length = ProtoField.uint32("openapi.header.message_length", "Message Length", base.DEC)

-- SignalData message
f_si_number_of_signals = ProtoField.uint16("openapi.signal_data.number_of_signals", "Number Of Signals", base.DEC)
f_si_reserved = ProtoField.uint16("openapi.signal_data.reserved", "Reserved", base.HEX)
f_si_signal_id = ProtoField.uint16("openapi.signal_data.signal_id", "Signal ID", base.DEC)
f_si_number_of_values = ProtoField.uint16("openapi.signal_data.number_of_values", "Number Of Values", base.DEC)
f_si_values = ProtoField.bytes("openapi.signal_data.values", "Values", base.SPACE)

-- DataQuality message
f_da_number_of_signals = ProtoField.uint16("openapi.data_quality.number_of_signals", "Number Of Signals", base.DEC)
f_da_signal_id = ProtoField.uint16("openapi.data_quality.signal_id", "Signal ID", base.DEC)
f_da_validity = ProtoField.uint16("openapi.data_quality.validity", "Validity", base.HEX)
f_da_reserved = ProtoField.uint16("openapi.data_quality.reserved", "Reserved", base.HEX)

-- Interpretation message
f_in_signal_id = ProtoField.uint16("openapi.interpretation.signal_id", "Signal ID", base.DEC)
f_in_interpretation_type = ProtoField.uint16("openapi.interpretation.type", "Type", base.DEC)
f_in_reserved = ProtoField.uint16("openapi.interpretation.reserved", "Reserved", base.HEX)
f_in_value_length = ProtoField.uint16("openapi.interpretation.value.length", "Value Length", base.DEC)
f_in_value_data_type = ProtoField.uint16("openapi.interpretation.value.data_type", "Data Type", base.DEC)
f_in_value_scale_factor = ProtoField.double("openapi.interpretation.value.scale_factor", "Scale Factor")
f_in_value_offset = ProtoField.double("openapi.interpretation.value.offset", "Offset")
f_in_value_period_time = ProtoField.relative_time("openapi.interpretation.value.period_time", "Period Time")
f_in_value_unit = ProtoField.string("openapi.interpretation.value.unit", "Unit", base.UNICODE)
f_in_value_vector_length = ProtoField.uint16("openapi.interpretation.value.vector_length", "Vector Length", base.DEC)
f_in_value_channel_type = ProtoField.uint16("openapi.interpretation.value.channel_type", "Channel Type", base.DEC)
f_in_value_unknown_type = ProtoField.bytes("openapi.interpretation.value.unknown_type", "Value", base.SPACE)

-- AuxSequenceData message
f_au_number_of_signals = ProtoField.uint16("openapi.aux_sequence_data.number_of_signals", "Number Of Signals", base.DEC)
f_au_reserved = ProtoField.uint16("openapi.aux_sequence_data.reserved", "Reserved", base.HEX)
f_au_signal_id = ProtoField.uint16("openapi.aux_sequence_data.signal_id", "Signal ID", base.DEC)
f_au_number_of_values = ProtoField.uint16("openapi.aux_sequence_data.number_of_values", "Number Of Values", base.DEC)
f_au_relative_time = ProtoField.uint32("openapi.aux_sequence_data.relative_time", "Relative Time", base.DEC)
f_au_absolute_time = ProtoField.absolute_time("openapi.aux_sequence_data.absolute_time", "Absolute Time (Calculated)", base.UTC)
f_au_can_status = ProtoField.uint8("openapi.aux_sequence_data.can_status", "CAN Status", base.HEX)
f_au_can_message_info = ProtoField.uint8("openapi.aux_sequence_data.can_message_info", "CAN Message Info", base.HEX)
f_au_can_data_size = ProtoField.uint8("openapi.aux_sequence_data.can_data_size", "CAN Data Size", base.DEC)
f_au_can_data_reserved = ProtoField.uint8("openapi.aux_sequence_data.can_data_reserved", "Reserved", base.HEX)
f_au_message_id = ProtoField.uint32("openapi.aux_sequence_data.message_id", "Message ID", base.DEC)
f_au_can_data = ProtoField.bytes("openapi.aux_sequence_data.can_data", "CAN Data", base.SPACE)

openapi_protocol.fields = {
    f_hd_magic,
    f_hd_header_length,
    f_hd_message_type,
    f_hd_message_length,
    f_hd_reserved1,
    f_hd_reserved2,
    f_hd_timestamp,
    f_si_number_of_signals,
    f_si_reserved,
    f_si_signal_id,
    f_si_number_of_values,
    f_si_values,
    f_da_number_of_signals,
    f_da_signal_id,
    f_da_validity,
    f_da_reserved,
    f_in_signal_id,
    f_in_interpretation_type,
    f_in_reserved,
    f_in_value_length,
    f_in_value_data_type,
    f_in_value_scale_factor,
    f_in_value_offset,
    f_in_value_period_time,
    f_in_value_unit,
    f_in_value_vector_length,
    f_in_value_channel_type,
    f_in_value_unknown_type,
    f_au_number_of_signals,
    f_au_reserved,
    f_au_signal_id,
    f_au_number_of_values,
    f_au_relative_time,
    f_au_absolute_time,
    f_au_can_status,
    f_au_can_message_info,
    f_au_can_data_size,
    f_au_can_data_reserved,
    f_au_message_id,
    f_au_can_data
}

-- This is the size of an OpenAPI message header (28 bytes) and the minimum number
-- of bytes we require to figure out how many bytes the rest of the message will be.
local OPENAPI_HDR_LEN = 28

-- Keeps track of the previous message type we've processed
local globals = {
    prev_message_string = ""
}

-- Given a B&K time family and number of ticks, calculates an absolute or relative
-- time, which will be returned as a number of seconds and nanoseconds.
local function get_timestamp(family, ticks)

    local divisor =
        2 ^ family:get_index(0) *
        3 ^ family:get_index(1) *
        5 ^ family:get_index(2) *
        7 ^ family:get_index(3)

    if divisor == 0 then
        debug("ERROR: time family can't be 0")
        return 0, 0
    end

    local seconds  = (ticks / divisor)
    local nanoseconds = math.fmod(ticks, divisor) * (1000000000 / divisor)

    return seconds, nanoseconds
end

-- Returns a formatted string containing the specified B&K time family and ticks
local function get_family_ticks_string(family, ticks)

    return "family" ..
        " 2^" .. family:get_index(0) ..
        " 3^" .. family:get_index(1) ..
        " 5^" .. family:get_index(2) ..
        " 7^" .. family:get_index(3) ..
        ", ticks " .. ticks
end

-- Maps the message type from the OpenAPI header to a descriptive string
local function get_message_string(val)

    local strings = {
        [1] = "SignalData",
        [2] = "DataQuality",
        [8] = "Interpretation",
        [11] = "AuxSequenceData"
    }

    return strings[val] or "Unknown"
end

-- Maps the validity flags from the DataQuality message to a string
local function get_data_quality_validity_string(val)

    local string = "Valid"

    if val ~= 0 then

        string = ""
        local separator = ""

        if bit32.band(val, 1) ~= 0 then
            string = string .. separator .. "Unknown"
            separator = ", "
        end

        if bit32.band(val, 2) ~= 0 then
            string = string .. separator .. "Clipped"
            separator = ", "
        end

        if bit32.band(val, 4) ~= 0 then
            string = string .. separator .. "Settling"
            separator = ", "
        end

        if bit32.band(val, 8) ~= 0 then
            string = string .. separator .. "Invalid"
            separator = ", "
        end

        if bit32.band(val, 16) ~= 0 then
            string = string .. separator .. "Overrun"
            separator = ", "
        end
    end

    return string
end

-- Maps the descriptor type from the Interpretation message to a string
local function get_interpretation_type_string(val)

    local strings = {
        [1] = "DataType",
        [2] = "ScaleFactor",
        [3] = "Offset",
        [4] = "PeriodTime",
        [5] = "Unit",
        [6] = "VectorLength",
        [7] = "ChannelType"
    }

    return strings[val] or "Unknown"
end

-- Maps the data type from the Interpretation message to a string
local function get_interpretation_content_data_type_string(val)

    local strings = {
        [1] = "Byte",
        [2] = "Int16",
        [3] = "Int24",
        [4] = "Int32",
        [5] = "Int64",
        [6] = "Float32",
        [7] = "Float64",
        [8] = "Complex32",
        [9] = "Complex64",
        [10] = "String"
    }

    return strings[val] or "Unknown"
end

-- Maps the channel type from the Interpretation message to a string
local function get_interpretation_channel_type_string(val)

    local strings = {
        [0] = "None",
        [1] = "Input_Analog",
        [2] = "Input_Auxiliary",
        [3] = "CANBus",
        [20] = "Output_Analog",
        [21] = "Output_Auxiliary"
    }

    return strings[val] or "Unknown"
end

-- Given a packet buffer (tvbuf), returns true if the buffer contains an OpenAPI message
local function is_openapi(tvbuf, offset)

    local length = tvbuf:len()
    if length < OPENAPI_HDR_LEN then return false end

    local magic = tvbuf(offset, 2):string()
    if magic ~= "BK" then return false end

    local header_length = tvbuf(offset + 2, 2):le_uint()
    if header_length ~= 20 then return false end

    local message_type = tvbuf(offset + 4, 2):le_uint()
    local message_string = get_message_string(message_type)
    if message_string == "Unknown" then return false end

    local reserved1 = tvbuf(offset + 6, 2):le_uint()
    if reserved1 ~= 0 then return false end

    local reserved2 = tvbuf(offset + 8, 4):le_uint()
    if reserved2 ~= 0 then return false end

    -- current OpenAPI implementations only support a time family of 2^32,
    -- anything else is considered not OpenAPI traffic
    local time_family = tvbuf(offset + 12, 4):le_uint()
    if time_family ~= 0x00000020 then return false end

    return true
end

-- Function to check and return the message length as well as
-- a boolean specifying whether the message was identified as
-- OpenAPI
local function check_message_length(tvbuf, offset)

    -- "msglen" is the number of bytes remaining in the tv buffer which we
    -- have available to dissect in this run
    local msglen = tvbuf:len() - offset

    -- check if capture only contains partial packet
    if msglen ~= tvbuf:reported_length_remaining(offset) then
        -- captured packets are being sliced/cut-off, so don't try to desegment/reassemble
        return 0, false
    end

    if msglen < OPENAPI_HDR_LEN then
        -- we need more bytes, so tell the main dissector function that we
        -- didn't dissect anything, and we need an unknown number of more
        -- bytes (which is what "DESEGMENT_ONE_MORE_SEGMENT" is used for)
        -- return as a negative number
        return -DESEGMENT_ONE_MORE_SEGMENT, false
    end

    -- we have enough bytes to check if this is an OpenAPI message
    if is_openapi(tvbuf, offset) then
        -- if we got here, then we know we have enough bytes in the Tvb buffer
        -- to at least figure out the full length of this OpenAPI messsage 
        -- (the length is the 32-bit integer in bytes 24 to 27)

        -- get the TvbRange of bytes 24-27
        local length_tvbr = tvbuf:range(offset + 24, 4)

        -- get the total OpenAPI message length as an unsigned integer, in little endian byte order
        local length_val = length_tvbr:le_uint() + OPENAPI_HDR_LEN

        if msglen < length_val then
            -- we need more bytes to get the whole OpenAPI message
            return -(length_val - msglen), false
        end

        -- got a complete OpenAPI message, return number of bytes (length_val), is OpenAPI (true)
        return length_val, true
    end

    -- not recognized as OpenAPI
    return 0, false
end

-- Dissects an OpenAPI SignalData message
local function dissect_signal_data(tvbuf, pktinfo, root, bytes_total, offset)

    local number_of_signals = tvbuf(offset, 2):le_uint()
    local tree_title = "OpenAPI SignalData Header, Number Of Signals: " .. number_of_signals

    local top_tree = root:add(openapi_protocol, tvbuf:range(offset, 4), tree_title)

    top_tree:add_le(f_si_number_of_signals, tvbuf(offset, 2))
    top_tree:add_le(f_si_reserved, tvbuf(offset + 2, 2))

    local header_length = 4
    local bytes_consumed = header_length
    offset = offset + header_length

    -- We need to know the number of bytes from each signal, but that
    -- information was sent earlier as part of an Interpretation message,
    -- which we don´t have access to here, it may not even be part of the
    -- capture. Sigh. To be able to show something, try to assume that
    -- the datatype and number of values of each signal contained in this
    -- message is the same, and based on this calculate the length of
    -- of each message in bytes
    local msg_len = (bytes_total - header_length) / number_of_signals

    local signal_ids = {}

    while bytes_consumed < bytes_total do

        local signal_id = tvbuf(offset, 2):le_uint()
        local number_of_values = tvbuf(offset + 2, 2):le_uint()
        local tree_title = "OpenAPI SignalData Descriptor, Signal ID: " .. signal_id .. ", Number Of Values: " .. number_of_values

        local value_size = msg_len - 4
        local tree = root:add(openapi_protocol, tvbuf:range(offset, msg_len), tree_title)

        tree:add_le(f_si_signal_id, tvbuf(offset, 2))
        tree:add_le(f_si_number_of_values, tvbuf(offset + 2, 2))
        tree:add(f_si_values, tvbuf(offset + 4, value_size))

        bytes_consumed = bytes_consumed + msg_len
        offset = offset + msg_len

        signal_ids[signal_id] = 0
    end

    return signal_ids
end

-- Dissects an OpenAPI DataQuality message
local function dissect_data_quality(tvbuf, pktinfo, root, bytes_total, offset)

    local number_of_signals = tvbuf(offset, 2):le_uint()
    local tree_title = "OpenAPI DataQuality Header, Number Of Signals: " .. number_of_signals

    local top_tree = root:add(openapi_protocol, tvbuf:range(offset, 2), tree_title)

    top_tree:add_le(f_da_number_of_signals, tvbuf(offset, 2))

    local header_length = 2
    local bytes_consumed = header_length
    offset = offset + header_length

    local msg_len = 6
    
    local signal_ids = {}

    while bytes_consumed < bytes_total do

        local signal_id = tvbuf(offset, 2):le_uint()
        local tree_title = "OpenAPI DataQuality Descriptor, Signal ID: " .. signal_id

        local validity = tvbuf(offset + 2, 2):le_uint()
        local validity_string = get_data_quality_validity_string(validity)

        local tree = root:add(openapi_protocol, tvbuf:range(offset, msg_len), tree_title)

        tree:add_le(f_da_signal_id, tvbuf(offset, 2))
        tree:add_le(f_da_validity, tvbuf(offset + 2, 2)):append_text(" (" .. validity_string .. ")")
        tree:add_le(f_da_reserved, tvbuf(offset + 4, 2))

        bytes_consumed = bytes_consumed + msg_len
        offset = offset + msg_len

        signal_ids[signal_id] = 0
    end

    return signal_ids
end

-- Dissects an OpenAPI Interpretation message
local function dissect_interpretation(tvbuf, pktinfo, root, bytes_total, offset)

    local bytes_consumed = 0

    local signal_ids = {}

    while bytes_consumed < bytes_total do

        local value_length = tvbuf(offset + 6, 2):le_uint()
        local msg_len = math.floor(((8 + value_length + 3) / 4)) * 4

        local signal_id = tvbuf(offset, 2):le_uint()

        if root.visible then -- if the tree is not visible, the Lua interpreter will silently fail when we access .text properties

            local type_val = tvbuf(offset + 2, 2):le_uint()
            local type_string = get_interpretation_type_string(type_val)

            local tree_title = "OpenAPI Interpretation Descriptor, Signal ID: " .. signal_id .. ", "

            local tree = root:add(openapi_protocol, tvbuf:range(offset, msg_len), tree_title)

            tree:add_le(f_in_signal_id, tvbuf(offset, 2))
            tree:add_le(f_in_interpretation_type, tvbuf(offset + 2, 2)):append_text(" (" .. type_string .. ")")
            tree:add_le(f_in_reserved, tvbuf(offset + 4, 2))
            tree:add_le(f_in_value_length, tvbuf(offset + 6, 2))

            if type_string == "DataType" then
                local data_type_val = tvbuf(offset + 8, 2):le_uint()
                local data_type_string = get_interpretation_content_data_type_string(data_type_val)
                local data_type_tree_item = tree:add_le(f_in_value_data_type, tvbuf(offset + 8, 2)):append_text(" (" .. data_type_string .. ")")
                tree:append_text(data_type_tree_item.text)
            elseif type_string == "ScaleFactor" then
                local scale_factor_tree_item = tree:add_le(f_in_value_scale_factor, tvbuf(offset + 8, 8))
                tree:append_text(scale_factor_tree_item.text)
            elseif type_string == "Offset" then
                local offset_tree_item = tree:add_le(f_in_value_offset, tvbuf(offset + 8, 8))
                tree:append_text(offset_tree_item.text)
            elseif type_string == "PeriodTime" then
                local family = tvbuf(offset + 8, 4):bytes()
                local ticks = tvbuf(offset + 12, 8):le_uint64():tonumber()
                local seconds, nanoseconds = get_timestamp(family, ticks)
                local nstime = NSTime.new(seconds, nanoseconds)
                local period_time_tree_item = tree:add(f_in_value_period_time, tvbuf(offset + 8, 12), nstime)
                tree:append_text(period_time_tree_item.text)
            elseif type_string == "Unit" then
                local string_start = offset + 8 + 2 -- skip 2-byte length field in the unit string
                local string_length = value_length - 2
                local unit_tree_item = tree:add_le(f_in_value_unit, tvbuf(string_start, string_length))
                tree:append_text(unit_tree_item.text)
            elseif type_string == "VectorLength" then
                local vector_length_tree_item = tree:add_le(f_in_value_vector_length, tvbuf(offset + 8, 2))
                tree:append_text(vector_length_tree_item.text)
            elseif type_string == "ChannelType" then
                local channel_type_val = tvbuf(offset + 8, 2):le_uint()
                local channel_type_string = get_interpretation_channel_type_string(channel_type_val)
                local channel_type_tree_item = tree:add_le(f_in_value_channel_type, tvbuf(offset + 8, 2))
                tree:append_text(channel_type_tree_item.text)
            else
                tree:add_le(f_in_value_unknown_type, tvbuf(offset + 8, value_length))
                tree:append_text("Unknown Message Type")
            end
        end

        bytes_consumed = bytes_consumed + msg_len
        offset = offset + msg_len

        signal_ids[signal_id] = 0
    end

    return signal_ids
end

-- Dissects an OpenAPI AuxSequenceData message
local function dissect_aux_sequence_data(tvbuf, pktinfo, root, bytes_total, offset, family, ticks)

    local number_of_signals = tvbuf(offset, 2):le_uint()
    local tree_title = "OpenAPI AuxSequenceData Header, Number Of Signals: " .. number_of_signals

    local top_tree = root:add(openapi_protocol, tvbuf:range(offset, 4), tree_title)

    top_tree:add_le(f_au_number_of_signals, tvbuf(offset, 2))
    top_tree:add_le(f_au_reserved, tvbuf(offset + 2, 2))

    offset = offset + 4

    local signal_ids = {}

    local signal = 0
    while signal < number_of_signals do

        local signal_id = tvbuf(offset, 2):le_uint()
        local number_of_values = tvbuf(offset + 2, 2):le_uint()

        local tree_title = "OpenAPI AuxSequenceData Descriptor, Signal ID: " .. signal_id .. ", Number Of Values: " .. number_of_values

        local tree = root:add(openapi_protocol, tvbuf:range(offset, 4), tree_title)

        tree:add_le(f_au_signal_id, tvbuf(offset, 2))
        tree:add_le(f_au_number_of_values, tvbuf(offset + 2, 2))

        offset = offset + 4

        local value = 0
        while value < number_of_values do

            local message_id = tvbuf(offset + 8, 4):le_uint()
            local tree_title = "OpenAPI AuxSequenceData Value, Message ID: " .. message_id
            local value_size = 20

            local val_tree = root:add(openapi_protocol, tvbuf:range(offset, value_size), tree_title)

            local can_data_size = tvbuf(offset + 6, 1):le_uint()

            val_tree:add_le(f_au_relative_time, tvbuf(offset, 4))

            -- compute absolute time based on the timestamp from the OpenAPI message header
            -- and the relative time from the AuxSequenceData message
            local rel_time = tvbuf(offset, 4):le_uint()
            local seconds, nanoseconds = get_timestamp(family, ticks + rel_time)
            local abs_time = NSTime.new(seconds, nanoseconds)
            val_tree:add_le(f_au_absolute_time, tvbuf(offset, 4), abs_time)

            val_tree:add(f_au_can_status, tvbuf(offset + 4, 1))
            val_tree:add(f_au_can_message_info, tvbuf(offset + 5, 1))
            val_tree:add(f_au_can_data_size, tvbuf(offset + 6, 1))
            val_tree:add(f_au_can_data_reserved, tvbuf(offset + 7, 1))
            val_tree:add_le(f_au_message_id, tvbuf(offset + 8, 4))
            val_tree:add(f_au_can_data, tvbuf(offset + 12, can_data_size))

            offset = offset + value_size
            value = value + 1
        end

        signal = signal + 1

        signal_ids[signal_id] = 0
    end

    return signal_ids
end

-- Main OpenAPI dissector function, dissects the OpenAPI message header
-- and then calls out to other dissector functions depending on the
-- type of message
local function dissect_openapi(tvbuf, pktinfo, root, offset, length_val)

    -- main window 'Protocol' and 'Info' columns
    pktinfo.cols.protocol = "OpenAPI"

    if offset == 0 then 
        globals.prev_message_string = ""
        pktinfo.cols.info:clear()
    end

    local message_type = tvbuf(offset + 4, 2):le_uint()
    local message_string = get_message_string(message_type)
    local magic_string = tvbuf(offset, 2):string()

    -- we will append more information as soon as we've figured out the message type and timestamp
    local tree = root:add(openapi_protocol, tvbuf:range(offset, OPENAPI_HDR_LEN), "OpenAPI")

    tree:add(f_hd_magic, tvbuf(offset, 2)):append_text(" (\"" .. magic_string .. "\")")
    tree:add_le(f_hd_header_length, tvbuf(offset + 2, 2))
    tree:add_le(f_hd_message_type, tvbuf(offset + 4, 2)):append_text(" (" .. message_string .. ")")
    tree:add_le(f_hd_reserved1, tvbuf(offset + 6, 2))
    tree:add_le(f_hd_reserved2, tvbuf(offset + 8, 4))

    -- compute message timestamp
    local family = tvbuf(offset + 12, 4):bytes()
    local ticks = tvbuf(offset + 16, 8):le_uint64():tonumber()
    local seconds, nanoseconds = get_timestamp(family, ticks)
    local nstime = NSTime.new(seconds, nanoseconds)

    local timestamp_tree_item = tree:add(f_hd_timestamp, tvbuf(offset + 12, 12), nstime):append_text(
        " (" .. get_family_ticks_string(family, tvbuf(offset + 16, 8):le_uint64()) .. ")"
    )

    tree:add_le(f_hd_message_length, tvbuf(offset + 24, 4))

    if tree.visible then -- if the tree is not visible, the Lua interpreter will silently fail when we access .text
        tree:append_text(" " .. message_string .. " Message Header, " .. timestamp_tree_item.text)
    end

    local msg_len = tvbuf(offset + 24, 4):le_uint()

    local signal_ids

    if message_string == "SignalData" then
        signal_ids = dissect_signal_data(tvbuf, pktinfo, root, msg_len, offset + 28)
    elseif message_string == "DataQuality" then
        signal_ids = dissect_data_quality(tvbuf, pktinfo, root, msg_len, offset + 28)
    elseif message_string == "Interpretation" then
        signal_ids = dissect_interpretation(tvbuf, pktinfo, root, msg_len, offset + 28)
    elseif message_string == "AuxSequenceData" then
        signal_ids = dissect_aux_sequence_data(tvbuf, pktinfo, root, msg_len, offset + 28, family, ticks)
    end

    -- update 'Info' column with the message type
    if globals.prev_message_string ~= message_string then
        globals.prev_message_string = message_string
        pktinfo.cols.info:append(message_string .. " ID ")
    end

    -- add list of Signal ID's in this message to Wireshark 'Info' column
    if signal_ids ~= nil then
        for i, v in pairs(signal_ids) do
            pktinfo.cols.info:append(i .. " ")
        end
    else
        pktinfo.cols.info:append(" (unknown)")
    end

    -- return the number of bytes we've dissected
    return length_val
end

-- Dissects an OpenAPI message, calling other dissector functions depending
-- on the message type
local function dissect_message(tvbuf, pktinfo, root, offset)

    local length_val, is_openapi = check_message_length(tvbuf, offset)

    if length_val < 0 then
        -- need more bytes to determine the protocol
        return length_val
    end

    if is_openapi then
        return dissect_openapi(tvbuf, pktinfo, root, offset, length_val)
    end

    -- not recognized as OpenAPI
    return 0
end

-- Wireshark calls this function once per captured TCP segment, passing a
-- 'tvbuf' (testy virtual buffer in Wireshark lingo) containing the data.
-- If we recognize the data in the buffer as OpenAPI data, then we should
-- dissect the data and return the number of bytes we recognized.
-- Otherwise, if the data is not OpenAPI (or an error occurred), we should
-- return 0 which will make Wireshark look for another dissector to handle
-- the buffer.
function openapi_protocol.dissector(tvbuf, pktinfo, root)

    local buffer_length = tvbuf:len()

    -- there could be multiple messages in the buffer so set up a loop
    local bytes_consumed = 0
    while bytes_consumed < buffer_length do

        local result = dissect_message(tvbuf, pktinfo, root, bytes_consumed)

        if result > 0 then
            -- we dissected an OpenAPI message of 'result' length
            bytes_consumed = bytes_consumed + result
        elseif result == 0 then
            -- The packet is not for us or we hit an error
            return 0
        else
            -- We need more bytes.
            -- Set desegment_offset to what we already consumed,
            -- and desegment_len to how many more are needed
            pktinfo.desegment_offset = bytes_consumed
            pktinfo.desegment_len = -result
            -- tell Wireshark that all the bytes in the buffer are for us
            return buffer_length
        end        
    end

    return bytes_consumed
end

openapi_protocol:register_heuristic("tcp", openapi_protocol.dissector)
