-- @brief Schneider Protocol dissector plugin
-- @author zzq
-- @date 2015.08.12
do
    -- create a new dissector
    local funcode = ''
    local NAME = 'UMAS'
    local PORT = 502
    local proto = Proto(NAME,'UMAS Protocol')
    --local win = TextWindow.new('test')

    local fields = proto.fields
    fields.Next_message_len = ProtoField.new('Next message len','next_message.len',ftypes.UINT16)
    fields.MBAP_header = ProtoField.new('MBAP header','mbap.head',ftypes.BYTES)
    fields.Session_id = ProtoField.new('Session id','session.id',ftypes.UINT16)
    fields.Modbus_Func_code =ProtoField.new('Modbus Funcode','modbus.funcode',ftypes.BYTES)
    fields.Fun_code = ProtoField.new('Function code','function.code',ftypes.STRING)
    fields.Status_code = ProtoField.new('Status Code','status',ftypes.STRING)
    fields.Payload = ProtoField.new('Payload','payload',ftypes.BYTES)
    fields.Unknow = ProtoField.new('Unknow','unknow',ftypes.BYTES)
    fields.Vison = ProtoField.new('Firmware Vison','fm.vison',ftypes.IPv4)
    fields.PLC_type = ProtoField.new('PLC type','plc.type',ftypes.STRING)
    fields.Project_name = ProtoField.new('Project name','project.name',ftypes.STRING)
    fields.Password_check_mask = ProtoField.new('Password check mask','passd.check_mask',ftypes.BYTES)
    fields.PLC_status = ProtoField.new('PLC status','plc.status',ftypes.STRING)
    fields.Connect_status = ProtoField.new('Connect Status','connect.status',ftypes.STRING)
    fields.Encryption_status = ProtoField.new('Encryption status','encryption.status',ftypes.STRING)
    fields.Checksum = ProtoField.new('Checksum','checksum',ftypes.BYTES)
    fields.Session_id_value = ProtoField.new('Session id value','session_id.value',ftypes.BYTES)
    fields.Number = ProtoField.new('Number','number',ftypes.UINT16)
    fields.Flag = ProtoField.new('Flag','flag',ftypes.STRING)
    fields.Address = ProtoField.new('Address','address',ftypes.BYTES)
    fields.Padding = ProtoField.new('Padding','padding',ftypes.BYTES)
    fields.Datas = ProtoField.new('Datas','datas',ftypes.BYTES)
    fields.Data_size = ProtoField.new('Data size','data.size',ftypes.UINT16)
    fields.Extend_instruction = ProtoField.new('Extend instruction','extend.instruction',ftypes.STRING)
    fields.Cipher = ProtoField.new('Cipher','cipher',ftypes.BYTES)
    fields.IO_status = ProtoField.new('IO Ststus','io.status',ftypes.BYTES)


    local function func_codes(func_codes,tree_team)
        local text = ''
        local test = ''
        local func_code = func_codes(2,1)
        if func_code:uint() == 0x01 then  text = 'open Communication'
        elseif func_code:uint() == 0x02 then text = 'Get Module INFO'
        elseif func_code:uint() == 0x03 then text = 'Get Project INFO'
        elseif func_code:uint() == 0x04 then text = 'Get Status INFO'
        elseif func_code:uint() == 0x10 then text = 'Get Reservation'
        elseif func_code:uint() == 0x11 then text = 'Release Reservation'
        elseif func_code:uint() == 0x12 then text = 'Keep Reservation'
        elseif func_code:uint() == 0x24 then text = 'Read Object Reference List'
        elseif func_code:uint() == 0x25 then text = 'Write Object Reference List'
        elseif func_code:uint() == 0x28 then text = 'Read Physical Memory'
        elseif func_code:uint() == 0x29 then text = 'Write Physical Memory'
        elseif func_code:uint() == 0x36 then text = 'Backup Restore Plc Project'
        elseif func_code:uint() == 0x40 then text = 'Run Plc'
        elseif func_code:uint() == 0x41 then text = 'Stop Plc'
        elseif func_code:uint() == 0x42 then text = 'Init Plc'
        elseif func_code:uint() == 0x6d then text = 'Extended Code'
        elseif func_code:uint() == 0x74 then text = 'Read IO ReferenceList'
        elseif func_code:uint() == 0x75 then text = 'Write IO Reference List'
        elseif func_code:uint() == 0x80 then text = 'Start Download'
        elseif func_code:uint() == 0x81 then text = 'End Download'
        elseif func_code:uint() == 0x82 then text = 'Modify instruction'
        elseif func_code:uint() == 0xfe then text = 'Effective communication'
        elseif func_code:uint() == 0xfd then text = 'Invalid communication'
        else text = 'Unknow'
        end
        tree_team:add(fields.Modbus_Func_code,func_codes(0,1))
        tree_team:add(fields.Session_id,func_codes(1,1))
        if func_code:uint() == 0xfe or func_code:uint() == 0xfd  then 
            tree_team:add(fields.Status_code,func_code,text)
        else 
            tree_team:add(fields.Fun_code,func_code,text)
        end
        return text
    end
    --功能码处理程序用到的小函数
    --0x04功能码用到的函数
    local function PLC_Status(PLC_STATUS_CODE)
        local text = ''
        if PLC_STATUS_CODE:uint() == 0x02 then text = 'stop'
        elseif PLC_STATUS_CODE:uint() == 0x03 then text = 'run'
        end
        return text   
    end

    local function Conn_Status(Conn_Status)
        local text = ''
        if Conn_Status:uint() == 0x02 then text = 'cancellation'
        elseif Conn_Status:uint() == 0x0a then text = 'connect'
        end
        return text
    end

    local function Project_file_encryption_status(code1,code2)
        local text = ''
        if code1:uint() == 0x81 and code2:uint() == 0x0b then text = 'encryption'
        elseif code1:uint() ==0x80 and code2:uint() == 0x00 then text = 'unencryption'
        end
        return text
    end
    --0x24用到的配置函数
    local function flag_get(flag_code)
        local text = ''
        if flag_code:uint() == 0x00 then text = 'S Block'
        elseif flag_code:uint() == 0x01 then text = 'SW Block'
        elseif flag_code:uint() == 0x02 then text = 'M Block'
        elseif flag_code:uint() == 0x03 then text = 'MW Block'
        end
        
        return text
        
    end

    --ox6d用到的配置函数
    local function get_Extend(Extend_code)
        local text = ''
        if Extend_code:uint() == 0x01 then text ='Modify control logic'
        elseif Extend_code:uint() == 0x03 then text ='Erase physical memory'
        elseif Extend_code:uint() == 0x04 then text = 'Initialize physical memory'
        elseif Extend_code:uint() == 0x05 then text = 'Verify read write protected password'
        end
        return text
    end 

    --End

    --各类功能码发送对应处理函数
    local function anaily_0x24(tvb,tree)
        local time = 0
        tree:add(fields.Number,tvb(0,1))
        for i = 1, tvb(0,1):uint(), 1 do
            local flag = tree:add_le(fields.Flag,tvb(2+time,1),flag_get(tvb(2+time,1)))
            flag:add_le(fields.Address,tvb(3+time,2))
            flag:add_le(fields.Padding,tvb(5+time,2))
            flag:add_le(fields.Padding,tvb(1+time,1))
            time = time + 6
        end
    end

    local function anaily_0x25(tvb,tree)
        local time = 0
        tree:add_le(fields.Number,tvb(0,1))
        for i = 1, tvb(0,1):uint(), 1 do
            local flag = tree:add_le(fields.Flag,tvb(2+time,1),flag_get(tvb(2+time,1)))
            flag:add_le(fields.Address,tvb(3+time,2))
            flag:add_le(fields.Datas,tvb(7+time,1))
            time = time +7
        end
    end

    local function anaily_0x28(tvb,tree)
        tree:add(fields.Address,tvb(0,2))
        tree:add_le(fields.Data_size,tvb(4,2))
        
    end

    local function anaily_0x29(tvb,tree)
        tree:add(fields.Address,tvb(0,2))
        tree:add_le(fields.Data_size,tvb(3,2))
        tree:add_le(fields.Datas,tvb(5))
    end

    local function anaily_0x36(tvb,tree)
        tree:add(fields.Datas,tvb)
    end

    local function anaily_0x40(tvb,tree)
        tree:add(fields.Datas,tvb)
    end

    local function anaily_0x41(tvb,tree)
        tree:add(fields.Datas,tvb)
    end

    local function anaily_0x42(tvb,tree)
        tree:add(fields.Datas,tvb)
    end

    local function anaily_0x6d(tvb,tree)
        tree:add(fields.Extend_instruction,tvb(0,1),get_Extend(tvb(0,1)))
        if tvb(0,1):uint() == 0x05 then
            tree:add(fields.Password_check_mask,tvb(1,1))
            tree:add(fields.Cipher,tvb(2))
        else 
            tree:add(fields.Address,tvb(1,2))
            tree:add_le(fields.Data_size,tvb(5,2))            
        end
    end

    local function anaily_0x74(tvb,tree)
        local time = 0
        local address = tree:add(fields.Number,tvb(0,1))
        for i = 1, tvb(0,1):uint(), 1 do
            address:add(fields.Address,tvb(1+time,4))
            time = time +5
        end
    end

    local function anaily_0x75(tvb,tree)
        local time = 0
        local address = tree:add(fields.Number,tvb(0,1))
        for i = 1, tvb(0,1):uint(), 1 do
            address:add(fields.Address,tvb(1+time,4))
            address:add(fields.IO_status,tvb(6,1))
            time = time +6
        end
        
    end

    local function anaily_0x81(tvb,tree)
        tree:add(fields.Datas,tvb())
    end

    --各类功能码接收对应处理函数
    local function anaily_r_0x01(tvb,tree)
        tree:add(fields.Payload,tvb())
        
    end
    local function anaily_r_0x02(tvb,tree)
        tree:add_le(fields.Vison,tvb(8,4))
        tree:add_le(fields.PLC_type,tvb(23,10))
    end
    local function anaily_r_0x03(tvb,tree)
        local len1 = tvb(34,1)
        local len2 = tvb(68,1)
        tree:add_le(fields.Next_message_len,len1)
        tree:add_le(fields.Project_name,tvb(35,len1:uint()))
        tree:add_le(fields.Next_message_len,len2)
        tree:add_le(fields.Password_check_mask,tvb(69,len2:uint()))
        tree:add_le(fields.Password_check_mask,tvb(72,1))
    end
    local function anaily_r_0x04(tvb,tree)
        local run_status = PLC_Status(tvb(0,1))
        local conn_status = Conn_Status(tvb(1,1))
        local encryption_status  = Project_file_encryption_status(tvb(2,1),tvb(21,1))
        tree:add_le(fields.PLC_status,tvb(0,1),run_status)
        tree:add_le(fields.Connect_status,tvb(1,1),conn_status)
        tree:add_le(fields.Encryption_status,tvb(2,1),encryption_status)
        tree:add_le(fields.Checksum,tvb(4,8))
        tree:add_le(fields.Unknow,tvb(8))
    end

    local function anaily_r_0x10(tvb,tree)
        tree:add(fields.Session_id_value,tvb)
    end

    local function anaily_r_0x24(tvb,tree)
        local time = 0
        tree:add_le(fields.Number,tvb(0,1))
        for i = 1, tvb(0,1):uint(), 1 do
            if (5+time)<=tvb():len() then
                tree:add_le(fields.Address,tvb(3+time,2))
                time = time + 4
            end
        end
    end

    local function anaily_r_0x25(tvb,tree)
        tree:add(fields.Padding,tvb())
    end

    local function anaily_r_0x28(tvb,tree)
        tree:add_le(fields.Data_size,tvb(0,2))
        tree:add(fields.Datas,tvb,2)
    end

    local function anaily_r_0x74(tvb,tree)
        local time = 0
        local number = tree:add(fields.Number,tvb(0,1))
        for i = 1, tvb(0,1):uint(), 1 do
            number:add(fields.IO_status,tvb(2+time,1))
            time = time +2
        end
    end

    local function anaily_r_0x75(tvb,tree)
        tree:add(fields.Datas,tvb())
    end

    local function anaily_r_0x81(tvb,tree)
        tree:add(fields.Checksum,tvb(1))
    end
    --解析器主体编写

    function proto.dissector (tvb, pinfo, tree)
        pinfo.cols.protocol = NAME
        if tvb(61,1):uint() == 0x5a then 
            if pinfo.dst_port == 502 then 
                local subtree = tree:add(proto, tvb(54))
                local MBAP_header = subtree:add(fields.MBAP_header,tvb(54,7))
                local funcode_text = func_codes(tvb(61,3),subtree)
                funcode = tvb(63,1):uint()
                --win:append(funcode..'\n')
                if tvb:len()>64 then
                    local payload = subtree:add(fields.Payload,tvb(64))
                    if funcode == 0x24 then anaily_0x24(tvb(64),payload)
                    elseif funcode == 0x25 then anaily_0x25(tvb(64),payload)
                    elseif funcode == 0x28 then anaily_0x28(tvb(64),payload)
                    elseif funcode == 0x29 then anaily_0x29(tvb(64),payload) 
                    elseif funcode == 0x36 then anaily_0x36(tvb(64),payload)
                    elseif funcode == 0x40 then anaily_0x40(tvb(64),payload)
                    elseif funcode == 0x41 then anaily_0x41(tvb(64),payload)
                    elseif funcode == 0x42 then anaily_0x42(tvb(64),payload)
                    elseif funcode == 0x6d then anaily_0x6d(tvb(64),payload)
                    elseif funcode == 0x74 then anaily_0x74(tvb(64),payload)
                    elseif funcode == 0x75 then anaily_0x75(tvb(64),payload)
                    elseif funcode == 0x81 then anaily_0x81(tvb(64),payload)
                    end
                end
                pinfo.cols.info = 'Function:'..funcode_text
            elseif pinfo.src_port == 502 then
                local subtree = tree:add(proto, tvb(54))
                local MBAP_header = subtree:add(fields.MBAP_header,tvb(54,7))
                local R_funcode = func_codes(tvb(61,3),subtree)
                if R_funcode == 'Effective communication' then
                    if tvb:len()>64 then       
                        local payload = subtree:add(fields.Payload,tvb(64))
                        if funcode == 0x01 then anaily_r_0x01(tvb(64),payload)
                        elseif funcode == 0x02 then anaily_r_0x02(tvb(64),payload)
                        elseif funcode == 0x03 then anaily_r_0x03(tvb(64),payload)
                        elseif funcode == 0x04 then anaily_r_0x04(tvb(64),payload)
                        elseif funcode == 0x64 then anaily_r_0x64(tvb(64),payload)
                        elseif funcode == 0x24 then anaily_r_0x24(tvb(64),payload)
                        elseif funcode == 0x25 then anaily_r_0x25(tvb(64),payload)
                        elseif funcode == 0x28 then anaily_r_0x28(tvb(64),payload)
                        elseif funcode == 0x74 then anaily_r_0x74(tvb(64),payload)
                        elseif funcode == 0x75 then anaily_r_0x75(tvb(64),payload)
                        elseif funcode == 0x81 then anaily_r_0x81(tvb(64),payload)
                        -- elseif funcode == 0xfe then anaily_r_0xfe(tvb(64),payload)
                        -- elseif funcode == 0xfd then anaily_r_0xfd(tvb(64),payload)
                        end
                    end
                    
                end
                pinfo.cols.info = funcode..' Reson:'.. R_funcode 
            end
        end
    end
    register_postdissector(proto)
end