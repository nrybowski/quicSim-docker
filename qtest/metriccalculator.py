import os, json

class MetricCalculator():
    _metricsperfile = []
    qlogtunit = "ms"
    conn_closed = False
    
    def calculateMetrics(self, logdir: str, tcpdumpfiles: list, qlogfile: str, istcpdump: bool, isquic: bool, sim: str, run: int):
        split_dir = logdir.split("/")
        name = split_dir[len(split_dir) - 3] + "/" + split_dir[len(split_dir) - 2]
        # Init state variables to track totals and to calculate averages
        totals = {
            "rtt_amount": 0,
            "rttvar_amount": 0,
            "tp_time": 0,
            "gp_time": 0,
            "cwnd_amount": 0,
            "unacked_packets": {},
            "next_seq": 0,
            "ackranges": [{
                "high_ack": 0,
                "low_ack": 0
            }],
            "quic_offset_pns": {},
            "rackt_count": 0,
            "probet_count": 0,
            "retranst_count":0
        }
        run_avgs = {
            "avg_goodput": 0.0,
            "avg_throughput": 0.0,
            "avg_rtt": 0.0,
            "avg_cwnd": 0.0,
            "avg_rttvar": 0.0,
            "retransmissions": 0,
            "spurious_retrans": 0,
            "avg_rack_timer": 0.0,
            "avg_probe_timer": 0.0,
            "avg_retrans_timer": 0.0,
            "loss_triggers": {}
        }
        self.conn_closed = False

        for file in tcpdumpfiles:
            serverside = "server" in file
            totals, run_avgs = self.getTcpDumpMetrics(file, isquic, serverside, run_avgs, totals)
        if qlogfile != "":
            run_avgs = self.getQlogMetrics(qlogfile, run_avgs, totals)

        # calculate averages and convert throughput/goodput to Kbps
        run_avgs["avg_throughput"] = self.divide(run_avgs["avg_throughput"], 125.0)
        run_avgs["avg_throughput"] = self.divide(run_avgs["avg_throughput"], totals["tp_time"])
        run_avgs["avg_goodput"] = self.divide(run_avgs["avg_goodput"], 125.0)
        run_avgs["avg_goodput"] = self.divide(run_avgs["avg_goodput"], totals["gp_time"])
        run_avgs["avg_rtt"] = self.divide(run_avgs["avg_rtt"], totals["rtt_amount"])
        run_avgs["avg_cwnd"] = self.divide(run_avgs["avg_cwnd"], totals["cwnd_amount"])
        run_avgs["avg_rttvar"] = self.divide(run_avgs["avg_rttvar"], totals["rttvar_amount"])
        run_avgs["avg_rack_timer"] = self.divide(run_avgs["avg_rack_timer"], totals["rackt_count"])
        run_avgs["avg_probe_timer"] = self.divide(run_avgs["avg_probe_timer"], totals["probet_count"])
        run_avgs["avg_retrans_timer"] = self.divide(run_avgs["avg_retrans_timer"], totals["retranst_count"])
        # convert time values to ms
        if self.qlogtunit == "us":
            run_avgs["avg_rttvar"] = self.divide(run_avgs["avg_rttvar"], 1000)
            run_avgs["avg_rack_timer"] = self.divide(run_avgs["avg_rack_timer"], 1000)
            run_avgs["avg_probe_timer"] = self.divide(run_avgs["avg_probe_timer"], 1000)
            run_avgs["avg_retrans_timer"] = self.divide(run_avgs["avg_retrans_timer"], 1000)
            run_avgs["avg_rtt"] = self.divide(run_avgs["avg_rtt"], 1000)
        id = next((index for (index, d) in enumerate(self._metricsperfile) if d["name"] == name and d["sim"] == sim), None)
        # Check if this test is run 1 or higher
        if id == None:
            self._metricsperfile.append({
                "name": name,
                "sim": sim,
                "mdn_goodput": 0.0,
                "mdn_throughput": 0.0,
                "mdn_rtt": 0.0,
                "mdn_cwnd": 0.0,
                "mdn_rttvar": 0.0,
                "mdn_retransmissions": 0,
                "mdn_spurious_retrans": 0,
                "mdn_rack_timer": 0.0,
                "mdn_probe_timer": 0.0,
                "mdn_retrans_timer": 0.0,
                "runs": []
            })
            id = len(self._metricsperfile) - 1
        self._metricsperfile[id]["runs"].append(run_avgs)

    def divide(self, p1, p2):
        try:
            return (p1 /p2)
        except ZeroDivisionError as z:
            print("Zero division")
            return 0.0
        except Exception as e:
            print("Division error")
            return 0.0

    def getQlogMetrics(self, file: str, run_avgs: dict, totals: dict):
        data = ""
        with open(file, "r") as qlog_file:
            data = qlog_file.read()

        qlog = json.loads(data)
        events = qlog["traces"][0]["events"]
        # get structure of event fields
        event_fields = [x.lower() for x in qlog["traces"][0]["event_fields"]]

        # get time unit
        if "configuration" in qlog["traces"][0] and "time_units" in qlog["traces"][0]["configuration"]:
            self.qlogtunit = qlog["traces"][0]["configuration"]["time_units"]
        # find event description field
        try:
            event_type_id = event_fields.index("event_type")
        except ValueError as e:
            event_type_id = event_fields.index("event")
        # find event data field
        data_id = event_fields.index("data")

        # loop through events
        for event in events:
            if event[event_type_id] == "metrics_updated":
                self.getAvgUpdatedMetrics(run_avgs, totals, event[data_id])
            elif event[event_type_id] == "packet_lost":
                self.getLossTriggers(run_avgs, event[data_id])
            elif "_timer" in event[event_type_id]:
                self.getTimerValues(run_avgs, totals, event[data_id], event[event_type_id])

        return run_avgs
    # Log triggers of lost packets
    def getLossTriggers(self, run_avgs: dict, event_data: dict):
        trigger = event_data["trigger"]
        if trigger in run_avgs["loss_triggers"].keys():
            run_avgs["loss_triggers"][trigger] += 1
        else:
            run_avgs["loss_triggers"][trigger] = 1

    def getAvgUpdatedMetrics(self, run_avgs: dict, totals: dict, event_data: dict):
        if "cwnd" in event_data:
            cur_cwnd = float(event_data["cwnd"])
            run_avgs["avg_cwnd"] += cur_cwnd
            totals["cwnd_amount"] += 1
        if "rtt_variance" in event_data:
            rttvar = float(event_data["rtt_variance"])
            run_avgs["avg_rttvar"] += rttvar
            totals["rttvar_amount"] += 1
        if "latest_rtt" in event_data:
            lat_rtt = float(event_data["latest_rtt"])
            run_avgs["avg_rtt"] += lat_rtt
            totals["rtt_amount"] += 1
    
    def getTimerValues(self, run_avgs: dict, totals: dict, event_data: dict, timer_type: str):
        if timer_type == "rack_timer":
            timer = float(event_data["timer"])
            run_avgs["avg_rack_timer"] += timer
            totals["rackt_count"] += 1
        elif timer_type == "probe_timer":
            timer = float(event_data["timer"])
            run_avgs["avg_probe_timer"] += timer
            totals["probet_count"] += 1
        elif timer_type == "retrans_timer":
            timer = float(event_data["timer"])
            run_avgs["avg_retrans_timer"] += timer
            totals["retranst_count"] += 1

    def getTcpDumpMetrics(self, file: str, isquic: bool, serverside: bool, run_avgs: dict, totals: dict):
        data = ""
        with open(file, "r") as tcpdump_file:
            data = tcpdump_file.read()

        packets = json.loads(data)
        serverip = ""
        print("starting process")
        for packet in packets:
            if "quic" not in packet['_source']['layers'] and isquic:
                print("skipping because no quic layer")
                continue

            if "tcp" not in packet['_source']['layers'] and not isquic:
                print("skipping because no tcp layer")
                continue
            
            if serverip == "":
                serverip = self.getServerIp(packet, isquic)
            
            isserver = self.checkPacketSendByServer(packet, serverip)
            if isquic:
                totals, run_avgs = self.processQuicPacket(packet, serverside, run_avgs, totals, isserver)
            else:
                totals, run_avgs = self.processTcpPacket(packet, serverside, run_avgs, totals, isserver)
        return totals, run_avgs

    # find out which ip is the server (sender of data)
    def getServerIp(self, packet: dict, isquic: bool):
        if isquic:
            if packet['_source']['layers']['quic']['quic.header_form'] == "1" and packet['_source']['layers']['quic']['quic.long.packet_type'] == "0":
                return packet['_source']['layers']['ip']['ip.dst']
            else:
                return ""
        else:
            if packet['_source']['layers']['tcp']['tcp.flags_tree']['tcp.flags.syn'] == "1" and packet['_source']['layers']['tcp']['tcp.flags_tree']['tcp.flags.ack'] == "1":
                return packet['_source']['layers']['ip']['ip.dst']
            else:
                return ""
    
    # check if sender of packet is server
    def checkPacketSendByServer(self, packet: dict, serverip: str):
        return serverip == packet["_source"]["layers"]["ip"]["ip.src"]

    def processQuicPacket(self, packet: dict, serverside: bool, run_avgs: dict, totals: dict, isserver: bool):
        if serverside:
            if isserver:
                try:
                    # complete size of packet
                    bytes_amount = float(packet['_source']['layers']["frame"]["frame.len"])
                    timestamp = float(packet['_source']['layers']['frame']['frame.time_relative'])
                    # only track throughput if connection is not closed
                    if not self.conn_closed:
                        totals, run_avgs = self.addThroughputBytes(run_avgs, bytes_amount, totals, timestamp)
                        self.checkRetransmissions(run_avgs,totals,packet['_source']['layers']["quic"], True)
                except KeyError as e:
                    print(e)
            #tracked acked packets to check for spurious retransmissions
            self.trackAckedPktsQUIC(packet, run_avgs, totals, isserver)
        else:
            if isserver:
                try:
                    # Get quic payload length for goodput calculation
                    frames = packet['_source']['layers']["quic"]["quic.frame"]
                    bytes_amount = self.getQuicFrameLength(frames)
                    timestamp = float(packet['_source']['layers']['frame']['frame.time_relative'])
                    totals, run_avgs = self.addGoodputBytes(run_avgs, bytes_amount, totals, timestamp)
                except KeyError as e:
                    print(e)
                except TypeError as t:
                    print(t)

        return totals, run_avgs

    def processTcpPacket(self, packet: dict, serverside: bool, run_avgs: dict, totals: dict, isserver: bool):
        if serverside:
            if isserver:
                try:
                    # complete size of packet
                    bytes_amount = float(packet['_source']['layers']["frame"]["frame.len"])
                    timestamp = float(packet['_source']['layers']['frame']['frame.time_relative'])
                    totals, run_avgs = self.addThroughputBytes(run_avgs, bytes_amount, totals, timestamp)
                    self.checkRetransmissions(run_avgs,totals,packet['_source']['layers']["tcp"], False)
                except KeyError as e:
                    print(e)
            #find RTT
            self.trackAckedPktsTCP(packet, run_avgs, totals, isserver)
        else:
            if isserver:
                try:
                    # Get tcp payload length for goodput calculation
                    bytes_amount = float(packet['_source']['layers']["tcp"]["tcp.len"])
                    timestamp = float(packet['_source']['layers']['frame']['frame.time_relative'])
                    totals, run_avgs = self.addGoodputBytes(run_avgs, bytes_amount, totals, timestamp)
                except KeyError as e:
                    print(e)

        return totals, run_avgs
    def trackAckedPktsQUIC(self, packet: dict, run_avgs: dict, totals: dict, isserver: bool):
        if not isserver:
            try:
                ackframe = self.getAckFrame(packet)
                if ackframe:
                    ack_timestamp = float(packet['_source']['layers']['frame']['frame.time_relative']) * 1000
                    large_ack = int(ackframe['quic.ack.largest_acknowledged'])
                    first_range = large_ack - int(ackframe['quic.ack.first_ack_range'])
                    acked_packets = []
                    ackranges = [{
                        "high_ack": large_ack,
                        "low_ack": first_range
                    }]
                    ackranges = self.getAckRangesQUIC(ackframe, ackranges, first_range)
                    #reverse list to start from lowest ack range
                    ackranges.reverse()
                    totals["ackranges"] += ackranges
            except TypeError as t:
                print(t)
            except KeyError as e:
                print(e)

            try:
                conn_closed = self.hasConnClose(packet)
                self.conn_closed = conn_closed
            except TypeError as t:
                print(t)
            except KeyError as e:
                print(e)

    def trackAckedPktsTCP(self, packet: dict, run_avgs: dict, totals: dict, isserver: bool):
        if not isserver:
            try:
                tcppacket = packet['_source']['layers']["tcp"] 
                ack_timestamp = float(packet['_source']['layers']['frame']['frame.time_relative']) * 1000
                large_ack = int(tcppacket['tcp.ack'])
                acked_packets = []
                ackranges = [{
                    "high_ack": large_ack,
                    "low_ack": 0
                }]
                ackranges = self.getAckRangesTCP(tcppacket, ackranges)
                totals["ackranges"] = ackranges
            except TypeError as t:
                print(t)
            except KeyError as e:
                print(e)

    def getAckFrame(self, packet: dict):
        frames = packet['_source']['layers']["quic"]["quic.frame"]
        ackframe = None
        if isinstance(frames, list):
            for frame in frames:
                if frame["quic.frame_type"] == "2":
                    ackframe = frame
                    break
        else:
            if frames["quic.frame_type"] == "2":
                    ackframe = frames
        return ackframe

    def hasConnClose(self, packet: dict):
        frames = packet['_source']['layers']["quic"]["quic.frame"]
        conn_close = None
        if isinstance(frames, list):
            for frame in frames:
                if frame["quic.frame_type"] == "29":
                    conn_close = frame
                    break
        else:
            if frames["quic.frame_type"] == "29":
                    conn_close = frames
        return (conn_close != None)
    
    def getAckRangesTCP(self, tcppacket: dict, ackranges: list):
        # parse SACK information
        if "tcp.options.sack_tree" in tcppacket['tcp.options_tree']:
            sack = tcppacket['tcp.options_tree']['tcp.options.sack_tree']
            left_egdes = sack['tcp.options.sack_le']
            right_edges = sack['tcp.options.sack_re']
            # check if there are multiple SACK ranges
            if isinstance(left_egdes, list):
                for index, gap in enumerate(left_egdes):
                    large_ack = int(right_edges[index])
                    low_ack = int(left_egdes[index])
                    ackranges.append({
                        "high_ack": large_ack,
                        "low_ack": low_ack
                    })
            else:
                large_ack = int(right_edges)
                low_ack = int(left_egdes)
                ackranges.append({
                    "high_ack": large_ack,
                    "low_ack": low_ack
                })

        return ackranges

    def getAckRangesQUIC(self, ackframe: dict, ackranges: list, large_ack: int):
        if "quic.ack.gap" in ackframe:
            ack_gaps = ackframe["quic.ack.gap"]
            range_lengths = ackframe["quic.ack.ack_range"]
            if isinstance(ack_gaps, list):
                for index, gap in enumerate(ack_gaps):
                    gap = int(gap) + 2
                    large_ack -= gap
                    range_length = int(range_lengths[index])
                    low_ack = large_ack - range_length
                    ackranges.append({
                        "high_ack": large_ack,
                        "low_ack": low_ack
                    })
                    large_ack = low_ack
            else:
                gap = int(ack_gaps) + 2
                large_ack -= gap
                range_length = int(range_lengths)
                low_ack = large_ack - range_length
                ackranges.append({
                    "high_ack": large_ack,
                    "low_ack": low_ack
                })

        return ackranges
    
    def isAcked(self, ackranges: list, pn: int, isquic: bool):
        acked = False
        if isquic:
            for ackrange in ackranges:
                if pn >= ackrange['low_ack'] and pn <= ackrange['high_ack']:
                    acked = True
                    break
        else:
            for ackrange in ackranges:
                if pn >= ackrange['low_ack'] and pn < ackrange['high_ack']:
                    acked = True
                    break
        return acked

    def getQuicFrameLength(self, frames):
        bytes_amount = 0
        # if quic packet contains multiple frames, go through all
        if isinstance(frames, list):
            for frame in frames:
                # if stream frames contains length, get value
                if "quic.stream.length" in frame:
                    bytes_amount += float(frame['quic.stream.length'])
                # else calculate length by parsing data
                else:
                    if "quic.stream_data" in frame:
                        data = frame["quic.stream_data"].replace(':', '')
                        bytes_amount = len(data) / 2
        else:
            if "quic.stream.length" in frames:
                    bytes_amount += float(frames['quic.stream.length'])
            else:
                if "quic.stream_data" in frames:
                    data = frames["quic.stream_data"].replace(':', '')
                    bytes_amount = len(data) / 2
        
        return bytes_amount

    def addThroughputBytes(self, run_avgs: dict, bytes_amount: float, totals: dict, timestamp: float):
        run_avgs["avg_throughput"] += bytes_amount
        totals["tp_time"] = timestamp
        return totals, run_avgs
    
    def addGoodputBytes(self, run_avgs: dict, bytes_amount: float, totals: dict, timestamp: float):
        run_avgs["avg_goodput"] += bytes_amount
        totals["gp_time"] = timestamp
        return totals, run_avgs

    def checkRetransmissions(self, run_avgs: dict, totals: dict, packet: dict, isquic: bool):
        if not isquic:
            cur_seq = int(packet["tcp.seq"])
            # If sequence is lower than highest observer sequence: retransmission
            if cur_seq < totals["next_seq"]:
                bytes_amount = float(packet["tcp.len"])
                run_avgs["avg_goodput"] -= bytes_amount
                run_avgs["retransmissions"] += 1
                acked = self.isAcked(totals["ackranges"], cur_seq, isquic)
                # if sequence already acked: spurious retransmission
                if acked:
                    run_avgs["spurious_retrans"] += 1
            next_seq = int(packet["tcp.nxtseq"])
            if next_seq > totals["next_seq"]:
                totals["next_seq"] = next_seq
        else:
            if type(packet) == list:
                packet = packet[0]
            frames = packet["quic.frame"]
            if type(frames) == dict:
                frames = [frames]
            for frame in frames:
                if "quic.stream.offset" in frame:
                    cur_seq = int(frame["quic.stream.offset"])
                    # if current stream offset is lower than highest stream offset: retransmission
                    if cur_seq < totals["next_seq"]:
                        bytes_amount = self.getQuicFrameLength(frames)
                        run_avgs["avg_goodput"] -= bytes_amount
                        run_avgs["retransmissions"] += 1
                        # Chech for packets that contained same offset and see if they are acked already
                        if cur_seq in totals["quic_offset_pns"].keys():
                            for pn in totals["quic_offset_pns"][cur_seq]:
                                acked = self.isAcked(totals["ackranges"], pn, isquic)
                                if acked:
                                    run_avgs["spurious_retrans"] += 1
                                    break

                    if "quic.short" in packet:
                        pn = int(packet["quic.short"]["quic.packet_number"])
                    else:
                        pn = int(packet["quic.packet_number"])
                    # track packet number for this stream offset
                    if cur_seq in totals["quic_offset_pns"].keys():
                        totals["quic_offset_pns"][cur_seq].append(pn)
                    else:
                        totals["quic_offset_pns"][cur_seq] = [pn]

                    if cur_seq > totals["next_seq"]:
                        totals["next_seq"] = cur_seq
                    break
    
    # for each test scenario: find median values from all runs
    def getMedianValues(self, runs: list):
        rtts = []
        cwnds = []
        goodputs = []
        throughputs = []
        rttvars = []
        retrans = []
        spur_retrans = []
        rackt = []
        probet = []
        retranst = []
        medians = {}

        for run in runs:
            rtts.append(run["avg_rtt"])
            cwnds.append(run["avg_cwnd"])
            goodputs.append(run["avg_goodput"])
            throughputs.append(run["avg_throughput"])
            rttvars.append(run["avg_rttvar"])
            retrans.append(run["retransmissions"])
            spur_retrans.append(run["spurious_retrans"])
            rackt.append(run["avg_rack_timer"])
            probet.append(run["avg_probe_timer"])
            retranst.append(run["avg_retrans_timer"])

        rtts.sort()
        cwnds.sort()
        goodputs.sort()
        throughputs.sort()
        rttvars.sort()
        retrans.sort()
        spur_retrans.sort()
        rackt.sort()
        probet.sort()
        retranst.sort()

        middle = int(len(rtts) / 2)
        if len(rtts) == 1:
            middle = 0

        medians["mdn_rtt"] = rtts[middle]
        medians["mdn_cwnd"] = cwnds[middle]
        medians["mdn_goodput"] = goodputs[middle]
        medians["mdn_throughput"] = throughputs[middle]
        medians["mdn_rttvar"] = rttvars[middle]
        medians["mdn_retransmissions"] = retrans[middle]
        medians["mdn_spurious_retrans"] = spur_retrans[middle]
        medians["mdn_rack_timer"] = rackt[middle]
        medians["mdn_probe_timer"] = probet[middle]
        medians["mdn_retrans_timer"] = retranst[middle]

        return medians

    def addMediansToResults(self, metricsfile: list):
        for id in range(0, len(metricsfile)):
            medians = self.getMedianValues(metricsfile[id]["runs"])
            metricsfile[id]["mdn_goodput"] = medians["mdn_goodput"]
            metricsfile[id]["mdn_throughput"] = medians["mdn_throughput"]
            metricsfile[id]["mdn_rtt"] = medians["mdn_rtt"]
            metricsfile[id]["mdn_cwnd"] = medians["mdn_cwnd"]
            metricsfile[id]["mdn_rttvar"] = medians["mdn_rttvar"]
            metricsfile[id]["mdn_retransmissions"] = medians["mdn_retransmissions"]
            metricsfile[id]["mdn_spurious_retrans"] = medians["mdn_spurious_retrans"]
            metricsfile[id]["mdn_rack_timer"] = medians["mdn_rack_timer"]
            metricsfile[id]["mdn_probe_timer"] = medians["mdn_probe_timer"]
            metricsfile[id]["mdn_retrans_timer"] = medians["mdn_retrans_timer"]
        
        return metricsfile

    def saveMetrics(self, outputdir: str):
        self._metricsperfile = self.addMediansToResults(self._metricsperfile)
        with open(outputdir + "/metrics.json", mode='w') as metrics_file:
            json.dump(self._metricsperfile, metrics_file, indent=4)
    
    def getMetrics(self):
        return self._metricsperfile