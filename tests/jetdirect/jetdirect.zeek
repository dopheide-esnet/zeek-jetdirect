# @TEST-EXEC: $ZEEK -C -r $TRACES/jetdirect-exploit.pcap ../../../scripts %INPUT
# @TEST-EXEC: $ZEEK_PREFIX/bin/zeek-cut msg note < notice.log > notice.tmp && mv notice.tmp notice.log
# @TEST-EXEC: btest-diff notice.log
