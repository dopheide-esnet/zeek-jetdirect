# @TEST-EXEC: $ZEEK -C -r $TRACES/cve-2017-2741.pcap ../../../scripts %INPUT
# @TEST-EXEC: $ZEEK_PREFIX/bin/zeek-cut msg note < notice.log > notice.tmp && mv notice.tmp notice.log
# @TEST-EXEC: btest-diff notice.log
