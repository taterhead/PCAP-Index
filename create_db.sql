CREATE TABLE IF NOT EXISTS pkt_index(tv_s integer, tv_us integer, ether_type INTEGER, ip_proto INTEGER, src_addr_hh UNSIGNED INTEGER, src_addr_h UNSIGNED INTEGER, src_addr_l UNSIGNED INTEGER, src_addr_ll UNSIGNED INTEGER, src_port INTEGER, dst_addr_hh UNSIGNED INTEGER, dst_addr_h UNSIGNED INTEGER, dst_addr_l UNSIGNED INTEGER, dst_addr_ll UNSIGNED INTEGER, dst_port INTEGER, pcap_fname TEXT, offset UNSIGNED INTEGER, data_len UNSIGNED INTEGER);

CREATE INDEX IF NOT EXISTS k_src ON pkt_index (src_addr_ll, src_port, src_addr_hh, src_addr_h, src_addr_l);
CREATE INDEX IF NOT EXISTS k_dst ON pkt_index (dst_addr_ll, dst_port, dst_addr_hh, dst_addr_h, dst_addr_l);
CREATE INDEX IF NOT EXISTS k_endpoints ON pkt_index (src_addr_ll,dst_addr_ll);
CREATE INDEX IF NOT EXISTS k_time ON pkt_index (tv_s, tv_us);
