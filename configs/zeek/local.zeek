# Zeek local configuration
# This file is loaded when running Zeek with the 'local' policy

@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http
@load base/protocols/ssl

# Enable JSON logging for easier parsing
redef LogAscii::use_json = T;
redef LogAscii::json_timestamps = JSON::TS_ISO8601;

# Set log rotation
redef Log::default_rotation_interval = 1hr;
redef Log::default_max_size = 100MB;
