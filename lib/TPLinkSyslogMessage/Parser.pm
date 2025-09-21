package TPLinkSyslogMessage::Parser;
use utf8;
use strict;
use warnings;
use Readonly;
use Socket;
use IO::Select;
use Compress::Zlib;
use feature 'state';
require Exporter;

our @ISA = qw(Exporter);
our @EXPORT = qw(
    facility_severity_from_prival match_first_line match_additional_line match_dhcp_info
    match_controller_operation_info match_dhcp_fields send_gelf_message
    fields_from_first_line_match fields_from_additional_line_match fields_from_dhcp_info
    fields_from_controller_operation_info
);

# Regexes, all precompiled for performance.

# "AP MAC" (AP?) messages consist of multiple lines which aren't that useful in
# a pack as they are not RFC compliant syslog messages. They're also not that
# easily parsed to something graylog can work with with. This regex matches the
# first of one of these multiline messages and captures fields which will be
# reused for the subsequent lines.
#
# One example two-line message:
#   <6>Sep 20 21:42:02 192.168.40.5 [1758400919.541010111] AP MAC=98:ba:5f:e0:a6:aa MAC SRC=d4:d4:da:c8:1e:54 IP SRC=192.168.50.73 IP DST=52.45.111.222 IP proto=6 SPT=49808 DPT=1883
#   [1758400919.891010111] AP MAC=98:ba:5f:e0:a6:aa MAC SRC=d4:d4:da:c8:1e:54 IP SRC=192.168.50.50 IP DST=52.45.111.222 IP proto=6 SPT=49808 DPT=1883
Readonly::Scalar my $FIRST_LINE_REGEX => qr{
    ^
    \< (?<prival> \d+) \> ((?<version> \d+) \s+)?
        ( (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \s+ \d+ \s+ [0-9]{2}:[0-9]{2}:[0-9]{2}) \s+
        ( [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3} ) \s+
        \[ (?<timestamp> \d+ [.] \d+ ) \] \s+
        (?<rest> AP \s MAC= .* )
    $
}xo;

# And this one matches additional lines with the same timestamp and additional information.
Readonly::Scalar my $ADDITIONAL_LINE_REGEX => qr{
    ^
        \[ (?<timestamp> \d+ [.] \d+ ) \] \s+
        (?<rest> (?:AP\s+) MAC= .* )
    $
}xo;

Readonly::Scalar my $CONTROLLER_DHCP_INFO_REGEX => qr{
    ^
    \< (?<prival> \d+) \> (?<version> \d+)? \s+
        ( [0-9]{4}-[0-9]{2}-[0-9]{2} \s+ [0-9]{2}:[0-9]{2}:[0-9]{2} ) \s+
        (?<origin> \S+) \s+ (?<appname>(-|\S+)) \s+ (?<procid>(-|\S+)) \s+ (?<msgid>(-|\S+)) \s+
        (?<rest>.*)
    $
}xo;

Readonly::Scalar my $CONTROLLER_OPERATION_INFO_REGEX => qr{
    ^
    \< (?<prival> \d+) \> (?<version> \d+)? \s+
        ( [0-9]{4}-[0-9]{2}-[0-9]{2} \s+ [0-9]{2}:[0-9]{2}:[0-9]{2} ) \s+
        (?<origin> \S+) \s+ (?<appname>(-|\S+)) \s+ (?<procid>(-|\S+)) \s+ (?<msgid>(-|\S+)) \s+
        (?<json> \{ .* \} )
    $
}xo;

# Regex to parse fields from each individual line after splitting multiline
# syslog messages.
Readonly::Scalar my $DHCP_FIELDS_REGEX => qr{
    AP \s MAC =   (?<AP_MAC>[0-9a-fA-F:]{17}) \s+
    MAC \s SRC =  (?<MAC_SRC>[0-9a-fA-F:]{17}) \s+
    IP \s SRC =   (?<IP_SRC>[0-9.]{7,15}) \s+
    IP \s DST =   (?<IP_DST>[0-9.]{7,15}) \s+
    IP \s proto = (?<IP_PROTO>[0-9]+) \s+
    SPT = (?<SPT>[0-9]+) \s+
    DPT = (?<DPT>[0-9]+)
}xo;

sub facility_severity_from_prival {
    my $prival = shift;

    if ( defined $prival and $prival =~ /^\d+$/ and $prival >= 0 ) {
        my $facility = int( $prival / 8 );
        my $severity = $prival % 8;
        $facility = undef if $facility > 23;
        return wantarray ? ($facility, $severity) : [ $facility, $severity ];
    }

    return wantarray ? (undef, undef) : [ undef, undef ];
}

sub match_first_line {
    my $line = shift;

    if ( $line =~ $FIRST_LINE_REGEX ) {
        my %stuff = %+;
        my ( $facility, $severity ) = facility_severity_from_prival( $stuff{ prival } );
        $stuff{ _facility } = $facility;
        $stuff{ level } = $severity;
        delete $stuff{ prival }; # No need to keep this now
        return wantarray ? %stuff : \%stuff;
    }

    return;
}    

sub match_additional_line {
    my $line = shift;

    if ( $line =~ $ADDITIONAL_LINE_REGEX ) {
        my %stuff = %+;
        my ( $facility, $severity ) = facility_severity_from_prival( $stuff{ prival } );
        $stuff{ _facility } = $facility;
        $stuff{ level } = $severity;
        delete $stuff{ prival }; # No need to keep this now
        return wantarray ? %stuff : \%stuff;
    }

    return;
}

sub match_dhcp_info {
    my $line = shift;

    if ( $line =~ $CONTROLLER_DHCP_INFO_REGEX ) {
        my %stuff = %+;
        my ( $facility, $severity ) = facility_severity_from_prival( $stuff{ prival } );
        $stuff{ _facility } = $facility;
        $stuff{ level } = $severity;
        delete $stuff{ prival }; # No need to keep this now
        return wantarray ? %stuff : \%stuff;
    }

    return;
}

sub match_controller_operation_info {
    my $line = shift;

    if ( $line =~ $CONTROLLER_OPERATION_INFO_REGEX ) {
        my %stuff = %+;
        my ( $facility, $severity ) = facility_severity_from_prival( $stuff{ prival } );
        $stuff{ _facility } = $facility;
        $stuff{ level } = $severity;
        delete $stuff{ prival }; # No need to keep this now
        return wantarray ? %stuff : \%stuff;
    }

    return;
}

sub match_dhcp_fields {
    my $line = shift;

    if ( $line =~ $DHCP_FIELDS_REGEX ) {
        my %stuff = %+;
        my ( $facility, $severity ) = facility_severity_from_prival( $stuff{ prival } );
        $stuff{ _facility } = $facility;
        $stuff{ level } = $severity;
        delete $stuff{ prival }; # No need to keep this now
        return wantarray ? %stuff : \%stuff;
    }

    return;
}

sub fields_from_first_line_match {
    my ( $line, $result ) = ( shift, shift );

    # Set %fields from the regex match.
    my %fields = %$result;
    
    # The payload sits in `rest`, repeat this in the message
    $fields{ short_message } = "TP-Link: $result->{rest}";
    $fields{ category } = 'AP';

    return \%fields;
}

sub fields_from_additional_line_match {
    my ( $result, $base_fields ) = ( shift, shift );

    # Shallow copy of %base_fields to %fields
    my %fields = %$base_fields;

    # And replace those fields that occurred on the additional line.
    foreach my $key ( keys %+ ) {
        $fields{ $key } = $result->{ $key };
    }

    # The payload sits in `rest`, repeat this in the message
    $fields{ short_message } = "TP-Link: $result->{rest}";
    $fields{ category } = 'AP';

    return \%fields;
}

sub fields_from_dhcp_info {
    my ( $result, $line ) = ( shift, shift );

    # DHCP info message examples; these occur in a single message at a time
    #
    # <134>1 2025-07-19 19:21:46 Omada-Controller-XXXX-YYYYYYYYYY - - - 2.5G WAN1: DHCP client lease expired. Began renewing the lease.
    # <134>1 2025-07-19 19:21:50 Omada-Controller-XXXX-YYYYYYYYYY - - - 2.5G WAN1: DHCP client renewing IP succeeded. (IP-Address=x.x.x.x, Mask=255.252.0.0, Gateway=x.x.x.x)
    my %fields;

    foreach my $key ( keys %$result ) {
        $fields{ $key } = $result->{ $key };
    }

    $fields{ short_message } = "TP-Link DHCP: @{[ $result->{rest} || $line ]}";
    $fields{ category } = 'DHCP';

    return \%fields;
}

sub fields_from_controller_operation_info {
    my ( $result, $line ) = ( shift, shift );

    state $json_deserializer = JSON->new->utf8->allow_nonref->canonical;

    # Operational message examples. These occur in a single message at a time
    # plus these contain a JSON payload, so that will be parsed as well and
    # the separate fields from that can be sent to Graylog.
    #
    # <158>1 2025-07-19 23:00:18 Omada-Controller-XXXX - - - {"details":{},"operation":"****** logged in successfully."}
    # <158>1 2025-07-19 18:18:23 Omada-Controller-XXXX - - - {"details":{},"operation":"Global Remote Logging configured successfully."}
    # <158>1 2025-07-19 18:18:23 Omada-Controller-XXXX - - - {"details":{},"operation":"General Settings edited successfully."}
    # <158>1 2025-07-19 18:18:23 Omada-Controller-XXXX - - - {"details":{},"operation":"Join User Experience Improvement Program edited successfully."}

    my %fields = (
        origin => $result->{ origin },
    );

    my $decoded = $json_deserializer->decode( $result->{ json } );

    foreach my $key ( keys %{ $decoded } ) {
        $fields{ $key } = $decoded->{ $key };
    }

    $fields{ short_message } = "TP-Link OPERATION: @{[ $fields{operation} || $line ]}";
    $fields{ category } = 'OPERATION';    

    return \%fields;
}

# Send a GELF message to Graylog via UDP
sub send_gelf_message {
    my ( $gelf_data, $GRAYLOG_IP, $GRAYLOG_PORT ) = @_;

    state $json_serializer = JSON::XS->new->utf8->allow_nonref->canonical;

    my $json_str = $json_serializer->encode( $gelf_data );
    my $compressed_data = compress( $json_str, Z_DEFAULT_COMPRESSION );

    # Create a temporary socket to send UDP
    socket( my $sock, PF_INET, SOCK_DGRAM, getprotobyname('udp') ) or die "socket: $!";
    my $dest_addr = sockaddr_in( $GRAYLOG_PORT, inet_aton( $GRAYLOG_IP ) );
    send( $sock, $compressed_data, 0, $dest_addr ) or warn "send GELF: $!";
    close( $sock );
}

1; # EOF