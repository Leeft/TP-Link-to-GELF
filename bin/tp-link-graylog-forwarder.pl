#!/usr/bin/perl -w
# vim: ts=4 sw=4 et syntax=perl
# vim: syntax on
use utf8;
use strict;
use warnings;
use feature 'say';
use Socket;
use IO::Select;
use Data::Printer;
use Try::Tiny;
use Compress::Zlib;
use JSON::XS;

# --- Configuration ---
my $GRAYLOG_PORT    = $ENV{ GRAYLOG_PORT } // 12201;  # Graylog's default GELF TCP port
my $GRAYLOG_IP      = $ENV{ GRAYLOG_IP }   || die "Specify GRAYLOG_IP for the address to send to";

my $LOG_LEVEL       = 6;         # Default GELF level (6=Informational, 7=Debug, etc.)
# TODO: Can further improve this with the data parsed from the messages

# 6.2.1.  PRI
#
#    The PRI part MUST have three, four, or five characters and will be
#    bound with angle brackets as the first and last characters.  The PRI
#    part starts with a leading "<" ('less-than' character, %d60),
#    followed by a number, which is followed by a ">" ('greater-than'
#    character, %d62).  The number contained within these angle brackets
#    is known as the Priority value (PRIVAL) and represents both the
#    Facility and Severity.  The Priority value consists of one, two, or
#    three decimal integers (ABNF DIGITS) using values of %d48 (for "0")
#    through %d57 (for "9").
#
#    Facility and Severity values are not normative but often used.  They
#    are described in the following tables for purely informational
#    purposes.  Facility values MUST be in the range of 0 to 23 inclusive.
#
#           Numerical             Facility
#              Code
#
#               0             kernel messages
#               1             user-level messages
#               2             mail system
#               3             system daemons
#               4             security/authorization messages
#               5             messages generated internally by syslogd
#               6             line printer subsystem
#               7             network news subsystem
#               8             UUCP subsystem
#               9             clock daemon
#              10             security/authorization messages
#              11             FTP daemon
#              12             NTP subsystem
#              13             log audit
#              14             log alert
#              15             clock daemon (note 2)
#              16             local use 0  (local0)
#              17             local use 1  (local1)
#              18             local use 2  (local2)
#              19             local use 3  (local3)
#              20             local use 4  (local4)
#              21             local use 5  (local5)
#              22             local use 6  (local6)
#              23             local use 7  (local7)
#
#               Table 1.  Syslog Message Facilities
#
#    Each message Priority also has a decimal Severity level indicator.
#    These are described in the following table along with their numerical
#    values.  Severity values MUST be in the range of 0 to 7 inclusive.
#
#            Numerical         Severity
#              Code
#
#               0       Emergency: system is unusable
#               1       Alert: action must be taken immediately
#               2       Critical: critical conditions
#               3       Error: error conditions
#               4       Warning: warning conditions
#               5       Notice: normal but significant condition
#               6       Informational: informational messages
#               7       Debug: debug-level messages
#
#               Table 2. Syslog Message Severities
#
#    The Priority value is calculated by first multiplying the Facility
#    number by 8 and then adding the numerical value of the Severity.  For
#    example, a kernel message (Facility=0) with a Severity of Emergency
#    (Severity=0) would have a Priority value of 0.  Also, a "local use 4"
#    message (Facility=20) with a Severity of Notice (Severity=5) would
#    have a Priority value of 165.  In the PRI of a syslog message, these
#    values would be placed between the angle brackets as <0> and <165>
#    respectively.  The only time a value of "0" follows the "<" is for
#    the Priority value of "0".  Otherwise, leading "0"s MUST NOT be used.
#
# 6.2.2.  VERSION
#
#    The VERSION field denotes the version of the syslog protocol
#    specification.  The version number MUST be incremented for any new
#    syslog protocol specification that changes any part of the HEADER
#    format.  Changes include the addition or removal of fields, or a
#    change of syntax or semantics of existing fields.  This document uses
#    a VERSION value of "1".  The VERSION values are IANA-assigned
#    (Section 9.1) via the Standards Action method as described in
#    [RFC5226].

# "AP MAC" messages consist of multiple lines, which aren't that useful in a pack.
# They're also not that easily parsed to something graylog can work with with.
# This regex matches the first of one of these multiline messages.
my $FIRST_LINE_REGEX = qr{
    ^
       \< (?<facility> ( [0-9] | [12][0-9] | 2[0-3] ) (?<priority> [0-7])) \> (?<version> \d+)? \s+
        ( (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \s+ \d+ \s+ [0-9]{2}:[0-9]{2}:[0-9]{2}) \s+
        ( [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3} ) \s+
        \[ (?<timestamp> \d+ [.] \d+ ) \] \s+
        (?<rest> AP \s MAC= .* )
    $
}xo;

# And this one matches additional lines while there are any.
my $ADDITIONAL_LINE_REGEX = qr{
    ^
        \[ (?<timestamp> \d+ [.] \d+ ) \] \s+
        (?<rest> (?:AP\s+) MAC= .* )
    $
}xo;

my $CONTROLLER_DHCP_INFO_REGEX = qr{
    ^
       \< (?<facility> ( [0-9] | [12][0-9] | 2[0-3] ) (?<priority> [0-7])) \> (?<version> \d+)? \s+
        ( [0-9]{4}-[0-9]{2}-[0-9]{2} \s+ [0-9]{2}:[0-9]{2}:[0-9]{2} ) \s+
        (?<origin> \S+) \s+ (?<appname>(-|\S+)) \s+ (?<procid>(-|\S+)) \s+ (?<msgid>(-|\S+)) \s+
        (?<rest>.*)
    $
}xo;

my $CONTROLLER_OPERATION_INFO_REGEX = qr{
    ^
       \< (?<facility> ( [0-9] | [12][0-9] | 2[0-3] ) (?<priority> [0-7])) \> (?<version> \d+)? \s+
        ( [0-9]{4}-[0-9]{2}-[0-9]{2} \s+ [0-9]{2}:[0-9]{2}:[0-9]{2} ) \s+
        (?<origin> \S+) \s+ (?<appname>(-|\S+)) \s+ (?<procid>(-|\S+)) \s+ (?<msgid>(-|\S+)) \s+
        (?<json> \{ .* \} )
    $
}xo;

# Regex to parse each individual line after splitting.
# Using qr{} for pre-compilation and /x for readability.
my $LINE_PARSE_REGEX = qr{
    AP \s MAC =   (?<AP_MAC>[0-9a-fA-F:]{17}) \s+
    MAC \s SRC =  (?<MAC_SRC>[0-9a-fA-F:]{17}) \s+
    IP \s SRC =   (?<IP_SRC>[0-9.]{7,15}) \s+
    IP \s DST =   (?<IP_DST>[0-9.]{7,15}) \s+
    IP \s proto = (?<IP_PROTO>[0-9]+) \s+
    SPT = (?<SPT>[0-9]+) \s+
    DPT = (?<DPT>[0-9]+)
}xo;


my $listen_sock;

socket( $listen_sock, PF_INET, SOCK_DGRAM, getprotobyname('udp') )
    or die "Couldn't set up listening socket: $!";

setsockopt( $listen_sock, SOL_SOCKET, SO_REUSEADDR, 1 )
    or die "Couldn't set setsockopt (SO_REUSEADDR): $!";

bind( $listen_sock, sockaddr_in( 514, INADDR_ANY ) )
    or die "Couldn't set INADDR_ANY on listening socket: $!";

say "Listening for TP-Link syslog messages on UDP 0.0.0.0:514; parsing and forwarding these messages to http://$GRAYLOG_IP:$GRAYLOG_PORT/gelf";

my $json_serializer = JSON::XS->new->utf8->allow_nonref->canonical;

my $sel = IO::Select->new;
   $sel->add( $listen_sock );

while ( my @ready_socks = $sel->can_read )
{
    foreach my $sock ( @ready_socks )
    {
        my $buffer;
        my $addr = recv( $sock, $buffer, 65536, 0 )
            or warn "recv: $!";

        my ($port, $ip) = sockaddr_in( $addr );
        my $sender_ip = inet_ntoa( $ip );

        #say "Received @{[ length($buffer) ]} bytes from $sender_ip:$port";

        # When messages are split the first line likely had data the subsequent
        # lines do not have; they are tracked in this hash so each message sent
        # can include the very same data for graylog.
        my %base_fields;

        my $short_message = 'TP-LINK'; # Uppercased so we can see when code below fails to change this default.

        foreach my $line ( split /\r\n/, $buffer )
        {
            next if not defined $line or not length $line;

            $line =~ s/^\s+|\s+$//g; # Trim whitespace

            next if length $line <= 3 or $line =~ /^\s*$/;

            # Basic validation: does it look like a TP-Link AP log line?

            my %fields;

            if ( $line =~ $FIRST_LINE_REGEX )
            {
                # Set %fields and %base_fields from the regex match.
                %fields = %+;
                %base_fields = %+;

                $short_message = "TP-Link: $fields{rest}";
                $fields{ category } = 'AP MAC';
            }
            elsif ( $line =~ $ADDITIONAL_LINE_REGEX )
            {
                # Shallow copy of %base_fields to %fields
                %fields = %base_fields;

                # And replace those fields that occurred on the additional line.
                foreach my $key ( keys %+ ) {
                    $fields{ $key } = $+{ $key };
                }

                $short_message = "TP-Link: $fields{rest}";
                $fields{ category } = 'AP MAC';
            }
            elsif ( $line =~ $CONTROLLER_DHCP_INFO_REGEX )
            {
                # DHCP info message examples; these occor in a single message at a time
                #
                # <134>1 2025-07-19 19:21:46 Omada-Controller-XXXX-YYYYYYYYYY - - - 2.5G WAN1: DHCP client lease expired. Began renewing the lease.
                # <134>1 2025-07-19 19:21:50 Omada-Controller-XXXX-YYYYYYYYYY - - - 2.5G WAN1: DHCP client renewing IP succeeded. (IP-Address=x.x.x.x, Mask=255.252.0.0, Gateway=x.x.x.x)
                %fields = %base_fields;

                foreach my $key ( keys %+ ) {
                    $fields{ $key } = $+{ $key };
                }

                $short_message = "TP-Link DHCP: @{[ $fields{rest} || $line ]}";
                $fields{ category } = 'DHCP';
            }
            elsif ( $line =~ $CONTROLLER_OPERATION_INFO_REGEX )
            {
                # Operational message examples. These occur in a single message at a time
                # plus these contain a JSON payload, so that will be parsed as well and
                # the separate fields from that can be sent to Graylog.
                #
                # <158>1 2025-07-19 23:00:18 Omada-Controller-XXXX - - - {"details":{},"operation":"****** logged in successfully."}
                # <158>1 2025-07-19 18:18:23 Omada-Controller-XXXX - - - {"details":{},"operation":"Global Remote Logging configured successfully."}
                # <158>1 2025-07-19 18:18:23 Omada-Controller-XXXX - - - {"details":{},"operation":"General Settings edited successfully."}
                # <158>1 2025-07-19 18:18:23 Omada-Controller-XXXX - - - {"details":{},"operation":"Join User Experience Improvement Program edited successfully."}

                %fields = %base_fields;

                $fields{ origin } = $+{ origin };

                my $json_deserializer = JSON->new->utf8->allow_nonref->canonical;
                my $decoded = $json_deserializer->decode( $+{ json } );

                foreach my $key ( keys %{ $decoded } ) {
                    $fields{ $key } = $decoded->{ $key };
                }

                $short_message = "TP-Link OPERATION: @{[ $fields{operation} || $line ]}";
                $fields{ category } = 'OPERATION';
            }
            else
            {
                # TODO: Implement additional parsing logic rather than just forwarding the message
                # as-is to TP-Link. Can't do that until more have been discovered though.
                say { *STDERR } "NO MATCH: $line";
                $short_message = "TP-Link Unknown: $line";
                $fields{ category } = 'UNPARSED';
            }

            # The timestamp _must_ be a number, a string will not be accepted.
            my $timestamp = 0 + ( $fields{ timestamp } || time() );

            my %gelf_message = (
                version       => "1.1",
                host          => $sender_ip,
                short_message => $short_message,
                full_message  => $line,
                level         => $LOG_LEVEL,
                timestamp     => $timestamp,
                _tp_link      => $fields{ category },
            );

            # No point repeating this data in the message
            delete $fields{timestamp};

            # "rest" should be removed from the messages as well, and if not
            # set after parsing we'll use the original message.
            my $rest = delete $fields{rest};
               $rest ||= $line;

            # Add all parsed fields as custom GELF fields (thus prefixed with '_')
            while ( my ($key, $val) = each %fields) {
                $gelf_message{"_$key"} = $val;
            }

            if ( $rest =~ $LINE_PARSE_REGEX )
            {
                # If the message has specific fields, parse thos
                # and set the fields for graylog to use. Again as custom
                # fields.
                my %parsed_fields = %+;
                while ( my ($key, $val) = each %parsed_fields ) {
                    $gelf_message{"_$key"} = $val;
                }
            }

            # Now attempt to deliver to Graylog. If that fails, log to STDOUT.
            try
            {
                send_gelf_message( \%gelf_message );
            }
            catch
            {
                my $err = $_;
                say { *STDERR } "$err: ".np( %gelf_message );
            };
        }
    }
}

sub send_gelf_message {
    my $gelf_data = shift;

    my $json_str = $json_serializer->encode( $gelf_data );
    my $compressed_data = compress( $json_str, Z_DEFAULT_COMPRESSION );

    # Create a temporary socket to send UDP
    socket( my $sock, PF_INET, SOCK_DGRAM, getprotobyname('udp') ) or die "socket: $!";
    my $dest_addr = sockaddr_in( $GRAYLOG_PORT, inet_aton( $GRAYLOG_IP ) );
    send( $sock, $compressed_data, 0, $dest_addr ) or warn "send GELF: $!";
    close( $sock );
}

# EOF