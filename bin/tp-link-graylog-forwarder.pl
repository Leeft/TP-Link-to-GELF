#!/usr/bin/perl -w
# vim: ts=4 sw=4 et syntax=perl
# vim: syntax on
use utf8;
use strict;
use warnings;
use feature qw( say state );
use Socket;
use IO::Select;
use Data::Printer;
use Try::Tiny;
use JSON::XS;
use Readonly;
use FindBin;
use lib ( "$FindBin::Bin/../lib/", "$FindBin::Bin/lib/" );
use TPLinkSyslogMessage::Parser;

# --- Configuration ---
my $GRAYLOG_PORT    = $ENV{ GRAYLOG_PORT } // 12201;  # Graylog's default GELF TCP port
my $GRAYLOG_IP      = $ENV{ GRAYLOG_IP }   || die "Specify GRAYLOG_IP for the address to send to";

my $DEFAULT_LOG_LEVEL = 6;         # Default GELF level (6=Informational, 7=Debug, etc.)

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

            my $fields;

            if ( my %result = match_first_line( $line ) )
            {
                $fields = fields_from_first_line_match( $line, \%result );
                # Preserve the fields in base_fields for any subsequent lines.
                %base_fields = %$fields;
            }
            elsif ( %result = match_additional_line( $line ) )
            {
                $fields = fields_from_additional_line_match( \%result, \%base_fields );
            }
            elsif ( %result = match_dhcp_info( $line ) )
            {
                $fields = fields_from_dhcp_info( \%result, $line );
            }
            elsif ( %result = match_controller_operation_info( $line ) )
            {
                $fields = fields_from_controller_operation_info( \%result, $line );
            }
            else
            {
                # TODO: Implement additional parsing logic rather than just forwarding the message
                # as-is to TP-Link. Can't do that until more have been discovered though.
                say { *STDERR } "COULD NOT PARSE: $line";
                $fields->{ short_message } = "TP-Link Unknown: $line";
                $fields->{ category } = 'UNPARSED';
            }

            # The timestamp _must_ be a number, a string will not be accepted.
            my $timestamp = 0 + ( $fields->{ timestamp } || time() );

            my %gelf_message = (
                version       => "1.1",
                host          => $sender_ip,
                short_message => $fields->{ short_message },
                full_message  => $line,
                level         => $fields->{ level } // $DEFAULT_LOG_LEVEL,
                timestamp     => $timestamp,
                _tp_link      => $fields->{ category },
            );

            # No point repeating this data in the message
            delete $fields->{ timestamp };

            # "rest" should be removed from the messages as well, and if not
            # set after parsing we'll use the original message.
            my $rest = delete $fields->{ rest };
               $rest ||= $line;

            # Add all parsed fields as custom GELF fields (thus prefixed with '_')
            while ( my ($key, $val) = each %$fields) {
                $gelf_message{"_$key"} = $val;
            }

            if ( $rest and my $dhcp = match_dhcp_fields( $rest ) )
            {
                # If the message has specific fields, parse thos
                # and set the fields for graylog to use. Again as custom
                # fields.
                while ( my ($key, $val) = each %$dhcp ) {
                    $gelf_message{"_$key"} = $val;
                }
            }

            # Now attempt to deliver to Graylog. If that fails, log to STDOUT.
            try
            {
                send_gelf_message( \%gelf_message, $GRAYLOG_IP, $GRAYLOG_PORT );
            }
            catch
            {
                my $err = $_;
                say { *STDERR } "COULD NOT SEND TO GELF ENDPOINT: $err: ".np( %gelf_message );
            };
        }
    }
}
   
# EOF