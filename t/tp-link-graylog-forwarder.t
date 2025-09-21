#!/bin/env /usr/bin/perl
use utf8;
use strict;
use warnings;
use Test::Most;
use Test::Deep;
use Data::Printer;
use FindBin;
use lib "$FindBin::Bin/../lib/";
use TPLinkSyslogMessage::Parser;

local $ENV{ GRAYLOG_IP } = '127.0.0.1';

subtest 'facility_severity_from_prival' => sub
{
    my $input;
    $input = facility_severity_from_prival(0);
    cmp_deeply $input, [0, 0], "PRIVAL 0 should return (0, 0)";
    $input = facility_severity_from_prival(6);
    cmp_deeply $input, [0, 6], "PRIVAL 6 should return (0, 6)"
        or diag np $input;
    $input = facility_severity_from_prival(7);
    cmp_deeply $input, [0, 7], "PRIVAL 7 should return (0, 7)";
    $input = facility_severity_from_prival(8);
    cmp_deeply $input, [1, 0], "PRIVAL 8 should return (1, 0)";
    $input = facility_severity_from_prival(31);
    cmp_deeply $input, [3, 7], "PRIVAL 31 should return (3, 7)";
    $input = facility_severity_from_prival(32);
    cmp_deeply $input, [4, 0], "PRIVAL 32 should return (4, 0)";

    # Test cases for invalid input
    $input = facility_severity_from_prival("not a number");
    cmp_deeply $input, [undef, undef], "Non-numeric string should return (undef, undef)";
    $input = facility_severity_from_prival(-1);
    cmp_deeply $input, [undef, undef], "Negative number should return (undef, undef)";
    $input = facility_severity_from_prival(256);
    cmp_deeply $input, [undef, 0], "Number out of range should return (undef, 0)"
        or diag np $input;

    # Test cases for edge cases
    $input = facility_severity_from_prival(127);
    cmp_deeply $input, [15, 7], "Maximum value (127) should return (15, 7)";
    $input = facility_severity_from_prival(192);
    cmp_deeply $input, [undef, 0], "Value beyond maximum should return (undef, 0)"
        or diag np $input;
};

# Test match_first_line

my $first_line = '<6>Sep 20 21:42:02 192.168.40.5 [1758400919.541010111] AP MAC=aa:bb:5f:e0:a6:aa MAC SRC=bb:aa:da:c8:1e:54 IP SRC=192.168.50.73 IP DST=52.45.111.111 IP proto=6 SPT=49808 DPT=1883';
my %result = match_first_line($first_line);
ok(%result, 'match_first_line matches valid input');
is($result{_facility}, 0, 'facility parsed');
is($result{level}, 6, 'severity parsed');
like($result{rest}, qr/^AP MAC=/, 'rest field starts with AP MAC=');

# Test match_additional_line
my $additional_line = '[1758400919.891010111] AP MAC=aa:bb:5f:e0:a6:aa MAC SRC=bb:aa:da:c8:1e:54 IP SRC=192.168.50.73 IP DST=52.45.111.111 IP proto=6 SPT=49808 DPT=1883';
my $result = match_additional_line($additional_line);
ok($result, 'match_additional_line matches valid input');
is($result->{timestamp}, '1758400919.891010111', 'timestamp parsed');
like($result->{rest}, qr/^AP MAC=/, 'rest field starts with AP MAC=');

# Test match_dhcp_info
my $dhcp_line = '<134>1 2025-07-19 19:21:46 Omada-Controller-XXXX-YYYYYYYYYY - - - 2.5G WAN1: DHCP client lease expired. Began renewing the lease.';
$result = match_dhcp_info($dhcp_line);
ok($result, 'match_dhcp_info matches valid input');
is($result->{_facility}, 16, 'facility parsed');
is($result->{level}, 6, 'severity parsed');
is($result->{origin}, 'Omada-Controller-XXXX-YYYYYYYYYY', 'origin parsed');
like($result->{rest}, qr/DHCP client lease expired/, 'rest field contains DHCP info');

# '<134>1 2025-09-20 23:21:16 Omada Controller_XXXXX-YYYYYYYY - - - DHCP Server allocated IP address 192.168.50.58 for the client[MAC: AA-CC-70-65-b2-d4].'

# Test match_controller_operation_info
my $op_line = '<158>1 2025-07-19 23:00:18 Omada-Controller-XXXX - - - {"details":{},"operation":"logged in successfully."}';
$result = match_controller_operation_info($op_line);
ok($result, 'match_controller_operation_info matches valid input');
is($result->{origin}, 'Omada-Controller-XXXX', 'origin parsed');
like($result->{json}, qr/"operation":"logged in successfully\./, 'json field contains operation');

# Another JSON message to test (todo)
# my $global_logging_line = '<158>1 2025-09-19 23:29:51 Omada Controller_347044 - - - {"details":{},"operation":"Global Remote Logging configured successfully."}';
# my %result = match_controller_operation_info($global_logging_line);
# ok(%result, 'match_controller_operation_info matches valid input');
# is($result{facility}, '13', 'facility parsed');
# is($result{priority}, '4', 'priority parsed');

done_testing();