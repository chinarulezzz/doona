package bedmod::http_sp;

use strict;
use warnings;
#use diagnostics;

use Socket;

# This package is an extension to doona, to check
# for http server vulnerabilities.  Works as an extension to BED too
#
# Tests for request methods and request fields specific to SharePoint
#
# The displayed output may not show particularly long commands but
# the right stuff is being sent
#
# Might want to mod, depending on desired results.
# For example, do a GET on an existing resource.
#
# Written by Grid

sub new {
    bless {};
}

sub init {
    my $self = shift;
    my %args = @_;

    $self->{proto} = "tcp";
    $self->{port}  = $args{p} || 80;

    return if $args{d};

    my $iaddr = inet_aton($self->{target})
        || die "\nUnknown host: $self->{target}\n";

    my $paddr = sockaddr_in($self->{port}, $iaddr)
        || die "\ngetprotobyname: $!\n";

    my $proto = getprotobyname('tcp')
        || die "\ngetprotobyname: $!\n";

    socket(SOCKET, PF_INET, SOCK_STREAM, $proto)
        || die "\nsocket: $!\n";

    connect(SOCKET, $paddr)
        || die "\nconnection attempt failed: $!\n";

    send(SOCKET, "HEAD / HTTP/1.0\r\n\r\n", 0)
        || die "\nHTTP request failed: $!\n";
}

sub health_check {
    my $self = shift;

    my $iaddr = inet_aton($self->{target})
        || die "\nUnknown host: $self->{target}\n";

    my $paddr = sockaddr_in($self->{port}, $iaddr)
        || die "\ngetprotobyname: $!\n";

    my $proto = getprotobyname('tcp')
        || die "\ngetprotobyname: $!\n";

    socket(SOCKET, PF_INET, SOCK_STREAM, $proto)
        || die "\nsocket: $!\n";

    connect(SOCKET, $paddr)
        || die "\nconnection attempt failed: $!\n";

    send(SOCKET, "HEAD / HTTP/1.0\r\n\r\n", 0)
        || die "\nHTTP request failed: $!\n";

    my $resp = <SOCKET>;

    if (!$self->{healthy}) {
        $self->{healthy} = $resp if $resp =~ /HTTP/;
        # print "Set healthy: $resp";
    }
    return $resp =~ m/^$self->{healthy}$/;
}

sub getQuit {
    ("\r\n\r\n");
}

sub getLoginarray {
    (
        "GET /default.XAXAX HTTP/1.1\r\nHost: 192.168.43.128\r\n\r\n",
        "GET /XAXAX.html HTTP/1.1\r\nHost: 192.168.43.128\r\n\r\n",
    );
}

sub getCommandarray {
    (
        "x-virus-infected: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "x-irm-cantdecrypt: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "x-irm-rejected: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "x-irm-notowner: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "x-irm-timeout: XAXAX\r\nHost: 192.168.43.128\r\n",
        "x-irm-crashed: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "x-irm-unknown-failure: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "SharePointError: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "X-RequestDigest: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "X-Forms_Based_Auth_Required: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "X-Forms_Based_Auth_Return_Url: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "X-MS-File-Checked-Out: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "X-RequestToken: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "SPRequestGuid: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "X-UseWebLanguage: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "X-RequestForceAuthentication: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "X-SharePointHealthScore: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "X-MS-InvokeApp: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
    );
}

sub getLogin {
    ("GET / HTTP/1.1\r\n");
}

sub testMisc {
    (
        "GET / HTTP/1.1\r\nHost: 192.168.43.128\r\n\r\n"
            . "LotsOfHeaders: XAXAX\r\n" x 1024 . "\r\n",
    );
}

sub usage {}

1;

# vim:sw=4:ts=4:sts=4:et:cc=80
# End of file.
