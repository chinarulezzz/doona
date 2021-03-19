package bedmod::http_more;

use strict;
use warnings;
#use diagnostics;

use Socket;

# This package is an extension to doona, to check
# for http server vulnerabilities.
#
# Tests for request methods and request fields not tested in the
# standard http module.

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
        #print "Set healthy: $resp";
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
        "CONNECT XAXAX:80 HTTP/1.1\r\n\r\n",
        "CONNECT 192.168.43.128/home:XAXAX HTTP/1.1\r\n\r\n",
        "PATCH /XAXAX HTTP/1.1\r\nHost: 192.168.43.128\r\n\r\n",
    );
}

sub getCommandarray {
    (
        "Accept-Datetime: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "Cache-Control: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "Content-MD5: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "Content-Type: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "Date: XAXAX\r\n\r\n",
        "Forwarded: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "Origin: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "Via: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "Warning: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "X-Requested-With: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "DNT: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "X-Forwarded-For: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "X-Forwarded-Host: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "X-Forwarded-Proto: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "Front-End-Https: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "X-Http-Method-Override: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "X-Att-Deviceid: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "X-Wap-Profile: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "Proxy-Connection: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "X-UIDH: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
        "X-Csrf-Token: XAXAX\r\nHost: 192.168.43.128\r\n\r\n",
    );
}

sub getLogin {
    (
        "CONNECT 192.168.43.128:80 HTTP/1.1\r\n",
        "PATCH /default.html HTTP/1.1\r\n",
    );
}

sub testMisc {
    (
        "CONNECT 192.168.43.128:80 HTTP/1.1\r\n"
            . "Lotsofheaders: XAXAX\r\n" x 1024 . "\r\n",

        "PATCH / HTTP/1.1\r\nHost: 192.168.43.128\r\n\r\n"
            . "Lotsofheaders: XAXAX\r\n" x 1024 . "\r\n",
    );
}

sub usage {}

1;

# vim:sw=4:ts=4:sts=4:et:cc=80
# End of file.
